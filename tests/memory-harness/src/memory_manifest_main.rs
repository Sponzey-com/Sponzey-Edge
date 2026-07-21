use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use edge_memory_harness::memory_manifest::{
    collect_manifest, inspect_manifest, validate_manifest, ManifestInputs, MemoryManifestStatus,
};
use edge_memory_harness::report_io::{publish_canonical_bytes, publish_digest};
use edge_memory_harness::HarnessError;

fn main() {
    if let Err(error) = run(env::args().skip(1).collect()) {
        eprintln!("memory manifest error: {error}");
        std::process::exit(1);
    }
}

fn run(arguments: Vec<String>) -> Result<(), HarnessError> {
    let (command, options) = parse(arguments)?;
    match command.as_str() {
        "collect" => {
            exact_keys(
                &options,
                &[
                    "--input-dir",
                    "--build-identity",
                    "--platform",
                    "--architecture",
                    "--repetitions",
                    "--status",
                    "--output",
                    "--digest-output",
                ],
            )?;
            let manifest = collect_manifest(&manifest_inputs(&options)?)?;
            let encoded = manifest.to_canonical_json()?;
            let published = publish_canonical_bytes(
                &PathBuf::from(required(&options, "--output")?),
                encoded.as_bytes(),
            )?;
            publish_digest(
                &PathBuf::from(required(&options, "--digest-output")?),
                &published.sha256,
            )?;
            println!(
                "memory manifest collected profile={} status=partial entries={} digest={}",
                manifest.profile_id,
                manifest.entries.len(),
                published.sha256
            );
        }
        "validate" => {
            exact_keys(
                &options,
                &[
                    "--input-dir",
                    "--build-identity",
                    "--platform",
                    "--architecture",
                    "--repetitions",
                    "--status",
                    "--manifest",
                    "--digest",
                ],
            )?;
            let (manifest_bytes, digest) = read_bundle(&options)?;
            let manifest =
                validate_manifest(&manifest_inputs(&options)?, &manifest_bytes, &digest)?;
            println!(
                "memory manifest validated profile={} status=partial entries={} digest={}",
                manifest.profile_id,
                manifest.entries.len(),
                digest
            );
        }
        "inspect" => {
            exact_keys(&options, &["--build-identity", "--manifest", "--digest"])?;
            let (manifest_bytes, digest) = read_bundle(&options)?;
            let manifest = inspect_manifest(
                &manifest_bytes,
                &digest,
                required(&options, "--build-identity")?,
            )?;
            println!(
                "memory manifest inspected profile={} status=partial entries={} digest={}",
                manifest.profile_id,
                manifest.entries.len(),
                digest
            );
        }
        _ => return Err(HarnessError::new("unknown memory manifest command")),
    }
    Ok(())
}

fn read_bundle(options: &BTreeMap<String, String>) -> Result<(Vec<u8>, String), HarnessError> {
    let manifest_path = PathBuf::from(required(options, "--manifest")?);
    let digest_path = PathBuf::from(required(options, "--digest")?);
    let manifest_bytes = read_regular(&manifest_path)?;
    let digest_bytes = read_regular(&digest_path)?;
    let digest_text = std::str::from_utf8(&digest_bytes)
        .map_err(|_| HarnessError::new("memory manifest digest is not UTF-8"))?;
    let digest = digest_text
        .strip_suffix('\n')
        .filter(|value| !value.contains('\n'))
        .ok_or_else(|| HarnessError::new("memory manifest digest is not canonical"))?;
    Ok((manifest_bytes, digest.to_string()))
}

fn parse(arguments: Vec<String>) -> Result<(String, BTreeMap<String, String>), HarnessError> {
    let mut arguments = arguments.into_iter();
    let command = arguments
        .next()
        .ok_or_else(|| HarnessError::new("memory manifest command is required"))?;
    let mut options = BTreeMap::new();
    while let Some(key) = arguments.next() {
        if !key.starts_with("--") || options.contains_key(&key) {
            return Err(HarnessError::new(
                "memory manifest option is invalid or duplicated",
            ));
        }
        let value = arguments
            .next()
            .ok_or_else(|| HarnessError::new("memory manifest option value is missing"))?;
        if value.is_empty() {
            return Err(HarnessError::new("memory manifest option value is empty"));
        }
        options.insert(key, value);
    }
    Ok((command, options))
}

fn manifest_inputs(options: &BTreeMap<String, String>) -> Result<ManifestInputs, HarnessError> {
    let status = match required(options, "--status")? {
        "partial" => MemoryManifestStatus::Partial,
        "approved" => MemoryManifestStatus::Approved,
        _ => return Err(HarnessError::new("memory manifest status is invalid")),
    };
    Ok(ManifestInputs {
        input_dir: PathBuf::from(required(options, "--input-dir")?),
        build_identity: required(options, "--build-identity")?.to_string(),
        platform: required(options, "--platform")?.to_string(),
        architecture: required(options, "--architecture")?.to_string(),
        repetitions: required(options, "--repetitions")?
            .parse()
            .map_err(|_| HarnessError::new("memory manifest repetitions is invalid"))?,
        status,
    })
}

fn exact_keys(options: &BTreeMap<String, String>, keys: &[&str]) -> Result<(), HarnessError> {
    if options.len() != keys.len() || keys.iter().any(|key| !options.contains_key(*key)) {
        return Err(HarnessError::new("memory manifest option set is invalid"));
    }
    Ok(())
}

fn required<'a>(options: &'a BTreeMap<String, String>, key: &str) -> Result<&'a str, HarnessError> {
    options
        .get(key)
        .map(String::as_str)
        .ok_or_else(|| HarnessError::new("memory manifest required option is missing"))
}

fn read_regular(path: &Path) -> Result<Vec<u8>, HarnessError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| HarnessError::new("memory manifest file is unavailable"))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(HarnessError::new(
            "memory manifest file must be physical and regular",
        ));
    }
    fs::read(path).map_err(|_| HarnessError::new("memory manifest file cannot be read"))
}
