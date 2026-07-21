use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use edge_memory_harness::memory_aggregate::{
    collect_aggregate, inspect_aggregate, validate_aggregate, AggregateInputs,
};
use edge_memory_harness::report_io::{publish_canonical_bytes, publish_digest};
use edge_memory_harness::HarnessError;

fn main() {
    if let Err(error) = run(env::args().skip(1).collect()) {
        eprintln!("memory aggregate error: {error}");
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
                    "--input-root",
                    "--build-identity",
                    "--platform",
                    "--architecture",
                    "--output",
                    "--digest-output",
                ],
            )?;
            let aggregate = collect_aggregate(&aggregate_inputs(&options)?)?;
            let encoded = aggregate.to_canonical_json()?;
            let published = publish_canonical_bytes(
                &PathBuf::from(required(&options, "--output")?),
                encoded.as_bytes(),
            )?;
            publish_digest(
                &PathBuf::from(required(&options, "--digest-output")?),
                &published.sha256,
            )?;
            println!(
                "memory aggregate collected profile={} status=partial runs={} scenarios={} digest={}",
                aggregate.profile_id,
                aggregate.runs.len(),
                aggregate.scenarios.len(),
                published.sha256
            );
        }
        "validate" => {
            exact_keys(
                &options,
                &[
                    "--input-root",
                    "--build-identity",
                    "--platform",
                    "--architecture",
                    "--aggregate",
                    "--digest",
                ],
            )?;
            let (aggregate_bytes, digest) = read_bundle(&options)?;
            let aggregate =
                validate_aggregate(&aggregate_inputs(&options)?, &aggregate_bytes, &digest)?;
            println!(
                "memory aggregate validated profile={} status=partial runs={} scenarios={} digest={}",
                aggregate.profile_id,
                aggregate.runs.len(),
                aggregate.scenarios.len(),
                digest
            );
        }
        "inspect" => {
            exact_keys(&options, &["--build-identity", "--aggregate", "--digest"])?;
            let (aggregate_bytes, digest) = read_bundle(&options)?;
            let aggregate = inspect_aggregate(
                &aggregate_bytes,
                &digest,
                required(&options, "--build-identity")?,
            )?;
            println!(
                "memory aggregate inspected profile={} status=partial runs={} scenarios={} digest={}",
                aggregate.profile_id,
                aggregate.runs.len(),
                aggregate.scenarios.len(),
                digest
            );
        }
        _ => return Err(HarnessError::new("unknown memory aggregate command")),
    }
    Ok(())
}

fn read_bundle(options: &BTreeMap<String, String>) -> Result<(Vec<u8>, String), HarnessError> {
    let aggregate_bytes = read_regular(&PathBuf::from(required(options, "--aggregate")?))?;
    let digest_bytes = read_regular(&PathBuf::from(required(options, "--digest")?))?;
    let digest_text = std::str::from_utf8(&digest_bytes)
        .map_err(|_| HarnessError::new("memory aggregate digest is not UTF-8"))?;
    let digest = digest_text
        .strip_suffix('\n')
        .filter(|value| !value.contains('\n'))
        .ok_or_else(|| HarnessError::new("memory aggregate digest is not canonical"))?;
    Ok((aggregate_bytes, digest.to_string()))
}

fn parse(arguments: Vec<String>) -> Result<(String, BTreeMap<String, String>), HarnessError> {
    let mut arguments = arguments.into_iter();
    let command = arguments
        .next()
        .ok_or_else(|| HarnessError::new("memory aggregate command is required"))?;
    let mut options = BTreeMap::new();
    while let Some(key) = arguments.next() {
        if !key.starts_with("--") || options.contains_key(&key) {
            return Err(HarnessError::new(
                "memory aggregate option is invalid or duplicated",
            ));
        }
        let value = arguments
            .next()
            .ok_or_else(|| HarnessError::new("memory aggregate option value is missing"))?;
        if value.is_empty() {
            return Err(HarnessError::new("memory aggregate option value is empty"));
        }
        options.insert(key, value);
    }
    Ok((command, options))
}

fn aggregate_inputs(options: &BTreeMap<String, String>) -> Result<AggregateInputs, HarnessError> {
    Ok(AggregateInputs {
        input_root: PathBuf::from(required(options, "--input-root")?),
        build_identity: required(options, "--build-identity")?.to_string(),
        platform: required(options, "--platform")?.to_string(),
        architecture: required(options, "--architecture")?.to_string(),
    })
}

fn exact_keys(options: &BTreeMap<String, String>, keys: &[&str]) -> Result<(), HarnessError> {
    if options.len() != keys.len() || keys.iter().any(|key| !options.contains_key(*key)) {
        return Err(HarnessError::new("memory aggregate option set is invalid"));
    }
    Ok(())
}

fn required<'a>(options: &'a BTreeMap<String, String>, key: &str) -> Result<&'a str, HarnessError> {
    options
        .get(key)
        .map(String::as_str)
        .ok_or_else(|| HarnessError::new("memory aggregate required option is missing"))
}

fn read_regular(path: &Path) -> Result<Vec<u8>, HarnessError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| HarnessError::new("memory aggregate file is unavailable"))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(HarnessError::new(
            "memory aggregate file must be physical and regular",
        ));
    }
    fs::read(path).map_err(|_| HarnessError::new("memory aggregate file cannot be read"))
}
