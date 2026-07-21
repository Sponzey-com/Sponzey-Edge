use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use edge_memory_harness::full_profile_readiness::{
    evaluate_full_profile, FullProfileInput, FullProfileReadinessReport,
};
use edge_memory_harness::report_io::{publish_canonical_bytes, publish_digest, sha256_hex};
use edge_memory_harness::HarnessError;

fn main() {
    if let Err(error) = run(env::args().skip(1).collect()) {
        eprintln!("full profile readiness error: {error}");
        std::process::exit(1);
    }
}

fn run(arguments: Vec<String>) -> Result<(), HarnessError> {
    let (command, options) = parse(arguments)?;
    match command.as_str() {
        "collect" => {
            exact_keys(&options, &["--input", "--output", "--digest-output"])?;
            let input = FullProfileInput::from_json(&read_regular(Path::new(required(
                &options, "--input",
            )?))?)?;
            let report = evaluate_full_profile(input)?;
            let encoded = report.to_canonical_json()?;
            let published = publish_canonical_bytes(
                &PathBuf::from(required(&options, "--output")?),
                encoded.as_bytes(),
            )?;
            publish_digest(
                &PathBuf::from(required(&options, "--digest-output")?),
                &published.sha256,
            )?;
            println!(
                "full profile readiness collected ready={} blockers={} digest={}",
                report.ready,
                report.blockers.len(),
                published.sha256
            );
        }
        "validate" => {
            exact_keys(&options, &["--build-identity", "--report", "--digest"])?;
            let report_bytes = read_regular(Path::new(required(&options, "--report")?))?;
            let digest_bytes = read_regular(Path::new(required(&options, "--digest")?))?;
            let digest = parse_digest(&digest_bytes)?;
            if sha256_hex(&report_bytes) != digest {
                return Err(HarnessError::new("full profile readiness digest mismatch"));
            }
            let report = FullProfileReadinessReport::from_canonical_json(&report_bytes)?;
            if report.build_identity != required(&options, "--build-identity")? {
                return Err(HarnessError::new(
                    "full profile readiness source identity mismatch",
                ));
            }
            println!(
                "full profile readiness validated ready={} blockers={} digest={}",
                report.ready,
                report.blockers.len(),
                digest
            );
        }
        _ => return Err(HarnessError::new("unknown full profile command")),
    }
    Ok(())
}

fn parse(arguments: Vec<String>) -> Result<(String, BTreeMap<String, String>), HarnessError> {
    let mut values = arguments.into_iter();
    let command = values
        .next()
        .ok_or_else(|| HarnessError::new("full profile command is required"))?;
    let mut options = BTreeMap::new();
    while let Some(key) = values.next() {
        if !key.starts_with("--") || options.contains_key(&key) {
            return Err(HarnessError::new("full profile option is invalid"));
        }
        let value = values
            .next()
            .filter(|value| !value.is_empty())
            .ok_or_else(|| HarnessError::new("full profile option value is missing"))?;
        options.insert(key, value);
    }
    Ok((command, options))
}

fn exact_keys(options: &BTreeMap<String, String>, expected: &[&str]) -> Result<(), HarnessError> {
    if options.len() != expected.len() || expected.iter().any(|key| !options.contains_key(*key)) {
        return Err(HarnessError::new("full profile option set is invalid"));
    }
    Ok(())
}

fn required<'a>(options: &'a BTreeMap<String, String>, key: &str) -> Result<&'a str, HarnessError> {
    options
        .get(key)
        .map(String::as_str)
        .ok_or_else(|| HarnessError::new("full profile option is missing"))
}

fn read_regular(path: &Path) -> Result<Vec<u8>, HarnessError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| HarnessError::new("full profile file is unavailable"))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(HarnessError::new(
            "full profile file must be physical and regular",
        ));
    }
    fs::read(path).map_err(|_| HarnessError::new("full profile file cannot be read"))
}

fn parse_digest(bytes: &[u8]) -> Result<String, HarnessError> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| HarnessError::new("full profile digest is not UTF-8"))?;
    let digest = text
        .strip_suffix('\n')
        .filter(|value| !value.contains('\n'))
        .ok_or_else(|| HarnessError::new("full profile digest is not canonical"))?;
    Ok(digest.to_string())
}
