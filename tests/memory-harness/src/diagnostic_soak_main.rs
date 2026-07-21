use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use edge_memory_harness::diagnostic_soak::{
    evaluate_diagnostic_soak, DiagnosticSoakInput, DiagnosticSoakReport,
};
use edge_memory_harness::report_io::{publish_canonical_bytes, publish_digest, sha256_hex};
use edge_memory_harness::HarnessError;

fn main() {
    if let Err(error) = run(env::args().skip(1).collect()) {
        eprintln!("diagnostic soak error: {error}");
        std::process::exit(1);
    }
}

fn run(arguments: Vec<String>) -> Result<(), HarnessError> {
    let (command, options) = parse(arguments)?;
    match command.as_str() {
        "collect" => {
            exact_keys(&options, &["--input", "--output", "--digest-output"])?;
            let input = DiagnosticSoakInput::from_json(&read_regular(Path::new(required(
                &options, "--input",
            )?))?)?;
            let report = evaluate_diagnostic_soak(input.observations)?;
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
                "diagnostic soak collected duration={} observations={} first_median={} last_median={} digest={}",
                report.duration_seconds,
                report.observation_count,
                report.first_window_median_rss_bytes,
                report.last_window_median_rss_bytes,
                published.sha256
            );
        }
        "validate" => {
            exact_keys(&options, &["--build-identity", "--report", "--digest"])?;
            let report_bytes = read_regular(Path::new(required(&options, "--report")?))?;
            let digest_bytes = read_regular(Path::new(required(&options, "--digest")?))?;
            let digest = parse_digest(&digest_bytes)?;
            if sha256_hex(&report_bytes) != digest {
                return Err(HarnessError::new("diagnostic soak digest mismatch"));
            }
            let report = DiagnosticSoakReport::from_canonical_json(&report_bytes)?;
            if report.build_identity != required(&options, "--build-identity")? {
                return Err(HarnessError::new(
                    "diagnostic soak source identity mismatch",
                ));
            }
            println!(
                "diagnostic soak validated duration={} observations={} plateau=passed digest={}",
                report.duration_seconds, report.observation_count, digest
            );
        }
        _ => return Err(HarnessError::new("unknown diagnostic soak command")),
    }
    Ok(())
}

fn parse(arguments: Vec<String>) -> Result<(String, BTreeMap<String, String>), HarnessError> {
    let mut values = arguments.into_iter();
    let command = values
        .next()
        .ok_or_else(|| HarnessError::new("diagnostic soak command is required"))?;
    let mut options = BTreeMap::new();
    while let Some(key) = values.next() {
        if !key.starts_with("--") || options.contains_key(&key) {
            return Err(HarnessError::new("diagnostic soak option is invalid"));
        }
        let value = values
            .next()
            .filter(|value| !value.is_empty())
            .ok_or_else(|| HarnessError::new("diagnostic soak option value is missing"))?;
        options.insert(key, value);
    }
    Ok((command, options))
}

fn exact_keys(options: &BTreeMap<String, String>, expected: &[&str]) -> Result<(), HarnessError> {
    if options.len() != expected.len() || expected.iter().any(|key| !options.contains_key(*key)) {
        return Err(HarnessError::new("diagnostic soak option set is invalid"));
    }
    Ok(())
}

fn required<'a>(options: &'a BTreeMap<String, String>, key: &str) -> Result<&'a str, HarnessError> {
    options
        .get(key)
        .map(String::as_str)
        .ok_or_else(|| HarnessError::new("diagnostic soak option is missing"))
}

fn read_regular(path: &Path) -> Result<Vec<u8>, HarnessError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| HarnessError::new("diagnostic soak file is unavailable"))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(HarnessError::new(
            "diagnostic soak file must be physical and regular",
        ));
    }
    fs::read(path).map_err(|_| HarnessError::new("diagnostic soak file cannot be read"))
}

fn parse_digest(bytes: &[u8]) -> Result<String, HarnessError> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| HarnessError::new("diagnostic soak digest is not UTF-8"))?;
    let digest = text
        .strip_suffix('\n')
        .filter(|value| !value.contains('\n'))
        .ok_or_else(|| HarnessError::new("diagnostic soak digest is not canonical"))?;
    Ok(digest.to_string())
}
