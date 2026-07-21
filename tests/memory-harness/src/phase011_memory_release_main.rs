use std::collections::BTreeMap;
use std::env;
use std::path::PathBuf;

use edge_memory_harness::phase011_memory_release_cli::{
    collect_phase011_memory_release, validate_phase011_memory_release, MemoryReleaseCollectOptions,
    MemoryReleaseValidateOptions,
};
use edge_memory_harness::HarnessError;

fn main() {
    if let Err(error) = run(env::args().skip(1).collect()) {
        eprintln!("Phase 011 memory release error: {error}");
        std::process::exit(1);
    }
}

fn run(arguments: Vec<String>) -> Result<(), HarnessError> {
    let (command, options) = parse(arguments)?;
    let summary = match command.as_str() {
        "collect" => {
            exact_keys(
                &options,
                &[
                    "--build-identity",
                    "--platform",
                    "--architecture",
                    "--inventory",
                    "--inventory-digest",
                    "--readiness",
                    "--readiness-digest",
                    "--soak-report",
                    "--soak-digest",
                    "--output",
                    "--digest-output",
                ],
            )?;
            collect_phase011_memory_release(MemoryReleaseCollectOptions {
                expected_build_identity: required(&options, "--build-identity")?,
                expected_platform: required(&options, "--platform")?,
                expected_architecture: required(&options, "--architecture")?,
                inventory: path(&options, "--inventory")?,
                inventory_digest: path(&options, "--inventory-digest")?,
                readiness: path(&options, "--readiness")?,
                readiness_digest: path(&options, "--readiness-digest")?,
                soak: path(&options, "--soak-report")?,
                soak_digest: path(&options, "--soak-digest")?,
                output: path(&options, "--output")?,
                output_digest: path(&options, "--digest-output")?,
            })?
        }
        "validate" => {
            exact_keys(&options, &["--build-identity", "--report", "--digest"])?;
            validate_phase011_memory_release(MemoryReleaseValidateOptions {
                expected_build_identity: required(&options, "--build-identity")?,
                report: path(&options, "--report")?,
                digest: path(&options, "--digest")?,
            })?
        }
        _ => {
            return Err(HarnessError::new(
                "unknown Phase 011 memory release command",
            ))
        }
    };
    println!("{summary}");
    Ok(())
}

fn parse(arguments: Vec<String>) -> Result<(String, BTreeMap<String, String>), HarnessError> {
    let mut values = arguments.into_iter();
    let command = values
        .next()
        .ok_or_else(|| HarnessError::new("Phase 011 memory release command is required"))?;
    let mut options = BTreeMap::new();
    while let Some(key) = values.next() {
        if !key.starts_with("--") || options.contains_key(&key) {
            return Err(HarnessError::new(
                "Phase 011 memory release option is invalid",
            ));
        }
        let value = values
            .next()
            .filter(|value| !value.is_empty())
            .ok_or_else(|| HarnessError::new("Phase 011 memory release option is missing"))?;
        options.insert(key, value);
    }
    Ok((command, options))
}

fn exact_keys(options: &BTreeMap<String, String>, expected: &[&str]) -> Result<(), HarnessError> {
    if options.len() != expected.len() || expected.iter().any(|key| !options.contains_key(*key)) {
        return Err(HarnessError::new(
            "Phase 011 memory release option set is invalid",
        ));
    }
    Ok(())
}

fn required(values: &BTreeMap<String, String>, key: &str) -> Result<String, HarnessError> {
    values
        .get(key)
        .cloned()
        .ok_or_else(|| HarnessError::new("Phase 011 memory release option is missing"))
}

fn path(values: &BTreeMap<String, String>, key: &str) -> Result<PathBuf, HarnessError> {
    Ok(PathBuf::from(required(values, key)?))
}
