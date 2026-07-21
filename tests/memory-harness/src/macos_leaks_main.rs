use std::collections::BTreeMap;
use std::env;
use std::path::PathBuf;

use edge_memory_harness::macos_leaks_cli::{
    collect_macos_leaks, validate_macos_leaks, MacosLeaksCollectOptions, MacosLeaksValidateOptions,
};
use edge_memory_harness::HarnessError;

fn main() {
    if let Err(error) = run(env::args().skip(1).collect()) {
        eprintln!("macOS leaks evidence error: {error}");
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
                    "--architecture",
                    "--original-binary-sha256",
                    "--signed-binary-sha256",
                    "--config-sha256",
                    "--process-identity-sha256",
                    "--tool-exit-code",
                    "--workload-expected",
                    "--workload-succeeded",
                    "--workload-failed",
                    "--cleanup-connections",
                    "--cleanup-payload-bytes",
                    "--cleanup-pressure",
                    "--recovery-status",
                    "--raw",
                    "--raw-digest",
                    "--report",
                    "--report-digest",
                ],
            )?;
            collect_macos_leaks(MacosLeaksCollectOptions {
                build_identity: required(&options, "--build-identity")?,
                architecture: required(&options, "--architecture")?,
                original_binary_sha256: required(&options, "--original-binary-sha256")?,
                signed_binary_sha256: required(&options, "--signed-binary-sha256")?,
                config_sha256: required(&options, "--config-sha256")?,
                process_identity_sha256: required(&options, "--process-identity-sha256")?,
                tool_exit_code: number(&options, "--tool-exit-code")?,
                workload_expected: number(&options, "--workload-expected")?,
                workload_succeeded: number(&options, "--workload-succeeded")?,
                workload_failed: number(&options, "--workload-failed")?,
                cleanup_connections: number(&options, "--cleanup-connections")?,
                cleanup_payload_bytes: number(&options, "--cleanup-payload-bytes")?,
                cleanup_pressure: required(&options, "--cleanup-pressure")?,
                recovery_status: number(&options, "--recovery-status")?,
                raw: path(&options, "--raw")?,
                raw_digest: path(&options, "--raw-digest")?,
                report: path(&options, "--report")?,
                report_digest: path(&options, "--report-digest")?,
            })?
        }
        "validate" => {
            exact_keys(
                &options,
                &[
                    "--build-identity",
                    "--raw",
                    "--raw-digest",
                    "--report",
                    "--report-digest",
                ],
            )?;
            validate_macos_leaks(MacosLeaksValidateOptions {
                expected_build_identity: required(&options, "--build-identity")?,
                raw: path(&options, "--raw")?,
                raw_digest: path(&options, "--raw-digest")?,
                report: path(&options, "--report")?,
                report_digest: path(&options, "--report-digest")?,
            })?
        }
        _ => return Err(HarnessError::new("unknown macOS leaks evidence command")),
    };
    println!("{summary}");
    Ok(())
}

fn parse(arguments: Vec<String>) -> Result<(String, BTreeMap<String, String>), HarnessError> {
    let mut values = arguments.into_iter();
    let command = values
        .next()
        .ok_or_else(|| HarnessError::new("macOS leaks evidence command is required"))?;
    let mut options = BTreeMap::new();
    while let Some(key) = values.next() {
        if !key.starts_with("--") || options.contains_key(&key) {
            return Err(HarnessError::new("macOS leaks evidence option is invalid"));
        }
        let value = values
            .next()
            .filter(|value| !value.is_empty())
            .ok_or_else(|| HarnessError::new("macOS leaks evidence option is missing"))?;
        options.insert(key, value);
    }
    Ok((command, options))
}

fn exact_keys(options: &BTreeMap<String, String>, expected: &[&str]) -> Result<(), HarnessError> {
    if options.len() != expected.len() || expected.iter().any(|key| !options.contains_key(*key)) {
        return Err(HarnessError::new(
            "macOS leaks evidence option set is invalid",
        ));
    }
    Ok(())
}

fn required(values: &BTreeMap<String, String>, key: &str) -> Result<String, HarnessError> {
    values
        .get(key)
        .cloned()
        .ok_or_else(|| HarnessError::new("macOS leaks evidence option is missing"))
}

fn number<T: std::str::FromStr>(
    values: &BTreeMap<String, String>,
    key: &str,
) -> Result<T, HarnessError> {
    required(values, key)?
        .parse()
        .map_err(|_| HarnessError::new("macOS leaks evidence number is invalid"))
}

fn path(values: &BTreeMap<String, String>, key: &str) -> Result<PathBuf, HarnessError> {
    Ok(PathBuf::from(required(values, key)?))
}
