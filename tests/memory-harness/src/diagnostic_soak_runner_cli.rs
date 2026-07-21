use std::collections::BTreeMap;
use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::diagnostic_soak_runner::{DiagnosticSoakOrchestrator, PortSoakWindowExecutor};
use crate::report_io::{publish_canonical_bytes, publish_digest};
use crate::soak_window::SoakWindowIdentity;
use crate::soak_window_adapters::{
    AdminSoakWindowRuntime, AttachedSoakWindowProcess, DriverSoakWindowLoad, SystemSoakSchedule,
};
use crate::HarnessError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiagnosticSoakRunnerOptions {
    pub pid: u32,
    pub proxy_address: SocketAddr,
    pub admin_address: SocketAddr,
    pub host: String,
    pub expected_revision: String,
    pub build_identity: String,
    pub config_sha256: String,
    pub output: PathBuf,
    pub digest_output: PathBuf,
}

pub fn parse_diagnostic_soak_runner_options(
    arguments: &[String],
) -> Result<DiagnosticSoakRunnerOptions, HarnessError> {
    const KEYS: [&str; 9] = [
        "--pid",
        "--proxy-address",
        "--admin-address",
        "--host",
        "--expected-revision",
        "--build-identity",
        "--config-sha256",
        "--output",
        "--digest-output",
    ];
    if arguments.len() != KEYS.len() * 2 {
        return Err(HarnessError::new(
            "diagnostic soak runner option set is invalid",
        ));
    }
    let mut values = BTreeMap::new();
    for pair in arguments.chunks_exact(2) {
        if !KEYS.contains(&pair[0].as_str())
            || pair[1].is_empty()
            || values.insert(pair[0].clone(), pair[1].clone()).is_some()
        {
            return Err(HarnessError::new(
                "diagnostic soak runner option is invalid",
            ));
        }
    }
    let pid = required(&values, "--pid")?
        .parse::<u32>()
        .ok()
        .filter(|value| *value > 0)
        .ok_or_else(|| HarnessError::new("diagnostic soak runner PID is invalid"))?;
    let output = PathBuf::from(required(&values, "--output")?);
    let digest_output = PathBuf::from(required(&values, "--digest-output")?);
    if output == digest_output {
        return Err(HarnessError::new(
            "diagnostic soak runner outputs must differ",
        ));
    }
    Ok(DiagnosticSoakRunnerOptions {
        pid,
        proxy_address: socket(&values, "--proxy-address")?,
        admin_address: socket(&values, "--admin-address")?,
        host: required(&values, "--host")?,
        expected_revision: required(&values, "--expected-revision")?,
        build_identity: required(&values, "--build-identity")?,
        config_sha256: required(&values, "--config-sha256")?,
        output,
        digest_output,
    })
}

pub fn run_diagnostic_soak_runner(
    options: DiagnosticSoakRunnerOptions,
) -> Result<String, HarnessError> {
    require_absent(&options.output)?;
    require_absent(&options.digest_output)?;
    let timeout = Duration::from_secs(15);
    let load = DriverSoakWindowLoad::new(
        options.proxy_address,
        options.proxy_address,
        options.host.clone(),
        timeout,
        65_536,
        4_096,
    )?;
    let runtime = AdminSoakWindowRuntime::new(
        options.admin_address,
        options.proxy_address,
        options.expected_revision,
        options.host,
        timeout,
        256 * 1024,
        65_536,
    )?;
    let process = AttachedSoakWindowProcess::attach(options.pid)?;
    let identity = SoakWindowIdentity::new(
        options.build_identity,
        options.config_sha256,
        process.start_identity(),
    )?;
    let executor = PortSoakWindowExecutor::new(load, runtime, process);
    let mut orchestrator =
        DiagnosticSoakOrchestrator::new(SystemSoakSchedule::new(), executor, identity);
    let report = orchestrator.run()?;
    let encoded = report.to_canonical_json()?;
    let published = publish_canonical_bytes(&options.output, encoded.as_bytes())?;
    publish_digest(&options.digest_output, &published.sha256)?;
    Ok(format!(
        "diagnostic soak runner published duration={} observations={} churn={} websocket={} digest={}",
        report.duration_seconds,
        report.observation_count,
        report.churn_requests,
        report.websocket_lifecycles,
        published.sha256
    ))
}

fn required(values: &BTreeMap<String, String>, key: &str) -> Result<String, HarnessError> {
    values
        .get(key)
        .cloned()
        .ok_or_else(|| HarnessError::new("diagnostic soak runner option is missing"))
}

fn socket(values: &BTreeMap<String, String>, key: &str) -> Result<SocketAddr, HarnessError> {
    required(values, key)?
        .parse()
        .map_err(|_| HarnessError::new("diagnostic soak runner address is invalid"))
}

fn require_absent(path: &Path) -> Result<(), HarnessError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Err(HarnessError::new(
            "diagnostic soak runner output already exists",
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(HarnessError::new(
            "diagnostic soak runner output cannot be inspected",
        )),
    }
}
