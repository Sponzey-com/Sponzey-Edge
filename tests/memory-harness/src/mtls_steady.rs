use std::collections::BTreeMap;
use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use crate::https_steady::{run_https_steady_with_config, HttpsSteadyOptions, HttpsSteadySpec};
use crate::mtls_connection_holder::build_mtls_client_config;
use crate::HarnessError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MtlsSteadyOptions {
    pub address: SocketAddr,
    pub host: String,
    pub server_name: String,
    pub root_pem: PathBuf,
    pub client_chain_pem: PathBuf,
    pub client_key_pem: PathBuf,
    pub requests: usize,
    pub workers: usize,
    pub timeout_ms: u64,
    pub max_response_bytes: usize,
    pub ready_output: PathBuf,
    pub start_file: PathBuf,
    pub summary_output: PathBuf,
    pub start_timeout_ms: u64,
}

pub fn build_mtls_steady_client_config(
    root_pem: &[u8],
    client_chain_pem: &[u8],
    client_key_pem: &[u8],
) -> Result<Arc<rustls::ClientConfig>, HarnessError> {
    build_mtls_client_config(root_pem, client_chain_pem, client_key_pem)
}

pub fn parse_mtls_steady_options(args: &[String]) -> Result<MtlsSteadyOptions, HarnessError> {
    const KEYS: [&str; 14] = [
        "--address",
        "--host",
        "--server-name",
        "--root-pem",
        "--client-chain-pem",
        "--client-key-pem",
        "--requests",
        "--workers",
        "--timeout-ms",
        "--max-response-bytes",
        "--ready-output",
        "--start-file",
        "--summary-output",
        "--start-timeout-ms",
    ];
    if args.len() != KEYS.len() * 2 {
        return Err(HarnessError::new("mTLS steady options are incomplete"));
    }
    let mut values = BTreeMap::new();
    for pair in args.chunks_exact(2) {
        if !KEYS.contains(&pair[0].as_str())
            || pair[1].is_empty()
            || values.insert(pair[0].clone(), pair[1].clone()).is_some()
        {
            return Err(HarnessError::new(
                "mTLS steady option is unknown or duplicated",
            ));
        }
    }
    let address = required(&values, "--address")?
        .parse()
        .map_err(|_| HarnessError::new("mTLS steady address is invalid"))?;
    let host = required(&values, "--host")?;
    let server_name = required(&values, "--server-name")?;
    let requests = positive_usize(&values, "--requests")?;
    let workers = positive_usize(&values, "--workers")?;
    let timeout_ms = positive_u64(&values, "--timeout-ms")?;
    let max_response_bytes = positive_usize(&values, "--max-response-bytes")?;
    let start_timeout_ms = positive_u64(&values, "--start-timeout-ms")?;
    HttpsSteadySpec::new(
        address,
        host.clone(),
        server_name.clone(),
        requests,
        workers,
        Duration::from_millis(timeout_ms),
        max_response_bytes,
    )?;
    Ok(MtlsSteadyOptions {
        address,
        host,
        server_name,
        root_pem: PathBuf::from(required(&values, "--root-pem")?),
        client_chain_pem: PathBuf::from(required(&values, "--client-chain-pem")?),
        client_key_pem: PathBuf::from(required(&values, "--client-key-pem")?),
        requests,
        workers,
        timeout_ms,
        max_response_bytes,
        ready_output: PathBuf::from(required(&values, "--ready-output")?),
        start_file: PathBuf::from(required(&values, "--start-file")?),
        summary_output: PathBuf::from(required(&values, "--summary-output")?),
        start_timeout_ms,
    })
}

pub fn run_mtls_steady_options(options: MtlsSteadyOptions) -> Result<String, HarnessError> {
    let root = fs::read(&options.root_pem)
        .map_err(|_| HarnessError::new("mTLS steady root read failed"))?;
    let chain = fs::read(&options.client_chain_pem)
        .map_err(|_| HarnessError::new("mTLS steady client chain read failed"))?;
    let key = fs::read(&options.client_key_pem)
        .map_err(|_| HarnessError::new("mTLS steady client key read failed"))?;
    let config = build_mtls_steady_client_config(&root, &chain, &key)?;
    let https = HttpsSteadyOptions {
        address: options.address,
        host: options.host,
        server_name: options.server_name,
        root_pem: options.root_pem,
        requests: options.requests,
        workers: options.workers,
        timeout_ms: options.timeout_ms,
        max_response_bytes: options.max_response_bytes,
        ready_output: options.ready_output,
        start_file: options.start_file,
        summary_output: options.summary_output,
        start_timeout_ms: options.start_timeout_ms,
    };
    run_https_steady_with_config(https, config)
}

fn required(values: &BTreeMap<String, String>, key: &str) -> Result<String, HarnessError> {
    values
        .get(key)
        .cloned()
        .ok_or_else(|| HarnessError::new(format!("mTLS steady option is missing: {key}")))
}

fn positive_usize(values: &BTreeMap<String, String>, key: &str) -> Result<usize, HarnessError> {
    positive_u64(values, key)?
        .try_into()
        .map_err(|_| HarnessError::new("mTLS steady value exceeds usize"))
}

fn positive_u64(values: &BTreeMap<String, String>, key: &str) -> Result<u64, HarnessError> {
    let value = required(values, key)?
        .parse::<u64>()
        .map_err(|_| HarnessError::new("mTLS steady numeric option is invalid"))?;
    if value == 0 {
        return Err(HarnessError::new(
            "mTLS steady numeric option must be positive",
        ));
    }
    Ok(value)
}
