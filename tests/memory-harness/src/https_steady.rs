use std::collections::BTreeMap;
use std::fs;
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::{Duration, Instant};

use rustls_pki_types::pem::PemObject;
use serde::{Deserialize, Serialize};

use crate::http_driver::{validate_response, HttpLoadCounters};
use crate::report_io::publish_canonical_bytes;
use crate::HarnessError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpsSteadySpec {
    address: SocketAddr,
    host: String,
    server_name: String,
    total_requests: usize,
    workers: usize,
    timeout: Duration,
    max_response_bytes: usize,
}

impl HttpsSteadySpec {
    pub fn new(
        address: SocketAddr,
        host: impl Into<String>,
        server_name: impl Into<String>,
        total_requests: usize,
        workers: usize,
        timeout: Duration,
        max_response_bytes: usize,
    ) -> Result<Self, HarnessError> {
        let host = host.into();
        let server_name = server_name.into();
        if host.is_empty()
            || total_requests == 0
            || workers == 0
            || workers > total_requests
            || timeout.is_zero()
            || max_response_bytes == 0
            || rustls_pki_types::ServerName::try_from(server_name.clone()).is_err()
        {
            return Err(HarnessError::new(
                "HTTPS steady load specification is invalid",
            ));
        }
        Ok(Self {
            address,
            host,
            server_name,
            total_requests,
            workers,
            timeout,
            max_response_bytes,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpsSteadyState {
    Created,
    Warming,
    Loading,
    Cooling,
    Completed,
    Failed,
}

pub struct HttpsSteadyDriver {
    spec: HttpsSteadySpec,
    config: Arc<rustls::ClientConfig>,
    state: HttpsSteadyState,
}

impl HttpsSteadyDriver {
    pub fn new(spec: HttpsSteadySpec, config: Arc<rustls::ClientConfig>) -> Self {
        Self {
            spec,
            config,
            state: HttpsSteadyState::Created,
        }
    }

    pub fn state(&self) -> HttpsSteadyState {
        self.state
    }

    pub fn run(&mut self) -> Result<HttpLoadCounters, HarnessError> {
        if self.state != HttpsSteadyState::Created {
            self.state = HttpsSteadyState::Failed;
            return Err(HarnessError::new(
                "HTTPS steady load lifecycle transition is invalid",
            ));
        }
        self.state = HttpsSteadyState::Warming;
        let requests_per_worker = self.spec.total_requests / self.spec.workers;
        let remainder = self.spec.total_requests % self.spec.workers;
        let start_barrier = Arc::new(Barrier::new(self.spec.workers + 1));
        let results = std::thread::scope(|scope| {
            let handles = (0..self.spec.workers)
                .map(|worker_index| {
                    let spec = self.spec.clone();
                    let config = Arc::clone(&self.config);
                    let start_barrier = Arc::clone(&start_barrier);
                    let worker_requests =
                        requests_per_worker + usize::from(worker_index < remainder);
                    scope.spawn(move || {
                        start_barrier.wait();
                        run_worker(&spec, &config, worker_requests)
                    })
                })
                .collect::<Vec<_>>();
            self.state = HttpsSteadyState::Loading;
            start_barrier.wait();
            handles
                .into_iter()
                .map(|handle| {
                    handle
                        .join()
                        .map_err(|_| HarnessError::new("HTTPS steady worker panicked"))
                })
                .collect::<Result<Vec<_>, HarnessError>>()
        });
        let results = match results {
            Ok(results) => results,
            Err(error) => {
                self.state = HttpsSteadyState::Failed;
                return Err(error);
            }
        };
        self.state = HttpsSteadyState::Cooling;
        let mut counters = HttpLoadCounters {
            expected: self.spec.total_requests as u64,
            succeeded: 0,
            failed: 0,
        };
        for result in results {
            counters.succeeded = counters
                .succeeded
                .checked_add(result.succeeded)
                .ok_or_else(|| HarnessError::new("HTTPS steady success count overflow"))?;
            counters.failed = counters
                .failed
                .checked_add(result.failed)
                .ok_or_else(|| HarnessError::new("HTTPS steady failure count overflow"))?;
        }
        let exact = counters.succeeded.checked_add(counters.failed) == Some(counters.expected)
            && counters.expected == self.spec.total_requests as u64;
        self.state = if exact && counters.failed == 0 {
            HttpsSteadyState::Completed
        } else {
            HttpsSteadyState::Failed
        };
        if !exact {
            return Err(HarnessError::new("HTTPS steady aggregate count mismatch"));
        }
        Ok(counters)
    }
}

fn run_worker(
    spec: &HttpsSteadySpec,
    config: &Arc<rustls::ClientConfig>,
    requests: usize,
) -> HttpLoadCounters {
    let mut counters = HttpLoadCounters {
        expected: requests as u64,
        succeeded: 0,
        failed: 0,
    };
    for _ in 0..requests {
        match execute_request(spec, config) {
            Ok(()) => counters.succeeded += 1,
            Err(_) => counters.failed += 1,
        }
    }
    counters
}

fn execute_request(
    spec: &HttpsSteadySpec,
    config: &Arc<rustls::ClientConfig>,
) -> Result<(), HarnessError> {
    let mut stream = std::net::TcpStream::connect_timeout(&spec.address, spec.timeout)
        .map_err(|_| HarnessError::new("HTTPS steady connection failed"))?;
    stream
        .set_read_timeout(Some(spec.timeout))
        .and_then(|_| stream.set_write_timeout(Some(spec.timeout)))
        .map_err(|_| HarnessError::new("HTTPS steady timeout configuration failed"))?;
    let server_name = rustls_pki_types::ServerName::try_from(spec.server_name.clone())
        .map_err(|_| HarnessError::new("HTTPS steady server name is invalid"))?;
    let mut connection = rustls::ClientConnection::new(Arc::clone(config), server_name)
        .map_err(|_| HarnessError::new("HTTPS steady client creation failed"))?;
    connection
        .complete_io(&mut stream)
        .map_err(|_| HarnessError::new("HTTPS steady handshake failed"))?;
    let mut stream = rustls::StreamOwned::new(connection, stream);
    let request = format!(
        "GET / HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        spec.host
    );
    stream
        .write_all(request.as_bytes())
        .map_err(|_| HarnessError::new("HTTPS steady request write failed"))?;
    let mut response = Vec::with_capacity(spec.max_response_bytes.min(8 * 1024));
    let mut chunk = [0_u8; 4096];
    loop {
        let read = stream
            .read(&mut chunk)
            .map_err(|_| HarnessError::new("HTTPS steady response read failed"))?;
        if read == 0 {
            break;
        }
        if response.len().checked_add(read).is_none()
            || response.len() + read > spec.max_response_bytes
        {
            return Err(HarnessError::new("HTTPS steady response exceeds bound"));
        }
        response.extend_from_slice(&chunk[..read]);
    }
    validate_response(&response)
}

pub fn build_https_client_config(
    root_pem: &[u8],
) -> Result<Arc<rustls::ClientConfig>, HarnessError> {
    let root = rustls_pki_types::CertificateDer::from_pem_slice(root_pem)
        .map_err(|_| HarnessError::new("HTTPS steady root parse failed"))?;
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(root)
        .map_err(|_| HarnessError::new("HTTPS steady root is invalid"))?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|_| HarnessError::new("HTTPS steady protocol config failed"))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(Arc::new(config))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpsSteadyOptions {
    pub address: SocketAddr,
    pub host: String,
    pub server_name: String,
    pub root_pem: PathBuf,
    pub requests: usize,
    pub workers: usize,
    pub timeout_ms: u64,
    pub max_response_bytes: usize,
    pub ready_output: PathBuf,
    pub start_file: PathBuf,
    pub summary_output: PathBuf,
    pub start_timeout_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpsSteadySummary {
    pub schema_version: u16,
    pub expected: u64,
    pub succeeded: u64,
    pub failed: u64,
    pub workers: usize,
    pub state: String,
}

pub fn parse_https_steady_options(args: &[String]) -> Result<HttpsSteadyOptions, HarnessError> {
    const KEYS: [&str; 12] = [
        "--address",
        "--host",
        "--server-name",
        "--root-pem",
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
        return Err(HarnessError::new("HTTPS steady options are incomplete"));
    }
    let mut values = BTreeMap::new();
    for pair in args.chunks_exact(2) {
        if !KEYS.contains(&pair[0].as_str())
            || pair[1].is_empty()
            || values.insert(pair[0].clone(), pair[1].clone()).is_some()
        {
            return Err(HarnessError::new(
                "HTTPS steady option is unknown or duplicated",
            ));
        }
    }
    let address = required(&values, "--address")?
        .parse()
        .map_err(|_| HarnessError::new("HTTPS steady address is invalid"))?;
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
    Ok(HttpsSteadyOptions {
        address,
        host,
        server_name,
        root_pem: PathBuf::from(required(&values, "--root-pem")?),
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

pub fn run_https_steady_options(options: HttpsSteadyOptions) -> Result<String, HarnessError> {
    let root_pem = fs::read(&options.root_pem)
        .map_err(|_| HarnessError::new("HTTPS steady root read failed"))?;
    let config = build_https_client_config(&root_pem)?;
    run_https_steady_with_config(options, config)
}

pub(crate) fn run_https_steady_with_config(
    options: HttpsSteadyOptions,
    config: Arc<rustls::ClientConfig>,
) -> Result<String, HarnessError> {
    if options.start_file.exists() {
        return Err(HarnessError::new(
            "HTTPS steady start file exists before readiness",
        ));
    }
    publish_canonical_bytes(
        &options.ready_output,
        format!("{} {}\n", options.requests, options.workers).as_bytes(),
    )?;
    let deadline = Instant::now() + Duration::from_millis(options.start_timeout_ms);
    while !options.start_file.exists() {
        if Instant::now() >= deadline {
            return Err(HarnessError::new("HTTPS steady start wait timed out"));
        }
        thread::sleep(Duration::from_millis(10));
    }
    let spec = HttpsSteadySpec::new(
        options.address,
        options.host,
        options.server_name,
        options.requests,
        options.workers,
        Duration::from_millis(options.timeout_ms),
        options.max_response_bytes,
    )?;
    let mut driver = HttpsSteadyDriver::new(spec, config);
    let counters = driver.run()?;
    let summary = HttpsSteadySummary {
        schema_version: 1,
        expected: counters.expected,
        succeeded: counters.succeeded,
        failed: counters.failed,
        workers: options.workers,
        state: match driver.state() {
            HttpsSteadyState::Completed => "completed",
            HttpsSteadyState::Failed => "failed",
            _ => "invalid",
        }
        .into(),
    };
    let encoded = serde_json::to_vec(&summary)
        .map_err(|_| HarnessError::new("HTTPS steady summary encoding failed"))?;
    publish_canonical_bytes(&options.summary_output, &encoded)?;
    if summary.failed != 0 || summary.succeeded != summary.expected {
        return Err(HarnessError::new(format!(
            "HTTPS steady load did not fully succeed: expected={} succeeded={} failed={}",
            summary.expected, summary.succeeded, summary.failed
        )));
    }
    Ok(format!(
        "HTTPS steady completed expected={} succeeded={} failed={} workers={}",
        summary.expected, summary.succeeded, summary.failed, summary.workers
    ))
}

fn required(values: &BTreeMap<String, String>, key: &str) -> Result<String, HarnessError> {
    values
        .get(key)
        .cloned()
        .ok_or_else(|| HarnessError::new(format!("HTTPS steady option is missing: {key}")))
}

fn positive_usize(values: &BTreeMap<String, String>, key: &str) -> Result<usize, HarnessError> {
    positive_u64(values, key)?
        .try_into()
        .map_err(|_| HarnessError::new("HTTPS steady value exceeds usize"))
}

fn positive_u64(values: &BTreeMap<String, String>, key: &str) -> Result<u64, HarnessError> {
    let value = required(values, key)?
        .parse::<u64>()
        .map_err(|_| HarnessError::new("HTTPS steady numeric option is invalid"))?;
    if value == 0 {
        return Err(HarnessError::new(
            "HTTPS steady numeric option must be positive",
        ));
    }
    Ok(value)
}
