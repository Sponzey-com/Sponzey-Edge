use crate::diagnostic_soak::{DiagnosticSoakObservation, SoakWorkload, SOAK_INTERVAL_SECONDS};
use crate::HarnessError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SoakWindowIdentity {
    build_identity: String,
    config_sha256: String,
    process_start_identity: String,
}

impl SoakWindowIdentity {
    pub fn new(
        build_identity: impl Into<String>,
        config_sha256: impl Into<String>,
        process_start_identity: impl Into<String>,
    ) -> Result<Self, HarnessError> {
        let value = Self {
            build_identity: build_identity.into(),
            config_sha256: config_sha256.into(),
            process_start_identity: process_start_identity.into(),
        };
        if !value
            .build_identity
            .strip_prefix("source-tree-sha256:")
            .is_some_and(valid_digest)
            || !valid_digest(&value.config_sha256)
            || value.process_start_identity.is_empty()
        {
            return Err(HarnessError::new("soak window identity is invalid"));
        }
        Ok(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SoakWindowRequest {
    index: u32,
    elapsed_seconds: u64,
    workload: SoakWorkload,
    expected: u64,
    identity: SoakWindowIdentity,
}

impl SoakWindowRequest {
    pub fn new(
        index: u32,
        elapsed_seconds: u64,
        identity: SoakWindowIdentity,
    ) -> Result<Self, HarnessError> {
        if index > 120 || elapsed_seconds != u64::from(index) * SOAK_INTERVAL_SECONDS {
            return Err(HarnessError::new("soak window position is invalid"));
        }
        let (workload, expected) = match index {
            0 => (SoakWorkload::Baseline, 0),
            value if value % 2 == 1 => (SoakWorkload::Churn, 1_000),
            _ => (SoakWorkload::Websocket, 128),
        };
        Ok(Self {
            index,
            elapsed_seconds,
            workload,
            expected,
            identity,
        })
    }

    pub fn index(&self) -> u32 {
        self.index
    }

    pub fn elapsed_seconds(&self) -> u64 {
        self.elapsed_seconds
    }

    pub fn workload(&self) -> SoakWorkload {
        self.workload
    }

    pub fn expected(&self) -> u64 {
        self.expected
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SoakWindowLoadResult {
    pub expected: u64,
    pub succeeded: u64,
    pub failed: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SoakWindowCleanup {
    pub active_connections: u64,
    pub payload_bytes: u64,
    pub pressure: String,
    pub recovery_status: u16,
}

pub trait SoakWindowLoadPort {
    fn run(
        &mut self,
        workload: SoakWorkload,
        expected: u64,
    ) -> Result<SoakWindowLoadResult, HarnessError>;
}

impl<T> SoakWindowLoadPort for &mut T
where
    T: SoakWindowLoadPort + ?Sized,
{
    fn run(
        &mut self,
        workload: SoakWorkload,
        expected: u64,
    ) -> Result<SoakWindowLoadResult, HarnessError> {
        (**self).run(workload, expected)
    }
}

pub trait SoakWindowRuntimePort {
    fn observe_cleanup(&mut self) -> Result<SoakWindowCleanup, HarnessError>;
}

impl<T> SoakWindowRuntimePort for &mut T
where
    T: SoakWindowRuntimePort + ?Sized,
{
    fn observe_cleanup(&mut self) -> Result<SoakWindowCleanup, HarnessError> {
        (**self).observe_cleanup()
    }
}

pub trait SoakWindowProcessPort {
    fn is_alive(&mut self) -> Result<bool, HarnessError>;
    fn identity_matches(&mut self) -> Result<bool, HarnessError>;
    fn sample_rss_bytes(&mut self) -> Result<u64, HarnessError>;
}

impl<T> SoakWindowProcessPort for &mut T
where
    T: SoakWindowProcessPort + ?Sized,
{
    fn is_alive(&mut self) -> Result<bool, HarnessError> {
        (**self).is_alive()
    }

    fn identity_matches(&mut self) -> Result<bool, HarnessError> {
        (**self).identity_matches()
    }

    fn sample_rss_bytes(&mut self) -> Result<u64, HarnessError> {
        (**self).sample_rss_bytes()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SoakWindowState {
    Created,
    Loading,
    Verifying,
    Completed,
    Failed,
}

pub struct SoakWindowRunner<L, R, P> {
    load: L,
    runtime: R,
    process: P,
    state: SoakWindowState,
}

impl<L, R, P> SoakWindowRunner<L, R, P>
where
    L: SoakWindowLoadPort,
    R: SoakWindowRuntimePort,
    P: SoakWindowProcessPort,
{
    pub fn new(load: L, runtime: R, process: P) -> Self {
        Self {
            load,
            runtime,
            process,
            state: SoakWindowState::Created,
        }
    }

    pub fn state(&self) -> SoakWindowState {
        self.state
    }

    pub fn run(
        &mut self,
        request: SoakWindowRequest,
    ) -> Result<DiagnosticSoakObservation, HarnessError> {
        if self.state != SoakWindowState::Created {
            return self.fail("soak window runner is not reusable");
        }
        let process_valid = match self.process_valid() {
            Ok(value) => value,
            Err(_) => return self.fail("soak window process check failed before load"),
        };
        if !process_valid {
            return self.fail("soak window process identity is invalid before load");
        }

        self.state = SoakWindowState::Loading;
        let load = match self.load.run(request.workload, request.expected) {
            Ok(value) => value,
            Err(_) => return self.fail("soak window load failed"),
        };
        if load.expected != request.expected
            || load.succeeded != request.expected
            || load.failed != 0
        {
            return self.fail("soak window load result is invalid");
        }

        self.state = SoakWindowState::Verifying;
        let cleanup = match self.runtime.observe_cleanup() {
            Ok(value) => value,
            Err(_) => return self.fail("soak window cleanup observation failed"),
        };
        if cleanup.active_connections != 0
            || cleanup.payload_bytes != 0
            || cleanup.pressure != "normal"
            || cleanup.recovery_status != 200
        {
            return self.fail("soak window cleanup is invalid");
        }
        let process_valid = match self.process_valid() {
            Ok(value) => value,
            Err(_) => return self.fail("soak window process check failed after load"),
        };
        if !process_valid {
            return self.fail("soak window process identity is invalid after load");
        }
        let rss_bytes = match self.process.sample_rss_bytes() {
            Ok(value) => value,
            Err(_) => return self.fail("soak window RSS sample failed"),
        };
        if rss_bytes == 0 {
            return self.fail("soak window RSS is invalid");
        }

        self.state = SoakWindowState::Completed;
        Ok(DiagnosticSoakObservation {
            index: request.index,
            elapsed_seconds: request.elapsed_seconds,
            workload: request.workload,
            build_identity: request.identity.build_identity,
            config_sha256: request.identity.config_sha256,
            process_start_identity: request.identity.process_start_identity,
            expected: load.expected,
            succeeded: load.succeeded,
            failed: load.failed,
            process_alive: true,
            rss_bytes,
            cleanup_connections: cleanup.active_connections,
            cleanup_payload_bytes: cleanup.payload_bytes,
            cleanup_pressure: cleanup.pressure,
            recovery_status: cleanup.recovery_status,
        })
    }

    fn fail<T>(&mut self, message: &str) -> Result<T, HarnessError> {
        self.state = SoakWindowState::Failed;
        Err(HarnessError::new(message))
    }

    fn process_valid(&mut self) -> Result<bool, HarnessError> {
        Ok(self.process.is_alive()? && self.process.identity_matches()?)
    }
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
