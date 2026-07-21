use crate::scenario::ScenarioFailure;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChildProcess {
    pub pid: u32,
    pub start_identity: String,
}

impl ChildProcess {
    pub fn new(pid: u32, start_identity: impl Into<String>) -> Self {
        Self {
            pid,
            start_identity: start_identity.into(),
        }
    }
}

pub trait ProcessSupervisor {
    fn start(&mut self) -> Result<ChildProcess, ScenarioFailure>;
    fn identity(&mut self, child: &ChildProcess) -> Result<String, ScenarioFailure>;
    fn is_alive(&mut self, child: &ChildProcess) -> Result<bool, ScenarioFailure>;
    fn stop(&mut self, child: &ChildProcess) -> Result<(), ScenarioFailure>;
}

pub trait RssSampler {
    fn sample_rss_bytes(&mut self, child: &ChildProcess) -> Result<u64, ScenarioFailure>;
}

pub trait LoadDriver {
    fn warm(&mut self, child: &ChildProcess) -> Result<(), ScenarioFailure>;
    fn load(&mut self, child: &ChildProcess) -> Result<(), ScenarioFailure>;
    fn cool(&mut self, child: &ChildProcess) -> Result<(), ScenarioFailure>;
}

pub trait MonotonicClock {
    fn now_ms(&mut self) -> u64;
}
