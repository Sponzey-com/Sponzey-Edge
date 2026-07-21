#[cfg(target_os = "linux")]
use std::fs;
use std::process::{Child, Command};
use std::time::Instant;

#[cfg(target_os = "macos")]
use crate::parse_macos_ps_rss_bytes;
use crate::ports::{ChildProcess, MonotonicClock, ProcessSupervisor, RssSampler};
use crate::scenario::ScenarioFailure;
use crate::HarnessError;

pub fn parse_linux_proc_status_rss_bytes(output: &str) -> Result<u64, HarnessError> {
    let values = output
        .lines()
        .filter_map(|line| line.strip_prefix("VmRSS:"))
        .collect::<Vec<_>>();
    if values.len() != 1 {
        return Err(HarnessError::new(
            "Linux process status must contain exactly one VmRSS",
        ));
    }
    let fields = values[0].split_whitespace().collect::<Vec<_>>();
    if fields.len() != 2 || fields[1] != "kB" {
        return Err(HarnessError::new(
            "Linux VmRSS must be a single value in kB",
        ));
    }
    let kib = fields[0]
        .parse::<u64>()
        .map_err(|_| HarnessError::new("Linux VmRSS value is invalid"))?;
    if kib == 0 {
        return Err(HarnessError::new("Linux VmRSS must be positive"));
    }
    kib.checked_mul(1024)
        .ok_or_else(|| HarnessError::new("Linux VmRSS value overflows bytes"))
}

pub fn parse_linux_proc_stat_start_identity(output: &str) -> Result<String, HarnessError> {
    let command_end = output
        .rfind(')')
        .ok_or_else(|| HarnessError::new("Linux process stat command is malformed"))?;
    let tail = output
        .get(command_end + 1..)
        .ok_or_else(|| HarnessError::new("Linux process stat tail is missing"))?;
    let start_ticks = tail
        .split_whitespace()
        .nth(19)
        .ok_or_else(|| HarnessError::new("Linux process stat start time is missing"))?;
    let start_ticks = start_ticks
        .parse::<u64>()
        .map_err(|_| HarnessError::new("Linux process start time is invalid"))?;
    if start_ticks == 0 {
        return Err(HarnessError::new(
            "Linux process start time must be positive",
        ));
    }
    Ok(format!("linux-start-ticks:{start_ticks}"))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChildCommandSpec {
    program: String,
    args: Vec<String>,
}

impl ChildCommandSpec {
    pub fn new<I, S>(program: impl Into<String>, args: I) -> Result<Self, HarnessError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let program = program.into();
        if program.is_empty() {
            return Err(HarnessError::new("child command program must not be empty"));
        }
        Ok(Self {
            program,
            args: args.into_iter().map(Into::into).collect(),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChildLifecycleState {
    NotStarted,
    Running,
    Stopped,
}

pub struct SystemProcessSupervisor {
    spec: ChildCommandSpec,
    state: ChildLifecycleState,
    child: Option<Child>,
}

impl SystemProcessSupervisor {
    pub fn new(spec: ChildCommandSpec) -> Self {
        Self {
            spec,
            state: ChildLifecycleState::NotStarted,
            child: None,
        }
    }

    pub fn state(&self) -> ChildLifecycleState {
        self.state
    }

    fn matches_running_child(&self, child: &ChildProcess) -> bool {
        self.state == ChildLifecycleState::Running
            && self
                .child
                .as_ref()
                .is_some_and(|running| running.id() == child.pid)
    }
}

impl ProcessSupervisor for SystemProcessSupervisor {
    fn start(&mut self) -> Result<ChildProcess, ScenarioFailure> {
        if self.state != ChildLifecycleState::NotStarted {
            return Err(ScenarioFailure::ProcessStartFailed);
        }
        let mut child = Command::new(&self.spec.program)
            .args(&self.spec.args)
            .spawn()
            .map_err(|_| ScenarioFailure::ProcessStartFailed)?;
        let pid = child.id();
        let start_identity = match read_process_identity(pid) {
            Ok(identity) => identity,
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(error);
            }
        };
        self.child = Some(child);
        self.state = ChildLifecycleState::Running;
        Ok(ChildProcess::new(pid, start_identity))
    }

    fn identity(&mut self, child: &ChildProcess) -> Result<String, ScenarioFailure> {
        if !self.matches_running_child(child) {
            return Err(ScenarioFailure::ProcessExitedEarly);
        }
        read_process_identity(child.pid)
    }

    fn is_alive(&mut self, child: &ChildProcess) -> Result<bool, ScenarioFailure> {
        if !self.matches_running_child(child) {
            return Err(ScenarioFailure::ProcessExitedEarly);
        }
        let running = self
            .child
            .as_mut()
            .ok_or(ScenarioFailure::ProcessExitedEarly)?;
        match running
            .try_wait()
            .map_err(|_| ScenarioFailure::ProcessExitedEarly)?
        {
            None => Ok(true),
            Some(_) => {
                self.state = ChildLifecycleState::Stopped;
                Ok(false)
            }
        }
    }

    fn stop(&mut self, child: &ChildProcess) -> Result<(), ScenarioFailure> {
        if !self.matches_running_child(child) {
            return Err(ScenarioFailure::CleanupFailed);
        }
        let mut running = self.child.take().ok_or(ScenarioFailure::CleanupFailed)?;
        if running
            .try_wait()
            .map_err(|_| ScenarioFailure::CleanupFailed)?
            .is_none()
        {
            running
                .kill()
                .and_then(|_| running.wait())
                .map_err(|_| ScenarioFailure::CleanupFailed)?;
        }
        self.state = ChildLifecycleState::Stopped;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct PlatformRssSampler;

impl RssSampler for PlatformRssSampler {
    fn sample_rss_bytes(&mut self, child: &ChildProcess) -> Result<u64, ScenarioFailure> {
        read_process_rss_bytes(child.pid)
    }
}

pub fn attach_process(pid: u32) -> Result<ChildProcess, ScenarioFailure> {
    Ok(ChildProcess::new(pid, read_process_identity(pid)?))
}

pub fn attached_process_is_alive(child: &ChildProcess) -> Result<bool, ScenarioFailure> {
    match read_process_identity(child.pid) {
        Ok(identity) => Ok(identity == child.start_identity),
        Err(ScenarioFailure::ProcessExitedEarly) => Ok(false),
        Err(error) => Err(error),
    }
}

pub fn attached_process_identity_matches(child: &ChildProcess) -> Result<bool, ScenarioFailure> {
    Ok(read_process_identity(child.pid)? == child.start_identity)
}

pub struct SystemMonotonicClock {
    started_at: Instant,
}

impl SystemMonotonicClock {
    pub fn new() -> Self {
        Self {
            started_at: Instant::now(),
        }
    }
}

impl Default for SystemMonotonicClock {
    fn default() -> Self {
        Self::new()
    }
}

impl MonotonicClock for SystemMonotonicClock {
    fn now_ms(&mut self) -> u64 {
        self.started_at
            .elapsed()
            .as_millis()
            .try_into()
            .unwrap_or(u64::MAX)
    }
}

fn read_process_rss_bytes(pid: u32) -> Result<u64, ScenarioFailure> {
    #[cfg(target_os = "macos")]
    {
        let output = process_field(pid, "rss=")?;
        let bytes =
            parse_macos_ps_rss_bytes(&output).map_err(|_| ScenarioFailure::SamplerFailed)?;
        if bytes == 0 {
            return Err(ScenarioFailure::SamplerFailed);
        }
        Ok(bytes)
    }
    #[cfg(target_os = "linux")]
    {
        let output = fs::read_to_string(format!("/proc/{pid}/status"))
            .map_err(|_| ScenarioFailure::SamplerFailed)?;
        parse_linux_proc_status_rss_bytes(&output).map_err(|_| ScenarioFailure::SamplerFailed)
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = pid;
        Err(ScenarioFailure::UnsupportedPlatform)
    }
}

fn read_process_identity(pid: u32) -> Result<String, ScenarioFailure> {
    #[cfg(target_os = "macos")]
    {
        let identity = process_field(pid, "lstart=")?;
        if identity.is_empty() {
            return Err(ScenarioFailure::ProcessExitedEarly);
        }
        Ok(format!("macos-lstart:{identity}"))
    }
    #[cfg(target_os = "linux")]
    {
        let output = fs::read_to_string(format!("/proc/{pid}/stat"))
            .map_err(|_| ScenarioFailure::ProcessExitedEarly)?;
        parse_linux_proc_stat_start_identity(&output)
            .map_err(|_| ScenarioFailure::ProcessExitedEarly)
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = pid;
        Err(ScenarioFailure::UnsupportedPlatform)
    }
}

#[cfg(target_os = "macos")]
fn process_field(pid: u32, field: &str) -> Result<String, ScenarioFailure> {
    let output = Command::new("ps")
        .args(["-o", field, "-p", &pid.to_string()])
        .output()
        .map_err(|_| ScenarioFailure::SamplerFailed)?;
    if !output.status.success() {
        return Err(ScenarioFailure::ProcessExitedEarly);
    }
    let value = String::from_utf8(output.stdout).map_err(|_| ScenarioFailure::SamplerFailed)?;
    let value = value.trim().to_string();
    if value.is_empty() {
        return Err(ScenarioFailure::ProcessExitedEarly);
    }
    Ok(value)
}
