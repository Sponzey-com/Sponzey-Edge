use edge_memory_harness::ports::{MonotonicClock, ProcessSupervisor, RssSampler};
use edge_memory_harness::scenario::ScenarioFailure;
use edge_memory_harness::system_adapters::{
    parse_linux_proc_stat_start_identity, parse_linux_proc_status_rss_bytes, ChildCommandSpec,
    ChildLifecycleState, PlatformRssSampler, SystemMonotonicClock, SystemProcessSupervisor,
};

#[test]
fn linux_proc_fixtures_parse_checked_rss_and_start_identity() {
    let status = "Name:\tedge-proxy\nVmSize:\t999 kB\nVmRSS:\t12345 kB\nThreads:\t1\n";
    assert_eq!(
        parse_linux_proc_status_rss_bytes(status).unwrap(),
        12_641_280
    );
    assert!(parse_linux_proc_status_rss_bytes("Name:\tx\n").is_err());
    assert!(parse_linux_proc_status_rss_bytes("VmRSS:\t0 kB\n").is_err());
    assert!(parse_linux_proc_status_rss_bytes("VmRSS:\t1 MB\n").is_err());
    assert!(parse_linux_proc_status_rss_bytes("VmRSS:\t1 kB\nVmRSS:\t2 kB\n").is_err());
    assert!(parse_linux_proc_status_rss_bytes("VmRSS:\t18446744073709551615 kB\n").is_err());

    let stat = "42 (edge proxy worker) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 987654 20";
    assert_eq!(
        parse_linux_proc_stat_start_identity(stat).unwrap(),
        "linux-start-ticks:987654"
    );
    assert!(parse_linux_proc_stat_start_identity("42 malformed").is_err());
}

#[test]
fn child_command_spec_and_supervisor_state_reject_invalid_reuse() {
    assert!(ChildCommandSpec::new("", Vec::<String>::new()).is_err());
    let spec = ChildCommandSpec::new("sleep", ["5"]).unwrap();
    let mut supervisor = SystemProcessSupervisor::new(spec);
    assert_eq!(supervisor.state(), ChildLifecycleState::NotStarted);

    let child = supervisor.start().unwrap();
    assert_eq!(supervisor.state(), ChildLifecycleState::Running);
    assert_eq!(supervisor.identity(&child).unwrap(), child.start_identity);
    assert!(supervisor.is_alive(&child).unwrap());
    assert_eq!(supervisor.start(), Err(ScenarioFailure::ProcessStartFailed));
    supervisor.stop(&child).unwrap();
    assert_eq!(supervisor.state(), ChildLifecycleState::Stopped);
    assert_eq!(supervisor.stop(&child), Err(ScenarioFailure::CleanupFailed));
}

#[test]
fn current_platform_child_rss_identity_and_clock_smoke() {
    let spec = ChildCommandSpec::new("sleep", ["5"]).unwrap();
    let mut supervisor = SystemProcessSupervisor::new(spec);
    let child = supervisor.start().unwrap();
    let mut sampler = PlatformRssSampler;
    let mut clock = SystemMonotonicClock::new();

    let before = clock.now_ms();
    let rss = sampler.sample_rss_bytes(&child).unwrap();
    let after = clock.now_ms();

    assert!(rss > 0);
    assert!(after >= before);
    assert_eq!(supervisor.identity(&child).unwrap(), child.start_identity);
    assert!(supervisor.is_alive(&child).unwrap());
    supervisor.stop(&child).unwrap();
    assert_eq!(supervisor.state(), ChildLifecycleState::Stopped);
}
