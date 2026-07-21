use edge_memory_harness::diagnostic_soak::SoakWorkload;
use edge_memory_harness::soak_window::{
    SoakWindowCleanup, SoakWindowIdentity, SoakWindowLoadPort, SoakWindowLoadResult,
    SoakWindowProcessPort, SoakWindowRequest, SoakWindowRunner, SoakWindowRuntimePort,
    SoakWindowState,
};
use edge_memory_harness::HarnessError;

const BUILD: &str =
    "source-tree-sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const CONFIG: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const PROCESS: &str = "macos-lstart:window-process";

#[test]
fn baseline_churn_and_websocket_windows_produce_exact_observations() {
    for (index, workload, expected) in [
        (0, SoakWorkload::Baseline, 0),
        (1, SoakWorkload::Churn, 1_000),
        (2, SoakWorkload::Websocket, 128),
    ] {
        let mut runner = clean_runner(expected);
        let observation = runner.run(request(index)).unwrap();
        assert_eq!(observation.index, index);
        assert_eq!(observation.elapsed_seconds, u64::from(index) * 60);
        assert_eq!(observation.workload, workload);
        assert_eq!(observation.expected, expected);
        assert_eq!(observation.succeeded, expected);
        assert_eq!(observation.failed, 0);
        assert_eq!(observation.rss_bytes, 12_345_678);
        assert_eq!(runner.state(), SoakWindowState::Completed);
    }
}

#[test]
fn invalid_index_elapsed_and_second_run_fail_closed() {
    assert!(SoakWindowRequest::new(121, 7_260, identity()).is_err());
    assert!(SoakWindowRequest::new(2, 119, identity()).is_err());

    let mut runner = clean_runner(1_000);
    runner.run(request(1)).unwrap();
    assert!(runner.run(request(1)).is_err());
    assert_eq!(runner.state(), SoakWindowState::Failed);
}

#[test]
fn load_failure_or_count_mismatch_fails_before_observation() {
    let mut failed = SoakWindowRunner::new(
        FakeLoad::failure(),
        FakeRuntime::clean(),
        FakeProcess::clean(),
    );
    assert!(failed.run(request(1)).is_err());
    assert_eq!(failed.state(), SoakWindowState::Failed);

    let mut mismatch = clean_runner(999);
    assert!(mismatch.run(request(1)).is_err());
    assert_eq!(mismatch.state(), SoakWindowState::Failed);
}

#[test]
fn stale_dead_or_zero_rss_process_and_dirty_cleanup_fail_closed() {
    let mut stale = SoakWindowRunner::new(
        FakeLoad::success(1_000),
        FakeRuntime::clean(),
        FakeProcess {
            alive: true,
            identity_matches: false,
            rss_bytes: 12_345_678,
        },
    );
    assert!(stale.run(request(1)).is_err());

    let mut dead = SoakWindowRunner::new(
        FakeLoad::success(1_000),
        FakeRuntime::clean(),
        FakeProcess {
            alive: false,
            identity_matches: true,
            rss_bytes: 12_345_678,
        },
    );
    assert!(dead.run(request(1)).is_err());

    let mut zero_rss = SoakWindowRunner::new(
        FakeLoad::success(1_000),
        FakeRuntime::clean(),
        FakeProcess {
            alive: true,
            identity_matches: true,
            rss_bytes: 0,
        },
    );
    assert!(zero_rss.run(request(1)).is_err());

    let mut dirty = SoakWindowRunner::new(
        FakeLoad::success(1_000),
        FakeRuntime {
            cleanup: SoakWindowCleanup {
                active_connections: 1,
                payload_bytes: 0,
                pressure: "normal".to_string(),
                recovery_status: 200,
            },
        },
        FakeProcess::clean(),
    );
    assert!(dirty.run(request(1)).is_err());
}

fn request(index: u32) -> SoakWindowRequest {
    SoakWindowRequest::new(index, u64::from(index) * 60, identity()).unwrap()
}

fn identity() -> SoakWindowIdentity {
    SoakWindowIdentity::new(BUILD, CONFIG, PROCESS).unwrap()
}

fn clean_runner(succeeded: u64) -> SoakWindowRunner<FakeLoad, FakeRuntime, FakeProcess> {
    SoakWindowRunner::new(
        FakeLoad::success(succeeded),
        FakeRuntime::clean(),
        FakeProcess::clean(),
    )
}

struct FakeLoad {
    result: Result<SoakWindowLoadResult, HarnessError>,
}

impl FakeLoad {
    fn success(succeeded: u64) -> Self {
        Self {
            result: Ok(SoakWindowLoadResult {
                expected: succeeded,
                succeeded,
                failed: 0,
            }),
        }
    }

    fn failure() -> Self {
        Self {
            result: Err(HarnessError::new("fake load failure")),
        }
    }
}

impl SoakWindowLoadPort for FakeLoad {
    fn run(
        &mut self,
        _workload: SoakWorkload,
        _expected: u64,
    ) -> Result<SoakWindowLoadResult, HarnessError> {
        self.result.clone()
    }
}

struct FakeRuntime {
    cleanup: SoakWindowCleanup,
}

impl FakeRuntime {
    fn clean() -> Self {
        Self {
            cleanup: SoakWindowCleanup {
                active_connections: 0,
                payload_bytes: 0,
                pressure: "normal".to_string(),
                recovery_status: 200,
            },
        }
    }
}

impl SoakWindowRuntimePort for FakeRuntime {
    fn observe_cleanup(&mut self) -> Result<SoakWindowCleanup, HarnessError> {
        Ok(self.cleanup.clone())
    }
}

struct FakeProcess {
    alive: bool,
    identity_matches: bool,
    rss_bytes: u64,
}

impl FakeProcess {
    fn clean() -> Self {
        Self {
            alive: true,
            identity_matches: true,
            rss_bytes: 12_345_678,
        }
    }
}

impl SoakWindowProcessPort for FakeProcess {
    fn is_alive(&mut self) -> Result<bool, HarnessError> {
        Ok(self.alive)
    }

    fn identity_matches(&mut self) -> Result<bool, HarnessError> {
        Ok(self.identity_matches)
    }

    fn sample_rss_bytes(&mut self) -> Result<u64, HarnessError> {
        Ok(self.rss_bytes)
    }
}
