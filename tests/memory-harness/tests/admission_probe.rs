use std::net::SocketAddr;
use std::time::Duration;

use edge_memory_harness::admission_probe::{
    parse_admission_probe_options, AdmissionProbe, AdmissionProbeObservation, AdmissionProbeSpec,
    AdmissionProbeState,
};

#[test]
fn terminal_close_is_classified_as_connection_rejection() {
    let mut probe = probe();

    probe.begin().unwrap();
    probe.connected().unwrap();
    probe
        .observe(AdmissionProbeObservation::TerminalClosed)
        .unwrap();

    assert_eq!(probe.state(), AdmissionProbeState::Rejected);
}

#[test]
fn open_timeout_response_bytes_and_io_failure_are_not_rejections() {
    for observation in [
        AdmissionProbeObservation::TimedOutOpen,
        AdmissionProbeObservation::ApplicationBytes,
    ] {
        let mut probe = probe();
        probe.begin().unwrap();
        probe.connected().unwrap();
        assert!(probe.observe(observation).is_err());
        assert_eq!(probe.state(), AdmissionProbeState::UnexpectedlyOpen);
    }

    let mut probe = probe();
    probe.begin().unwrap();
    probe.connected().unwrap();
    assert!(probe.observe(AdmissionProbeObservation::IoFailure).is_err());
    assert_eq!(probe.state(), AdmissionProbeState::Failed);
}

#[test]
fn duplicate_transition_and_invalid_cli_fail_closed() {
    let mut probe = probe();
    probe.begin().unwrap();
    assert!(probe.begin().is_err());
    assert_eq!(probe.state(), AdmissionProbeState::Failed);

    let valid = vec![
        "--address".to_string(),
        "127.0.0.1:8080".to_string(),
        "--connect-timeout-ms".to_string(),
        "5000".to_string(),
        "--terminal-timeout-ms".to_string(),
        "500".to_string(),
    ];
    assert_eq!(
        parse_admission_probe_options(&valid)
            .unwrap()
            .terminal_timeout_ms,
        500
    );

    let mut duplicate = valid.clone();
    duplicate.extend(["--terminal-timeout-ms".to_string(), "1".to_string()]);
    assert!(parse_admission_probe_options(&duplicate).is_err());

    let mut unknown = valid.clone();
    unknown.extend(["--unknown".to_string(), "x".to_string()]);
    assert!(parse_admission_probe_options(&unknown).is_err());

    let mut zero = valid;
    zero[5] = "0".to_string();
    assert!(parse_admission_probe_options(&zero).is_err());
}

fn probe() -> AdmissionProbe {
    AdmissionProbe::new(
        AdmissionProbeSpec::new(
            "127.0.0.1:8080".parse::<SocketAddr>().unwrap(),
            Duration::from_secs(5),
            Duration::from_millis(500),
        )
        .unwrap(),
    )
}
