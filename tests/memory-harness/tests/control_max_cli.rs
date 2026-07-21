use edge_memory_harness::control_max::{parse_control_max_command, ControlMaxCommand};

#[test]
fn parses_strict_prepare_and_hold_commands() {
    let prepare = parse_control_max_command(&strings(&[
        "prepare",
        "--data-dir",
        "/tmp/data",
        "--manifest-output",
        "/tmp/manifest.json",
    ]))
    .unwrap();
    assert!(matches!(prepare, ControlMaxCommand::Prepare(_)));

    let hold = parse_control_max_command(&strings(&[
        "hold",
        "--data-dir",
        "/tmp/data",
        "--manifest",
        "/tmp/manifest.json",
        "--ready-output",
        "/tmp/ready",
        "--stop-file",
        "/tmp/stop",
        "--summary-output",
        "/tmp/summary.json",
        "--timeout-ms",
        "60000",
    ]))
    .unwrap();
    assert!(matches!(hold, ControlMaxCommand::Hold(_)));
}

#[test]
fn rejects_unknown_duplicate_missing_and_zero_options() {
    for args in [
        strings(&["unknown"]),
        strings(&["prepare", "--data-dir", "/tmp/data"]),
        strings(&[
            "prepare",
            "--data-dir",
            "/tmp/data",
            "--data-dir",
            "/tmp/again",
            "--manifest-output",
            "/tmp/manifest",
        ]),
        strings(&[
            "hold",
            "--data-dir",
            "/tmp/data",
            "--manifest",
            "/tmp/manifest",
            "--ready-output",
            "/tmp/ready",
            "--stop-file",
            "/tmp/stop",
            "--summary-output",
            "/tmp/summary",
            "--timeout-ms",
            "0",
        ]),
    ] {
        assert!(parse_control_max_command(&args).is_err());
    }
}

fn strings(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_string()).collect()
}
