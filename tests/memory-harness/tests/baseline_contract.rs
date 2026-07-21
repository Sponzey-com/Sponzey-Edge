use edge_memory_harness::{
    parse_macos_ps_rss_bytes, BaselineEvent, BaselineLifecycle, BaselineProfile, BaselineReport,
    BaselineState, MemorySample,
};

#[test]
fn parses_macos_ps_rss_kib_as_checked_bytes() {
    assert_eq!(parse_macos_ps_rss_bytes("  12345\n").unwrap(), 12_641_280);
    assert!(parse_macos_ps_rss_bytes("").is_err());
    assert!(parse_macos_ps_rss_bytes("12 13").is_err());
    assert!(parse_macos_ps_rss_bytes("0").is_err());
    assert!(parse_macos_ps_rss_bytes("18446744073709551615").is_err());
}

#[test]
fn mini_baseline_lifecycle_rejects_out_of_order_events() {
    let mut lifecycle = BaselineLifecycle::new();
    assert_eq!(lifecycle.state(), BaselineState::Created);
    assert!(lifecycle
        .transition(BaselineEvent::SampleCollected)
        .is_err());

    lifecycle
        .transition(BaselineEvent::PreflightPassed)
        .unwrap();
    lifecycle.transition(BaselineEvent::ChildReady).unwrap();
    lifecycle
        .transition(BaselineEvent::SampleCollected)
        .unwrap();
    lifecycle.transition(BaselineEvent::ReportWritten).unwrap();
    assert_eq!(lifecycle.state(), BaselineState::Reported);
}

#[test]
fn canonical_report_requires_samples_and_contains_no_local_process_details() {
    let profile = BaselineProfile {
        scenario: "idle".to_string(),
        platform: "macos".to_string(),
        architecture: "arm64".to_string(),
        build_identity: "source-tree-sha256:test".to_string(),
        process_start_identity: "Thu Jul 16 10:00:00 2026".to_string(),
    };
    assert!(BaselineReport::new(profile.clone(), 0, Vec::new()).is_err());

    let report = BaselineReport::new(
        profile,
        100,
        vec![
            MemorySample {
                elapsed_ms: 0,
                rss_bytes: 20 * 1024 * 1024,
            },
            MemorySample {
                elapsed_ms: 1_000,
                rss_bytes: 24 * 1024 * 1024,
            },
        ],
    )
    .unwrap();
    assert_eq!(report.baseline_rss_bytes, 20 * 1024 * 1024);
    assert_eq!(report.peak_rss_bytes, 24 * 1024 * 1024);

    let json = report.to_canonical_json().unwrap();
    assert!(json.contains("\"schema_version\": 1"));
    assert!(!json.contains("\"pid\""));
    assert!(!json.contains("config_file"));
    assert!(!json.contains("private_key"));
}
