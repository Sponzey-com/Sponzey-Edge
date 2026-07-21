use edge_memory_harness::control_max::{
    build_metric_max_fixture, load_audit_fixture, prepare_audit_fixture, ControlMaxEvent,
    ControlMaxLifecycle, ControlMaxState, FixtureManifest, PRODUCTION_AUDIT_RECORDS,
};
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn lifecycle_requires_verified_maxima_and_three_queries() {
    let mut lifecycle = ControlMaxLifecycle::new();

    assert_eq!(lifecycle.state(), ControlMaxState::Created);
    lifecycle.advance(ControlMaxEvent::PrepareAudit).unwrap();
    lifecycle.advance(ControlMaxEvent::AuditPrepared).unwrap();
    lifecycle.advance(ControlMaxEvent::AuditLoaded).unwrap();
    lifecycle.advance(ControlMaxEvent::MetricsLoaded).unwrap();
    assert_eq!(lifecycle.state(), ControlMaxState::Ready);

    for cycle in 1..=3 {
        lifecycle
            .advance(ControlMaxEvent::QueryCompleted(cycle))
            .unwrap();
    }
    lifecycle.advance(ControlMaxEvent::Finish).unwrap();

    assert_eq!(lifecycle.state(), ControlMaxState::Completed);
    assert!(lifecycle.advance(ControlMaxEvent::Finish).is_err());
}

#[test]
fn lifecycle_fails_closed_on_invalid_order_or_failed_verification() {
    let mut invalid = ControlMaxLifecycle::new();
    assert!(invalid.advance(ControlMaxEvent::AuditLoaded).is_err());
    assert_eq!(invalid.state(), ControlMaxState::Failed);

    let mut failed = ControlMaxLifecycle::new();
    failed.advance(ControlMaxEvent::PrepareAudit).unwrap();
    failed.advance(ControlMaxEvent::Fail).unwrap();
    assert_eq!(failed.state(), ControlMaxState::Failed);
    assert!(failed.advance(ControlMaxEvent::AuditPrepared).is_err());
}

#[test]
fn manifest_requires_exact_counts_and_sha256_identity() {
    let valid = FixtureManifest::new(
        PRODUCTION_AUDIT_RECORDS,
        2_048,
        "response_budget",
        "a".repeat(64),
    )
    .unwrap();
    assert_eq!(valid.audit_records, 100_000);

    assert!(FixtureManifest::new(99_999, 2_048, "response_budget", "a".repeat(64)).is_err());
    assert!(FixtureManifest::new(100_000, 0, "response_budget", "a".repeat(64)).is_err());
    assert!(FixtureManifest::new(100_000, 2_048, "unknown", "a".repeat(64)).is_err());
    assert!(FixtureManifest::new(100_000, 2_048, "response_budget", "not-a-digest").is_err());
}

#[test]
fn production_metric_fixture_reaches_both_cardinality_limits() {
    let fixture = build_metric_max_fixture().unwrap();

    assert_eq!(fixture.series_count(), 16_384);
    assert_eq!(fixture.cumulative_series_count(), 12_288);
    assert_eq!(fixture.rejection_reason(), "series_limit");
    let summary = fixture.query_admin_summary().unwrap();
    assert_eq!(summary.status_code, 200);
    let body: serde_json::Value = serde_json::from_str(&summary.body).unwrap();
    assert!(body["counters"].as_array().unwrap().len() <= 500);
    assert!(body["gauges"].as_array().unwrap().len() <= 500);
    assert!(body["histograms"].as_array().unwrap().len() <= 500);
}

#[test]
fn audit_fixture_reopens_verifies_and_uses_bounded_admin_query() {
    let root = temporary_root("small-audit");
    let prepared = prepare_audit_fixture(&root, 3).unwrap();
    assert_eq!(prepared.records, 3);

    let mut fixture = load_audit_fixture(&root, 3).unwrap();
    assert_eq!(fixture.verified_records(), 3);
    let response = fixture.query_admin_page().unwrap();
    assert_eq!(response.status_code, 200);
    let body: serde_json::Value = serde_json::from_str(&response.body).unwrap();
    assert_eq!(body["records"].as_array().unwrap().len(), 3);
    fs::remove_dir_all(root).unwrap();
}

fn temporary_root(name: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("sponzey-control-max-{name}-{nonce}"))
}
