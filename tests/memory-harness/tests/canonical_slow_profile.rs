use edge_memory_harness::canonical_slow_profile::{
    CanonicalSlowRequestProfile, CANONICAL_SLOW_BODY_CONNECTIONS, CANONICAL_SLOW_HEADER_CONNECTIONS,
};

#[test]
fn canonical_slow_request_profile_fixes_counts_body_relation_and_ceilings() {
    let profile = CanonicalSlowRequestProfile::phase011().unwrap();

    assert_eq!(profile.profile_id, "phase011-slow-request-capacity-v1");
    assert_eq!(profile.scenario_version, "phase011-v1");
    assert_eq!(profile.slow_header_connections, 256);
    assert_eq!(
        profile.slow_header_connections,
        CANONICAL_SLOW_HEADER_CONNECTIONS
    );
    assert_eq!(profile.slow_body_connections, 128);
    assert_eq!(
        profile.slow_body_connections,
        CANONICAL_SLOW_BODY_CONNECTIONS
    );
    assert_eq!(profile.declared_body_bytes, 65_536);
    assert_eq!(profile.sent_body_bytes, 32_768);
    assert_eq!(profile.slow_header_rss_ceiling_bytes, 402_653_184);
    assert_eq!(profile.slow_body_rss_ceiling_bytes, 536_870_912);
    assert_eq!(
        profile.minimum_slow_body_payload_bytes().unwrap(),
        4_194_304
    );
}

#[test]
fn canonical_slow_request_profile_rejects_changed_or_invalid_contracts() {
    let canonical = CanonicalSlowRequestProfile::phase011().unwrap();
    assert!(canonical.validate().is_ok());

    let mut changed_header = canonical.clone();
    changed_header.slow_header_connections = 64;
    assert!(changed_header.validate().is_err());

    let mut changed_body = canonical.clone();
    changed_body.slow_body_connections = 32;
    assert!(changed_body.validate().is_err());

    let mut invalid_relation = canonical.clone();
    invalid_relation.sent_body_bytes = invalid_relation.declared_body_bytes;
    assert!(invalid_relation.validate().is_err());

    let mut changed_ceiling = canonical;
    changed_ceiling.slow_body_rss_ceiling_bytes += 1;
    assert!(changed_ceiling.validate().is_err());
}
