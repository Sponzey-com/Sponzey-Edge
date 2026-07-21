#[test]
fn workspace_crates_expose_foundation_smoke_names() {
    assert_eq!(edge_domain::crate_name(), "edge-domain");
    assert_eq!(edge_ports::crate_name(), "edge-ports");
    assert_eq!(edge_application::crate_name(), "edge-application");
    assert_eq!(edge_adapters::crate_name(), "edge-adapters");
    assert_eq!(edge_core::crate_name(), "edge-core");
    assert_eq!(edge_admin_api::crate_name(), "edge-admin-api");
}
