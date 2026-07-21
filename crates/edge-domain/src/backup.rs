mod model;
pub use model::*;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ErrorCode;

    fn descriptor(
        kind: BackupArtifactKind,
        id: &str,
        path: &str,
        length: u64,
        mode: BackupArtifactMode,
    ) -> BackupArtifactDescriptor {
        BackupArtifactDescriptor {
            kind,
            logical_id: id.to_string(),
            relative_logical_path: path.to_string(),
            length_bytes: length,
            sha256: [7; 32],
            mode,
            required_for_restore: true,
        }
    }

    fn valid_manifest() -> BackupManifest {
        let artifacts = vec![
            descriptor(
                BackupArtifactKind::ConfigRevisionPointer,
                "current",
                "config/current",
                5,
                BackupArtifactMode::Public,
            ),
            descriptor(
                BackupArtifactKind::ConfigRevision,
                "rev-1",
                "config/revisions/rev-1",
                100,
                BackupArtifactMode::Public,
            ),
        ];
        BackupManifest {
            schema_version: 1,
            archive_id: "archive-1".to_string(),
            created_at_epoch_seconds: 1_700_000_000,
            source_app_version: "0.1.0".to_string(),
            source_layout_version: 1,
            current_revision_id: "rev-1".to_string(),
            admin_initialized: false,
            referenced_certificate_refs: Vec::new(),
            referenced_trust_bundle_refs: Vec::new(),
            artifact_count: artifacts.len() as u32,
            total_plaintext_bytes: artifacts.iter().map(|item| item.length_bytes).sum(),
            artifacts,
            manifest_digest: [9; 32],
        }
    }

    #[test]
    fn manifest_v1_accepts_minimal_recoverable_inventory_at_limits() {
        let manifest = valid_manifest();
        manifest.validate(&BackupLimits::schema_v1()).unwrap();
        let mut boundary = valid_manifest();
        boundary.artifacts[1].length_bytes = BackupLimits::schema_v1().max_config_or_secret_bytes;
        boundary.total_plaintext_bytes = boundary
            .artifacts
            .iter()
            .map(|item| item.length_bytes)
            .sum();
        boundary.validate(&BackupLimits::schema_v1()).unwrap();
    }

    #[test]
    fn manifest_rejects_unsafe_duplicate_and_mode_mismatch_without_mutation() {
        for path in [
            "/absolute",
            "config/../secret",
            "config//current",
            "config\\current",
        ] {
            let mut manifest = valid_manifest();
            manifest.artifacts[0].relative_logical_path = path.to_string();
            let original = manifest.clone();
            assert_eq!(
                manifest
                    .validate(&BackupLimits::schema_v1())
                    .unwrap_err()
                    .code,
                ErrorCode::BackupManifestInvalid
            );
            assert_eq!(manifest, original);
        }
        let mut duplicate = valid_manifest();
        duplicate.artifacts[1].relative_logical_path = "config/current".to_string();
        assert_eq!(
            duplicate
                .validate(&BackupLimits::schema_v1())
                .unwrap_err()
                .code,
            ErrorCode::BackupManifestInvalid
        );

        let mut private_key = valid_manifest();
        private_key.artifacts.push(descriptor(
            BackupArtifactKind::CertificatePrivateKey,
            "cert-1",
            "certificates/cert-1/private-key",
            100,
            BackupArtifactMode::Public,
        ));
        private_key.artifact_count += 1;
        private_key.total_plaintext_bytes += 100;
        assert_eq!(
            private_key
                .validate(&BackupLimits::schema_v1())
                .unwrap_err()
                .code,
            ErrorCode::BackupManifestInvalid
        );
    }

    #[test]
    fn manifest_rejects_limit_plus_one_and_checked_sum_overflow() {
        let limits = BackupLimits::schema_v1();
        let mut oversized = valid_manifest();
        oversized.artifacts[1].length_bytes = limits.max_config_or_secret_bytes + 1;
        oversized.total_plaintext_bytes = oversized.artifacts[1].length_bytes + 5;
        assert_eq!(
            oversized.validate(&limits).unwrap_err().code,
            ErrorCode::BackupLimitExceeded
        );
        let mut overflow = valid_manifest();
        overflow.artifacts[0].length_bytes = u64::MAX;
        overflow.artifacts[1].length_bytes = 1;
        overflow.total_plaintext_bytes = 0;
        assert_eq!(
            overflow.validate(&limits).unwrap_err().code,
            ErrorCode::BackupLimitExceeded
        );

        let mut count_limited = limits;
        count_limited.max_artifacts = 1;
        assert_eq!(
            valid_manifest().validate(&count_limited).unwrap_err().code,
            ErrorCode::BackupLimitExceeded
        );

        validate_manifest_encoded_size(limits.max_manifest_bytes, &limits).unwrap();
        assert_eq!(
            validate_manifest_encoded_size(limits.max_manifest_bytes + 1, &limits)
                .unwrap_err()
                .code,
            ErrorCode::BackupLimitExceeded
        );

        let prefix = "config/revisions/";
        let boundary_id = "r".repeat(limits.max_logical_path_bytes - prefix.len());
        let mut path_boundary = valid_manifest();
        path_boundary.current_revision_id = boundary_id.clone();
        path_boundary.artifacts[1].logical_id = boundary_id.clone();
        path_boundary.artifacts[1].relative_logical_path = format!("{prefix}{boundary_id}");
        path_boundary.validate(&limits).unwrap();
        path_boundary.artifacts[1].relative_logical_path.push('x');
        assert_eq!(
            path_boundary.validate(&limits).unwrap_err().code,
            ErrorCode::BackupLimitExceeded
        );
    }

    #[test]
    fn manifest_rejects_schema_unknown_kind_and_incomplete_certificate_relations() {
        let mut schema = valid_manifest();
        schema.schema_version = 2;
        assert_eq!(
            schema
                .validate(&BackupLimits::schema_v1())
                .unwrap_err()
                .code,
            ErrorCode::BackupSchemaUnsupported
        );

        let mut unknown = valid_manifest();
        unknown.artifacts.push(descriptor(
            BackupArtifactKind::Unknown("future".to_string()),
            "future",
            "future/item",
            1,
            BackupArtifactMode::Public,
        ));
        unknown.artifact_count += 1;
        unknown.total_plaintext_bytes += 1;
        assert_eq!(
            unknown
                .validate(&BackupLimits::schema_v1())
                .unwrap_err()
                .code,
            ErrorCode::BackupManifestInvalid
        );

        let mut incomplete = valid_manifest();
        incomplete.artifacts.push(descriptor(
            BackupArtifactKind::CertificateChain,
            "cert-1",
            "certificates/cert-1/chain",
            100,
            BackupArtifactMode::Public,
        ));
        incomplete.artifact_count += 1;
        incomplete.total_plaintext_bytes += 100;
        assert_eq!(
            incomplete
                .validate(&BackupLimits::schema_v1())
                .unwrap_err()
                .code,
            ErrorCode::BackupManifestInvalid
        );
    }

    #[test]
    fn phase009_manifest_v2_requires_complete_referenced_trust_bundle_relation() {
        let mut manifest = valid_manifest();
        manifest.schema_version = 2;
        manifest.referenced_trust_bundle_refs = vec!["private-root".to_string()];
        manifest.artifacts.extend([
            descriptor(
                BackupArtifactKind::TrustBundleRoots,
                "private-root",
                "trust-bundles/private-root/roots",
                100,
                BackupArtifactMode::Public,
            ),
            descriptor(
                BackupArtifactKind::TrustBundleMetadata,
                "private-root",
                "trust-bundles/private-root/metadata",
                100,
                BackupArtifactMode::Public,
            ),
        ]);
        manifest
            .artifacts
            .sort_by(|left, right| left.relative_logical_path.cmp(&right.relative_logical_path));
        manifest.artifact_count = manifest.artifacts.len() as u32;
        manifest.total_plaintext_bytes = manifest
            .artifacts
            .iter()
            .map(|item| item.length_bytes)
            .sum();

        manifest.validate(&BackupLimits::schema_v2()).unwrap();
        assert_eq!(
            manifest
                .validate(&BackupLimits::schema_v1())
                .unwrap_err()
                .code,
            ErrorCode::BackupSchemaUnsupported
        );
        let mut incomplete = manifest.clone();
        incomplete
            .artifacts
            .retain(|item| item.kind != BackupArtifactKind::TrustBundleMetadata);
        incomplete.artifact_count = incomplete.artifacts.len() as u32;
        incomplete.total_plaintext_bytes = incomplete
            .artifacts
            .iter()
            .map(|item| item.length_bytes)
            .sum();
        assert_eq!(
            incomplete
                .validate(&BackupLimits::schema_v2())
                .unwrap_err()
                .code,
            ErrorCode::BackupManifestInvalid
        );

        valid_manifest()
            .validate(&BackupLimits::schema_v2())
            .unwrap();
    }

    #[test]
    fn phase010_manifest_v3_requires_ordered_contiguous_audit_segments() {
        let mut manifest = valid_manifest();
        manifest.schema_version = 3;
        manifest.artifacts.extend([
            descriptor(
                BackupArtifactKind::AuditLedgerSegment,
                "0000000000000001",
                "audit/segments/0000000000000001",
                100,
                BackupArtifactMode::Public,
            ),
            descriptor(
                BackupArtifactKind::AuditLedgerSegment,
                "0000000000000002",
                "audit/segments/0000000000000002",
                100,
                BackupArtifactMode::Public,
            ),
        ]);
        manifest
            .artifacts
            .sort_by(|left, right| left.relative_logical_path.cmp(&right.relative_logical_path));
        manifest.artifact_count = manifest.artifacts.len() as u32;
        manifest.total_plaintext_bytes = manifest
            .artifacts
            .iter()
            .map(|item| item.length_bytes)
            .sum();
        manifest.validate(&BackupLimits::schema_v3()).unwrap();
        assert_eq!(
            manifest
                .validate(&BackupLimits::schema_v2())
                .unwrap_err()
                .code,
            ErrorCode::BackupSchemaUnsupported
        );

        let mut gap = manifest.clone();
        let segment = gap
            .artifacts
            .iter_mut()
            .find(|item| item.logical_id == "0000000000000002")
            .unwrap();
        segment.logical_id = "0000000000000003".to_string();
        segment.relative_logical_path = "audit/segments/0000000000000003".to_string();
        assert_eq!(
            gap.validate(&BackupLimits::schema_v3()).unwrap_err().code,
            ErrorCode::BackupManifestInvalid
        );
    }

    #[test]
    fn manifest_admin_initialized_requires_exact_owner_only_verifier() {
        let mut manifest = valid_manifest();
        manifest.admin_initialized = true;
        assert_eq!(
            manifest
                .validate(&BackupLimits::schema_v1())
                .unwrap_err()
                .code,
            ErrorCode::BackupManifestInvalid
        );
        manifest.artifacts.push(descriptor(
            BackupArtifactKind::AdminPasswordHash,
            "admin-password-hash",
            "secrets/admin-password-hash",
            100,
            BackupArtifactMode::OwnerOnly,
        ));
        manifest.artifact_count += 1;
        manifest.total_plaintext_bytes += 100;
        manifest.validate(&BackupLimits::schema_v1()).unwrap();
    }

    #[test]
    fn sensitive_string_is_redacted_and_explicitly_exposed() {
        let value = SensitiveString::new("correct horse battery staple").unwrap();
        assert_eq!(format!("{value:?}"), "SensitiveString(<redacted>)");
        assert_eq!(value.expose(|secret| secret.len()), 28);
        assert!(!format!("{value:?}").contains("horse"));
        assert_eq!(
            SensitiveString::new("").unwrap_err().code,
            ErrorCode::BackupSecretInputInvalid
        );
        assert_eq!(
            SensitiveString::from_utf8(vec![0xff]).unwrap_err().code,
            ErrorCode::BackupSecretInputInvalid
        );
        assert!(SensitiveString::new("s".repeat(SensitiveString::MAX_BYTES)).is_ok());
        assert_eq!(
            SensitiveString::new("s".repeat(SensitiveString::MAX_BYTES + 1))
                .unwrap_err()
                .code,
            ErrorCode::BackupSecretInputInvalid
        );
    }

    #[test]
    fn backup_machine_enforces_happy_path_failure_cleanup_and_terminal_state() {
        let mut machine = BackupStateMachine::default();
        for event in [
            BackupEvent::Start,
            BackupEvent::LockAcquired,
            BackupEvent::InventoryBuilt,
            BackupEvent::InventoryValidated,
            BackupEvent::EnvelopeOpened,
            BackupEvent::EncryptedRecordWritten,
            BackupEvent::EnvelopeAuthenticated,
            BackupEvent::EnvelopeFinalized,
            BackupEvent::FileSynced,
            BackupEvent::RenameCommitted,
        ] {
            machine.transition(event).unwrap();
        }
        assert_eq!(machine.state(), BackupState::Completed);
        assert_eq!(
            machine.transition(BackupEvent::Start).unwrap_err().code,
            ErrorCode::BackupStateTransitionInvalid
        );

        let mut failed = BackupStateMachine::default();
        failed.transition(BackupEvent::Start).unwrap();
        failed
            .transition(BackupEvent::OperationFailed(ErrorCode::BackupSourceInvalid))
            .unwrap();
        assert!(matches!(failed.state(), BackupState::CleaningUp { .. }));
        failed.transition(BackupEvent::CleanupFinished).unwrap();
        assert!(matches!(failed.state(), BackupState::Failed { .. }));
    }

    #[test]
    fn restore_machine_enforces_authentication_before_stage_and_preflight_before_commit() {
        let mut machine = RestoreStateMachine::default();
        for event in [
            RestoreEvent::Start,
            RestoreEvent::LockAcquired,
            RestoreEvent::EnvelopeOpened,
            RestoreEvent::EnvelopeAuthenticated,
            RestoreEvent::ManifestRead,
            RestoreEvent::StageCreated,
            RestoreEvent::StageExtracted,
            RestoreEvent::ArtifactsVerified,
            RestoreEvent::ConfigValidated,
            RestoreEvent::CertificatesValidated,
            RestoreEvent::SecretsValidated,
            RestoreEvent::AuditValidated,
            RestoreEvent::RuntimePreflighted,
            RestoreEvent::CommitPrepared,
            RestoreEvent::TransactionPersisted,
            RestoreEvent::StagePublished,
            RestoreEvent::PublishedTargetVerified,
            RestoreEvent::ProvenancePersisted,
        ] {
            machine.transition(event).unwrap();
        }
        assert_eq!(machine.state(), RestoreState::Completed);
        assert_eq!(
            machine.transition(RestoreEvent::Start).unwrap_err().code,
            ErrorCode::RestoreStateTransitionInvalid
        );
        let mut invalid = RestoreStateMachine::default();
        invalid.transition(RestoreEvent::Start).unwrap();
        assert_eq!(
            invalid
                .transition(RestoreEvent::StageCreated)
                .unwrap_err()
                .code,
            ErrorCode::RestoreStateTransitionInvalid
        );
        assert_eq!(invalid.state(), RestoreState::Locking);

        invalid
            .transition(RestoreEvent::OperationFailed(
                ErrorCode::BackupSourceInvalid,
            ))
            .unwrap();
        assert!(matches!(invalid.state(), RestoreState::CleaningUp { .. }));
        invalid.transition(RestoreEvent::CleanupFinished).unwrap();
        assert!(matches!(invalid.state(), RestoreState::Failed { .. }));
    }

    #[test]
    fn restore_machine_requires_explicit_rollback_and_recovery_paths() {
        let mut rollback = RestoreStateMachine::default();
        for event in [
            RestoreEvent::Start,
            RestoreEvent::LockAcquired,
            RestoreEvent::EnvelopeOpened,
            RestoreEvent::EnvelopeAuthenticated,
            RestoreEvent::ManifestRead,
            RestoreEvent::StageCreated,
            RestoreEvent::StageExtracted,
            RestoreEvent::ArtifactsVerified,
            RestoreEvent::ConfigValidated,
            RestoreEvent::CertificatesValidated,
            RestoreEvent::SecretsValidated,
            RestoreEvent::AuditValidated,
            RestoreEvent::RuntimePreflighted,
            RestoreEvent::CommitPrepared,
            RestoreEvent::TransactionPersisted,
        ] {
            rollback.transition(event).unwrap();
        }
        rollback
            .transition(RestoreEvent::RollbackRequested(
                ErrorCode::BackupSourceInvalid,
            ))
            .unwrap();
        assert!(matches!(rollback.state(), RestoreState::RollingBack { .. }));
        rollback.transition(RestoreEvent::RollbackRestored).unwrap();
        rollback.transition(RestoreEvent::CleanupFinished).unwrap();
        assert!(matches!(rollback.state(), RestoreState::Failed { .. }));

        let mut recovery = RestoreStateMachine::default();
        recovery
            .transition(RestoreEvent::RecoveryRequested)
            .unwrap();
        recovery
            .transition(RestoreEvent::InterruptedTransactionRecovered)
            .unwrap();
        recovery
            .transition(RestoreEvent::PublishedTargetVerified)
            .unwrap();
        recovery
            .transition(RestoreEvent::ProvenancePersisted)
            .unwrap();
        assert_eq!(recovery.state(), RestoreState::Completed);
    }

    #[test]
    fn restore_machine_allows_new_target_commit_without_replace_transaction() {
        let mut machine = RestoreStateMachine::default();
        for event in [
            RestoreEvent::Start,
            RestoreEvent::LockAcquired,
            RestoreEvent::EnvelopeOpened,
            RestoreEvent::EnvelopeAuthenticated,
            RestoreEvent::ManifestRead,
            RestoreEvent::StageCreated,
            RestoreEvent::StageExtracted,
            RestoreEvent::ArtifactsVerified,
            RestoreEvent::ConfigValidated,
            RestoreEvent::CertificatesValidated,
            RestoreEvent::SecretsValidated,
            RestoreEvent::AuditValidated,
            RestoreEvent::RuntimePreflighted,
            RestoreEvent::NewTargetCommitPrepared,
            RestoreEvent::StagePublished,
            RestoreEvent::PublishedTargetVerified,
            RestoreEvent::ProvenancePersisted,
        ] {
            machine.transition(event).unwrap();
        }
        assert_eq!(machine.state(), RestoreState::Completed);
    }

    #[test]
    fn restore_machine_requires_provenance_after_published_target_verification() {
        let mut machine = RestoreStateMachine::default();
        machine.transition(RestoreEvent::RecoveryRequested).unwrap();
        machine
            .transition(RestoreEvent::InterruptedTransactionRecovered)
            .unwrap();
        machine
            .transition(RestoreEvent::PublishedTargetVerified)
            .unwrap();

        assert_eq!(machine.state(), RestoreState::RecordingProvenance);
        machine
            .transition(RestoreEvent::ProvenancePersisted)
            .unwrap();
        assert_eq!(machine.state(), RestoreState::Completed);
    }
}
