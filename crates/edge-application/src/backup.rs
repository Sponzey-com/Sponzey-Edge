use edge_domain::{
    AppError, AuditAction, AuditActorKind, AuditContext, AuditOperationId, AuditOutcome,
    AuditRecord, AuditRecordKind, AuditRequestId, AuditTargetId, AuditTargetKind, BackupEvent,
    BackupLimits, BackupManifest, BackupStateMachine, ConfigRevisionId, ErrorCode, RestoreEvent,
    RestoreState, RestoreStateMachine, SensitiveString,
};
use edge_ports::{
    BackupArchiveReader, BackupArchiveWriter, BackupArtifactSource, BackupManifestDigester, Clock,
    DataDirectoryLockManager, LogSink, OperationIdGenerator, RestoreArchiveExtractor,
    RestorePreflight, RestoreProvenanceWriter, RestorePublisher, RestoreReplacePublisher,
    RestoreRollbackOutcome, RestoreTransaction, RestoreTransactionState, RestoreTransactionStore,
    StructuredLogEvent,
};

pub struct ReplaceRestoreBackupInput {
    pub passphrase: SensitiveString,
}

pub struct ReplaceRestoreBackupUseCase<'a, L, E, P, T, U, C, I, G> {
    lock: &'a L,
    extractor: &'a mut E,
    preflight: &'a mut P,
    transactions: &'a mut T,
    publisher: &'a mut U,
    provenance: &'a mut dyn RestoreProvenanceWriter,
    clock: &'a C,
    ids: &'a mut I,
    logs: &'a mut G,
    limits: BackupLimits,
}

impl<'a, L, E, P, T, U, C, I, G> ReplaceRestoreBackupUseCase<'a, L, E, P, T, U, C, I, G>
where
    L: DataDirectoryLockManager,
    E: RestoreArchiveExtractor,
    P: RestorePreflight,
    T: RestoreTransactionStore,
    U: RestoreReplacePublisher,
    C: Clock,
    I: OperationIdGenerator,
    G: LogSink,
{
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        lock: &'a L,
        extractor: &'a mut E,
        preflight: &'a mut P,
        transactions: &'a mut T,
        publisher: &'a mut U,
        provenance: &'a mut dyn RestoreProvenanceWriter,
        clock: &'a C,
        ids: &'a mut I,
        logs: &'a mut G,
        limits: BackupLimits,
    ) -> Self {
        Self {
            lock,
            extractor,
            preflight,
            transactions,
            publisher,
            provenance,
            clock,
            ids,
            logs,
            limits,
        }
    }

    pub fn execute(
        &mut self,
        input: ReplaceRestoreBackupInput,
    ) -> Result<RestoreReceipt, AppError> {
        let operation_id = self.ids.next_id()?;
        record_backup_log(
            self.logs,
            "backup.restore_replace.started",
            vec![("operation_id", &operation_id)],
        )?;
        let started = self.clock.now_epoch_seconds();
        let mut machine = RestoreStateMachine::default();
        machine.transition(RestoreEvent::Start)?;
        let mut transaction = None;
        let result = self.execute_inner(input, &operation_id, &mut machine, &mut transaction);
        if let Err(original) = result {
            let mut failure = original;
            if matches!(
                machine.state(),
                RestoreState::Committing | RestoreState::VerifyingPublishedTarget
            ) {
                if let Some(tx) = &transaction {
                    let _ = machine.transition(RestoreEvent::RollbackRequested(failure.code));
                    match self.publisher.rollback_after_failure(tx) {
                        Ok(_) => {
                            let _ = machine.transition(RestoreEvent::RollbackRestored);
                            let _ = self.transactions.delete(&operation_id);
                        }
                        Err(error) => failure = error,
                    }
                }
            } else {
                let _ = machine.transition(RestoreEvent::OperationFailed(failure.code));
            }
            let _ = self.extractor.cleanup();
            let _ = machine.transition(RestoreEvent::CleanupFinished);
            let _ = record_backup_log(
                self.logs,
                "backup.restore_replace.failed",
                vec![
                    ("operation_id", &operation_id),
                    ("error_code", failure.code.as_str()),
                ],
            );
            return Err(failure);
        }
        let receipt = result.unwrap();
        let duration = self
            .clock
            .now_epoch_seconds()
            .saturating_sub(started)
            .to_string();
        let _ = record_backup_log(
            self.logs,
            "backup.restore_replace.succeeded",
            vec![
                ("operation_id", &operation_id),
                ("archive_id", &receipt.archive_id),
                ("commit_mode", receipt.commit_mode),
                ("duration_seconds", &duration),
            ],
        );
        Ok(receipt)
    }

    fn execute_inner(
        &mut self,
        input: ReplaceRestoreBackupInput,
        operation_id: &str,
        machine: &mut RestoreStateMachine,
        transaction: &mut Option<RestoreTransaction>,
    ) -> Result<RestoreReceipt, AppError> {
        let _guard = self.lock.try_acquire_exclusive()?;
        machine.transition(RestoreEvent::LockAcquired)?;
        let stage = self.extractor.extract(&input.passphrase, &self.limits)?;
        for event in [
            RestoreEvent::EnvelopeOpened,
            RestoreEvent::EnvelopeAuthenticated,
            RestoreEvent::ManifestRead,
            RestoreEvent::StageCreated,
            RestoreEvent::StageExtracted,
            RestoreEvent::ArtifactsVerified,
        ] {
            machine.transition(event)?;
        }
        self.preflight.validate_config(&stage)?;
        machine.transition(RestoreEvent::ConfigValidated)?;
        self.preflight.validate_certificates(&stage)?;
        machine.transition(RestoreEvent::CertificatesValidated)?;
        self.preflight.validate_secrets(&stage)?;
        machine.transition(RestoreEvent::SecretsValidated)?;
        self.preflight.validate_audit(&stage)?;
        machine.transition(RestoreEvent::AuditValidated)?;
        self.preflight.preflight_runtime(&stage)?;
        machine.transition(RestoreEvent::RuntimePreflighted)?;
        let mut tx = self.publisher.prepare_replace(operation_id, &stage)?;
        machine.transition(RestoreEvent::CommitPrepared)?;
        self.transactions.persist(&tx)?;
        machine.transition(RestoreEvent::TransactionPersisted)?;
        *transaction = Some(tx.clone());
        self.publisher.move_target_to_rollback(&tx)?;
        tx.state = RestoreTransactionState::TargetMoved;
        self.transactions.persist(&tx)?;
        *transaction = Some(tx.clone());
        machine.transition(RestoreEvent::TargetMovedToRollback)?;
        self.publisher.publish_stage(&tx)?;
        tx.state = RestoreTransactionState::StagePublished;
        self.transactions.persist(&tx)?;
        *transaction = Some(tx.clone());
        machine.transition(RestoreEvent::StagePublished)?;
        self.publisher.verify_target(&tx, &stage)?;
        machine.transition(RestoreEvent::PublishedTargetVerified)?;
        append_restore_provenance(
            self.provenance,
            operation_id,
            &stage.archive_id,
            Some(&stage.revision_id),
            self.clock.now_epoch_seconds(),
            machine,
        )?;
        self.publisher.cleanup_committed(&tx)?;
        self.transactions.delete(operation_id)?;
        Ok(RestoreReceipt {
            operation_id: operation_id.to_string(),
            archive_id: stage.archive_id,
            restored_layout_version: 1,
            restored_revision_id: stage.revision_id,
            certificate_count: stage.certificate_count,
            trust_bundle_count: stage.trust_bundle_count,
            rollback_copy_created: true,
            commit_mode: "replace_transaction",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestoreRecoveryReceipt {
    pub operation_id: String,
    pub outcome: &'static str,
}
pub struct RecoverRestoreUseCase<'a, T, U, C, G> {
    transactions: &'a mut T,
    publisher: &'a mut U,
    provenance: &'a mut dyn RestoreProvenanceWriter,
    clock: &'a C,
    logs: &'a mut G,
}
impl<'a, T: RestoreTransactionStore, U: RestoreReplacePublisher, C: Clock, G: LogSink>
    RecoverRestoreUseCase<'a, T, U, C, G>
{
    pub fn new(
        transactions: &'a mut T,
        publisher: &'a mut U,
        provenance: &'a mut dyn RestoreProvenanceWriter,
        clock: &'a C,
        logs: &'a mut G,
    ) -> Self {
        Self {
            transactions,
            publisher,
            provenance,
            clock,
            logs,
        }
    }
    pub fn execute(&mut self, operation_id: &str) -> Result<RestoreRecoveryReceipt, AppError> {
        record_backup_log(
            self.logs,
            "backup.restore_recovery.started",
            vec![("operation_id", operation_id)],
        )?;
        let result = self.execute_inner(operation_id);
        match &result {
            Ok(receipt) => {
                let _ = record_backup_log(
                    self.logs,
                    "backup.restore_recovery.succeeded",
                    vec![("operation_id", operation_id), ("outcome", receipt.outcome)],
                );
            }
            Err(error) => {
                let _ = record_backup_log(
                    self.logs,
                    "backup.restore_recovery.failed",
                    vec![
                        ("operation_id", operation_id),
                        ("error_code", error.code.as_str()),
                    ],
                );
            }
        }
        result
    }

    fn execute_inner(&mut self, operation_id: &str) -> Result<RestoreRecoveryReceipt, AppError> {
        let mut machine = RestoreStateMachine::default();
        machine.transition(RestoreEvent::RecoveryRequested)?;
        let tx = self.transactions.load(operation_id)?.ok_or_else(|| {
            AppError::new(
                ErrorCode::RestoreTransactionUnresolved,
                ErrorCode::RestoreTransactionUnresolved.default_user_message(),
            )
        })?;
        let target = self.publisher.target_valid(&tx)?;
        let rollback = self.publisher.rollback_valid(&tx)?;
        let outcome = match (tx.state, target, rollback) {
            (RestoreTransactionState::Prepared, true, false) => {
                self.publisher.cleanup_committed(&tx)?;
                "restore_aborted"
            }
            (RestoreTransactionState::TargetMoved, true, true)
            | (RestoreTransactionState::StagePublished, true, _) => {
                self.publisher.cleanup_committed(&tx)?;
                "commit_completed"
            }
            (RestoreTransactionState::Prepared, false, true)
            | (RestoreTransactionState::TargetMoved, false, true)
            | (RestoreTransactionState::StagePublished, false, true) => {
                match self.publisher.rollback_after_failure(&tx)? {
                    RestoreRollbackOutcome::Restored => "rollback_restored",
                    RestoreRollbackOutcome::NotRequired => return Err(transaction_ambiguous()),
                }
            }
            _ => return Err(transaction_ambiguous()),
        };
        machine.transition(RestoreEvent::InterruptedTransactionRecovered)?;
        machine.transition(RestoreEvent::PublishedTargetVerified)?;
        if outcome == "commit_completed" {
            append_restore_provenance(
                self.provenance,
                operation_id,
                &tx.archive_id,
                None,
                self.clock.now_epoch_seconds(),
                &mut machine,
            )?;
        } else {
            machine.transition(RestoreEvent::ProvenanceNotRequired)?;
        }
        self.transactions.delete(operation_id)?;
        Ok(RestoreRecoveryReceipt {
            operation_id: operation_id.to_string(),
            outcome,
        })
    }
}

pub struct RestoreBackupInput {
    pub passphrase: SensitiveString,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestoreReceipt {
    pub operation_id: String,
    pub archive_id: String,
    pub restored_layout_version: u32,
    pub restored_revision_id: ConfigRevisionId,
    pub certificate_count: u32,
    pub trust_bundle_count: u32,
    pub rollback_copy_created: bool,
    pub commit_mode: &'static str,
}

pub struct RestoreBackupUseCase<'a, L, E, P, U, C, I, G> {
    lock: &'a L,
    extractor: &'a mut E,
    preflight: &'a mut P,
    publisher: &'a mut U,
    provenance: &'a mut dyn RestoreProvenanceWriter,
    clock: &'a C,
    ids: &'a mut I,
    logs: &'a mut G,
    limits: BackupLimits,
}

impl<'a, L, E, P, U, C, I, G> RestoreBackupUseCase<'a, L, E, P, U, C, I, G>
where
    L: DataDirectoryLockManager,
    E: RestoreArchiveExtractor,
    P: RestorePreflight,
    U: RestorePublisher,
    C: Clock,
    I: OperationIdGenerator,
    G: LogSink,
{
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        lock: &'a L,
        extractor: &'a mut E,
        preflight: &'a mut P,
        publisher: &'a mut U,
        provenance: &'a mut dyn RestoreProvenanceWriter,
        clock: &'a C,
        ids: &'a mut I,
        logs: &'a mut G,
        limits: BackupLimits,
    ) -> Self {
        Self {
            lock,
            extractor,
            preflight,
            publisher,
            provenance,
            clock,
            ids,
            logs,
            limits,
        }
    }

    pub fn execute(&mut self, input: RestoreBackupInput) -> Result<RestoreReceipt, AppError> {
        let operation_id = self.ids.next_id()?;
        record_backup_log(
            self.logs,
            "backup.restore.started",
            vec![("operation_id", &operation_id)],
        )?;
        let started = self.clock.now_epoch_seconds();
        let mut machine = RestoreStateMachine::default();
        machine.transition(RestoreEvent::Start)?;
        let result = self.execute_inner(input, &operation_id, &mut machine);
        match &result {
            Ok(receipt) => {
                let duration = self
                    .clock
                    .now_epoch_seconds()
                    .saturating_sub(started)
                    .to_string();
                let _ = record_backup_log(
                    self.logs,
                    "backup.restore.succeeded",
                    vec![
                        ("operation_id", &operation_id),
                        ("archive_id", &receipt.archive_id),
                        ("commit_mode", receipt.commit_mode),
                        ("duration_seconds", &duration),
                    ],
                );
            }
            Err(error) => {
                let _ = machine.transition(RestoreEvent::OperationFailed(error.code));
                let _ = self.extractor.cleanup();
                let _ = machine.transition(RestoreEvent::CleanupFinished);
                let _ = record_backup_log(
                    self.logs,
                    "backup.restore.failed",
                    vec![
                        ("operation_id", &operation_id),
                        ("error_code", error.code.as_str()),
                    ],
                );
            }
        }
        result
    }

    fn execute_inner(
        &mut self,
        input: RestoreBackupInput,
        operation_id: &str,
        machine: &mut RestoreStateMachine,
    ) -> Result<RestoreReceipt, AppError> {
        let _guard = self.lock.try_acquire_exclusive()?;
        machine.transition(RestoreEvent::LockAcquired)?;
        let stage = self.extractor.extract(&input.passphrase, &self.limits)?;
        for event in [
            RestoreEvent::EnvelopeOpened,
            RestoreEvent::EnvelopeAuthenticated,
            RestoreEvent::ManifestRead,
            RestoreEvent::StageCreated,
            RestoreEvent::StageExtracted,
            RestoreEvent::ArtifactsVerified,
        ] {
            machine.transition(event)?;
        }
        self.preflight.validate_config(&stage)?;
        machine.transition(RestoreEvent::ConfigValidated)?;
        self.preflight.validate_certificates(&stage)?;
        machine.transition(RestoreEvent::CertificatesValidated)?;
        self.preflight.validate_secrets(&stage)?;
        machine.transition(RestoreEvent::SecretsValidated)?;
        self.preflight.validate_audit(&stage)?;
        machine.transition(RestoreEvent::AuditValidated)?;
        self.preflight.preflight_runtime(&stage)?;
        machine.transition(RestoreEvent::RuntimePreflighted)?;
        self.publisher.prepare_new_target(&stage)?;
        machine.transition(RestoreEvent::NewTargetCommitPrepared)?;
        self.publisher.publish_new_target(&stage)?;
        machine.transition(RestoreEvent::StagePublished)?;
        self.publisher.verify_published_target(&stage)?;
        machine.transition(RestoreEvent::PublishedTargetVerified)?;
        append_restore_provenance(
            self.provenance,
            operation_id,
            &stage.archive_id,
            Some(&stage.revision_id),
            self.clock.now_epoch_seconds(),
            machine,
        )?;
        Ok(RestoreReceipt {
            operation_id: operation_id.to_string(),
            archive_id: stage.archive_id,
            restored_layout_version: 1,
            restored_revision_id: stage.revision_id,
            certificate_count: stage.certificate_count,
            trust_bundle_count: stage.trust_bundle_count,
            rollback_copy_created: false,
            commit_mode: "new_target",
        })
    }
}

fn append_restore_provenance(
    writer: &mut dyn RestoreProvenanceWriter,
    operation_id: &str,
    archive_id: &str,
    revision_id: Option<&ConfigRevisionId>,
    timestamp: u64,
    machine: &mut RestoreStateMachine,
) -> Result<(), AppError> {
    let result = (|| {
        let operation_id = AuditOperationId::parse(operation_id).map_err(audit_record_error)?;
        let record = AuditRecord {
            record_version: 1,
            record_kind: AuditRecordKind::Reconciliation,
            context: AuditContext {
                request_id: AuditRequestId::parse(operation_id.as_str())
                    .map_err(audit_record_error)?,
                operation_id,
                actor_kind: AuditActorKind::MaintenanceCli,
                received_at_epoch_seconds: timestamp,
            },
            action: AuditAction::MaintenanceRestoreImported,
            target_kind: AuditTargetKind::Restore,
            target_id: AuditTargetId::parse(archive_id).map_err(audit_record_error)?,
            before_revision: None,
            after_revision: revision_id
                .map(|revision_id| AuditTargetId::parse(revision_id.as_str()))
                .transpose()
                .map_err(audit_record_error)?,
            outcome: Some(AuditOutcome::ReconciledCommitted),
            error_code: None,
        };
        writer.append_restore_provenance(record)
    })();
    match result {
        Ok(_) => machine.transition(RestoreEvent::ProvenancePersisted),
        Err(error) => {
            machine.transition(RestoreEvent::ProvenanceAppendFailed(error.code))?;
            Err(error)
        }
    }
}

fn audit_record_error(_: impl std::fmt::Display) -> AppError {
    AppError::new(
        ErrorCode::AuditRecordInvalid,
        "restore audit identity is invalid",
    )
}

pub struct VerifyBackupInput {
    pub passphrase: SensitiveString,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupVerificationReport {
    pub operation_id: String,
    pub archive_id: String,
    pub schema_version: u32,
    pub artifact_count: u32,
    pub total_bytes: u64,
    pub config_present: bool,
    pub revision_pointer_valid: bool,
    pub certificates_count: u32,
    pub referenced_certificates_count: u32,
    pub trust_bundles_count: u32,
    pub referenced_trust_bundles_count: u32,
    pub audit_segments_count: u16,
    pub admin_initialized: bool,
    pub secrets_present: bool,
    pub compatible: bool,
}

pub struct VerifyBackupUseCase<'a, R, D, C, I, G> {
    reader: &'a mut R,
    digester: &'a D,
    clock: &'a C,
    ids: &'a mut I,
    logs: &'a mut G,
    limits: BackupLimits,
}

impl<'a, R, D, C, I, G> VerifyBackupUseCase<'a, R, D, C, I, G>
where
    R: BackupArchiveReader,
    D: BackupManifestDigester,
    C: Clock,
    I: OperationIdGenerator,
    G: LogSink,
{
    pub fn new(
        reader: &'a mut R,
        digester: &'a D,
        clock: &'a C,
        ids: &'a mut I,
        logs: &'a mut G,
        limits: BackupLimits,
    ) -> Self {
        Self {
            reader,
            digester,
            clock,
            ids,
            logs,
            limits,
        }
    }

    pub fn execute(
        &mut self,
        input: VerifyBackupInput,
    ) -> Result<BackupVerificationReport, AppError> {
        let operation_id = self.ids.next_id()?;
        record_backup_log(
            self.logs,
            "backup.verify.started",
            vec![("operation_id", &operation_id)],
        )?;
        let started = self.clock.now_epoch_seconds();
        let result = self.verify(input, &operation_id);
        match &result {
            Ok(report) => {
                let count = report.artifact_count.to_string();
                let duration = self
                    .clock
                    .now_epoch_seconds()
                    .saturating_sub(started)
                    .to_string();
                let _ = record_backup_log(
                    self.logs,
                    "backup.verify.succeeded",
                    vec![
                        ("operation_id", &operation_id),
                        ("archive_id", &report.archive_id),
                        ("artifact_count", &count),
                        ("duration_seconds", &duration),
                    ],
                );
            }
            Err(error) => {
                let _ = record_backup_log(
                    self.logs,
                    "backup.verify.failed",
                    vec![
                        ("operation_id", &operation_id),
                        ("error_code", error.code.as_str()),
                    ],
                );
            }
        }
        result
    }

    fn verify(
        &mut self,
        input: VerifyBackupInput,
        operation_id: &str,
    ) -> Result<BackupVerificationReport, AppError> {
        let archive = self.reader.read(&input.passphrase, &self.limits)?;
        archive.manifest.validate(&self.limits)?;
        if self.digester.digest(&archive.manifest)? != archive.manifest.manifest_digest
            || archive.records.len() != archive.manifest.artifacts.len()
            || archive
                .records
                .iter()
                .zip(&archive.manifest.artifacts)
                .any(|(record, expected)| {
                    record.relative_logical_path != expected.relative_logical_path
                        || record.length_bytes != expected.length_bytes
                        || record.sha256 != expected.sha256
                })
        {
            return Err(AppError::new(
                ErrorCode::BackupDigestMismatch,
                ErrorCode::BackupDigestMismatch.default_user_message(),
            ));
        }
        let certificates_count = archive
            .manifest
            .artifacts
            .iter()
            .filter(|item| matches!(item.kind, edge_domain::BackupArtifactKind::CertificateChain))
            .count() as u32;
        let trust_bundles_count = archive
            .manifest
            .artifacts
            .iter()
            .filter(|item| matches!(item.kind, edge_domain::BackupArtifactKind::TrustBundleRoots))
            .count() as u32;
        let audit_segments_count = archive
            .manifest
            .artifacts
            .iter()
            .filter(|item| item.kind == edge_domain::BackupArtifactKind::AuditLedgerSegment)
            .count()
            .try_into()
            .map_err(|_| {
                AppError::new(
                    ErrorCode::BackupLimitExceeded,
                    "audit segment count exceeds backup limit",
                )
            })?;
        Ok(BackupVerificationReport {
            operation_id: operation_id.to_string(),
            archive_id: archive.manifest.archive_id.clone(),
            schema_version: archive.manifest.schema_version,
            artifact_count: archive.manifest.artifact_count,
            total_bytes: archive.manifest.total_plaintext_bytes,
            config_present: true,
            revision_pointer_valid: true,
            certificates_count,
            referenced_certificates_count: archive.manifest.referenced_certificate_refs.len()
                as u32,
            trust_bundles_count,
            referenced_trust_bundles_count: archive.manifest.referenced_trust_bundle_refs.len()
                as u32,
            audit_segments_count,
            admin_initialized: archive.manifest.admin_initialized,
            secrets_present: archive.manifest.admin_initialized || certificates_count > 0,
            compatible: true,
        })
    }
}

pub struct CreateBackupInput {
    pub source_app_version: String,
    pub destination_identity: String,
    pub passphrase: SensitiveString,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupReceipt {
    pub operation_id: String,
    pub archive_id: String,
    pub schema_version: u32,
    pub artifact_count: u32,
    pub plaintext_bytes: u64,
    pub encrypted_bytes: u64,
    pub created_at_epoch_seconds: u64,
    pub destination_identity: String,
    pub current_revision_id: ConfigRevisionId,
    pub source_fingerprint: String,
}

pub struct CreateBackupUseCase<'a, L, S, D, W, C, I, G> {
    lock: &'a L,
    source: &'a mut S,
    digester: &'a D,
    writer: &'a mut W,
    clock: &'a C,
    ids: &'a mut I,
    logs: &'a mut G,
    limits: BackupLimits,
}

impl<'a, L, S, D, W, C, I, G> CreateBackupUseCase<'a, L, S, D, W, C, I, G>
where
    L: DataDirectoryLockManager,
    S: BackupArtifactSource,
    D: BackupManifestDigester,
    W: BackupArchiveWriter,
    C: Clock,
    I: OperationIdGenerator,
    G: LogSink,
{
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        lock: &'a L,
        source: &'a mut S,
        digester: &'a D,
        writer: &'a mut W,
        clock: &'a C,
        ids: &'a mut I,
        logs: &'a mut G,
        limits: BackupLimits,
    ) -> Self {
        Self {
            lock,
            source,
            digester,
            writer,
            clock,
            ids,
            logs,
            limits,
        }
    }

    pub fn execute(&mut self, input: CreateBackupInput) -> Result<BackupReceipt, AppError> {
        validate_destination_identity(&input.destination_identity)?;
        if input.source_app_version.is_empty() {
            return Err(AppError::new(
                ErrorCode::BackupSourceInvalid,
                "source app version is empty",
            ));
        }
        let operation_id = self.ids.next_id()?;
        record_backup_log(
            self.logs,
            "backup.create.started",
            vec![("operation_id", &operation_id)],
        )?;
        let started_at = self.clock.now_epoch_seconds();
        let mut machine = BackupStateMachine::default();
        machine.transition(BackupEvent::Start)?;
        let _guard = match self.lock.try_acquire_exclusive() {
            Ok(guard) => guard,
            Err(failure) => {
                let _ = machine.transition(BackupEvent::OperationFailed(failure.code));
                let _ = self.writer.cleanup();
                let _ = machine.transition(BackupEvent::CleanupFinished);
                let _ = record_backup_log(
                    self.logs,
                    "backup.create.failed",
                    vec![
                        ("operation_id", &operation_id),
                        ("error_code", failure.code.as_str()),
                    ],
                );
                return Err(failure);
            }
        };
        machine.transition(BackupEvent::LockAcquired)?;

        let result = self.execute_locked(&input, &operation_id, started_at, &mut machine);
        if let Err(failure) = &result {
            let _ = machine.transition(BackupEvent::OperationFailed(failure.code));
            let _ = self.writer.cleanup();
            let _ = machine.transition(BackupEvent::CleanupFinished);
            let _ = record_backup_log(
                self.logs,
                "backup.create.failed",
                vec![
                    ("operation_id", &operation_id),
                    ("error_code", failure.code.as_str()),
                ],
            );
        }
        result
    }

    fn execute_locked(
        &mut self,
        input: &CreateBackupInput,
        operation_id: &str,
        started_at: u64,
        machine: &mut BackupStateMachine,
    ) -> Result<BackupReceipt, AppError> {
        let inventory = self.source.inventory()?;
        machine.transition(BackupEvent::InventoryBuilt)?;
        let archive_id = self.ids.next_id()?;
        let plaintext_bytes = inventory.artifacts.iter().try_fold(0_u64, |sum, item| {
            sum.checked_add(item.length_bytes).ok_or_else(|| {
                AppError::new(
                    ErrorCode::BackupLimitExceeded,
                    "artifact byte total overflow",
                )
            })
        })?;
        let mut manifest = BackupManifest {
            schema_version: self.limits.max_schema_version,
            archive_id: archive_id.clone(),
            created_at_epoch_seconds: started_at,
            source_app_version: input.source_app_version.clone(),
            source_layout_version: 1,
            current_revision_id: inventory.current_revision_id.as_str().to_string(),
            admin_initialized: inventory.admin_initialized,
            referenced_certificate_refs: inventory.referenced_certificate_refs.clone(),
            referenced_trust_bundle_refs: inventory.referenced_trust_bundle_refs.clone(),
            artifact_count: inventory.artifacts.len().try_into().map_err(|_| {
                AppError::new(ErrorCode::BackupLimitExceeded, "artifact count overflow")
            })?,
            total_plaintext_bytes: plaintext_bytes,
            artifacts: inventory.artifacts.clone(),
            manifest_digest: [0; 32],
        };
        manifest.validate(&self.limits)?;
        manifest.manifest_digest = self.digester.digest(&manifest)?;
        machine.transition(BackupEvent::InventoryValidated)?;
        self.writer.open(&manifest, &input.passphrase)?;
        machine.transition(BackupEvent::EnvelopeOpened)?;
        for expected in &inventory.artifacts {
            let artifact = self.source.read_artifact(expected)?;
            if artifact.descriptor != *expected
                || artifact.payload.len() as u64 != expected.length_bytes
            {
                return Err(AppError::new(
                    ErrorCode::BackupSourceChanged,
                    "backup source changed after inventory",
                ));
            }
            self.writer.write_record(artifact)?;
            machine.transition(BackupEvent::EncryptedRecordWritten)?;
        }
        let encrypted_bytes = self.writer.finalize()?;
        machine.transition(BackupEvent::EnvelopeAuthenticated)?;
        machine.transition(BackupEvent::EnvelopeFinalized)?;
        self.writer.sync()?;
        machine.transition(BackupEvent::FileSynced)?;
        self.writer.publish()?;
        machine.transition(BackupEvent::RenameCommitted)?;
        let duration_seconds = self
            .clock
            .now_epoch_seconds()
            .saturating_sub(started_at)
            .to_string();
        let count = manifest.artifact_count.to_string();
        // The archive is already durably published. Observability failure must not
        // turn that committed result into an ambiguous operation failure.
        let _ = record_backup_log(
            self.logs,
            "backup.create.succeeded",
            vec![
                ("operation_id", operation_id),
                ("archive_id", &archive_id),
                ("artifact_count", &count),
                ("duration_seconds", &duration_seconds),
            ],
        );
        Ok(BackupReceipt {
            operation_id: operation_id.to_string(),
            archive_id,
            schema_version: manifest.schema_version,
            artifact_count: manifest.artifact_count,
            plaintext_bytes,
            encrypted_bytes,
            created_at_epoch_seconds: started_at,
            destination_identity: input.destination_identity.clone(),
            current_revision_id: inventory.current_revision_id,
            source_fingerprint: inventory.source_fingerprint,
        })
    }
}

fn validate_destination_identity(value: &str) -> Result<(), AppError> {
    if value.is_empty() || value.contains(['/', '\\', '\0']) || value == "." || value == ".." {
        return Err(AppError::new(
            ErrorCode::BackupDestinationUnsafe,
            "backup destination identity is unsafe",
        ));
    }
    Ok(())
}

fn transaction_ambiguous() -> AppError {
    AppError::new(
        ErrorCode::RestoreTransactionAmbiguous,
        ErrorCode::RestoreTransactionAmbiguous.default_user_message(),
    )
}

fn record_backup_log(
    logs: &mut impl LogSink,
    event: &str,
    fields: Vec<(&str, &str)>,
) -> Result<(), AppError> {
    logs.record_log(StructuredLogEvent {
        component: "backup".to_string(),
        event: event.to_string(),
        fields: fields
            .into_iter()
            .map(|(key, value)| (key.to_string(), value.to_string()))
            .collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use edge_domain::{
        AppError, BackupArtifactDescriptor, BackupArtifactKind, BackupArtifactMode, BackupLimits,
        ConfigRevisionId, DataDirectoryLockState, SensitiveString,
    };
    use edge_ports::{
        BackupArchiveRead, BackupArchiveReader, BackupArchiveWriter, BackupArtifact,
        BackupArtifactSource, BackupManifestDigester, BackupRecordSummary, BackupSourceInventory,
        Clock, DataDirectoryLockGuard, DataDirectoryLockManager, LogSink, OperationIdGenerator,
        RestoreArchiveExtractor, RestorePreflight, RestorePublisher, RestoreReplacePublisher,
        RestoreRollbackOutcome, RestoreStageSummary, RestoreTransaction, RestoreTransactionState,
        RestoreTransactionStore, StructuredLogEvent,
    };
    use std::cell::RefCell;
    use std::rc::Rc;

    #[derive(Debug)]
    struct Guard;
    impl DataDirectoryLockGuard for Guard {
        fn state(&self) -> DataDirectoryLockState {
            DataDirectoryLockState::HeldExclusive
        }
        fn release(&mut self) -> Result<(), AppError> {
            Ok(())
        }
    }
    struct Lock;
    impl DataDirectoryLockManager for Lock {
        fn try_acquire_exclusive(&self) -> Result<Box<dyn DataDirectoryLockGuard>, AppError> {
            Ok(Box::new(Guard))
        }
    }
    struct BusyLock;
    impl DataDirectoryLockManager for BusyLock {
        fn try_acquire_exclusive(&self) -> Result<Box<dyn DataDirectoryLockGuard>, AppError> {
            Err(AppError::new(
                ErrorCode::DataDirectoryBusy,
                "data directory is busy",
            ))
        }
    }
    struct Source {
        inventory: BackupSourceInventory,
        payloads: Vec<Vec<u8>>,
        reads: usize,
    }
    impl BackupArtifactSource for Source {
        fn inventory(&mut self) -> Result<BackupSourceInventory, AppError> {
            Ok(self.inventory.clone())
        }
        fn read_artifact(
            &mut self,
            _: &BackupArtifactDescriptor,
        ) -> Result<BackupArtifact, AppError> {
            let descriptor = self.inventory.artifacts[self.reads].clone();
            let payload = self.payloads[self.reads].clone();
            self.reads += 1;
            Ok(BackupArtifact {
                descriptor,
                payload,
            })
        }
    }
    #[derive(Default)]
    struct Writer {
        calls: Vec<&'static str>,
        fail_at: Option<&'static str>,
    }
    impl Writer {
        fn step(&mut self, name: &'static str) -> Result<(), AppError> {
            self.calls.push(name);
            if self.fail_at == Some(name) {
                return Err(AppError::new(ErrorCode::BackupWriteFailed, "injected"));
            }
            Ok(())
        }
    }
    impl BackupArchiveWriter for Writer {
        fn open(
            &mut self,
            _: &edge_domain::BackupManifest,
            _: &SensitiveString,
        ) -> Result<(), AppError> {
            self.step("open")
        }
        fn write_record(&mut self, _: BackupArtifact) -> Result<(), AppError> {
            self.step("record")
        }
        fn finalize(&mut self) -> Result<u64, AppError> {
            self.step("finalize")?;
            Ok(512)
        }
        fn sync(&mut self) -> Result<(), AppError> {
            self.step("sync")
        }
        fn publish(&mut self) -> Result<(), AppError> {
            self.step("publish")
        }
        fn cleanup(&mut self) -> Result<(), AppError> {
            self.step("cleanup")
        }
    }
    struct Digester;
    impl BackupManifestDigester for Digester {
        fn digest(&self, _: &edge_domain::BackupManifest) -> Result<[u8; 32], AppError> {
            Ok([3; 32])
        }
    }
    struct Ids(usize);
    impl OperationIdGenerator for Ids {
        fn next_id(&mut self) -> Result<String, AppError> {
            self.0 += 1;
            Ok(format!("id-{}", self.0))
        }
    }
    struct Time;
    impl Clock for Time {
        fn now_epoch_seconds(&self) -> u64 {
            1234
        }
    }
    #[derive(Default)]
    struct Logs(Vec<StructuredLogEvent>);
    impl LogSink for Logs {
        fn record_log(&mut self, event: StructuredLogEvent) -> Result<(), AppError> {
            self.0.push(event);
            Ok(())
        }
    }
    #[derive(Default)]
    struct Provenance(Vec<AuditRecord>);
    impl RestoreProvenanceWriter for Provenance {
        fn append_restore_provenance(
            &mut self,
            record: AuditRecord,
        ) -> Result<edge_domain::AuditLedgerHead, AppError> {
            self.0.push(record);
            Ok(edge_domain::AuditLedgerHead {
                generation: 1,
                sequence: self.0.len() as u64,
            })
        }
    }
    #[derive(Default)]
    struct FailSuccessLog(Vec<StructuredLogEvent>);
    impl LogSink for FailSuccessLog {
        fn record_log(&mut self, event: StructuredLogEvent) -> Result<(), AppError> {
            if event.event == "backup.create.succeeded" {
                return Err(AppError::new(ErrorCode::InternalBug, "log unavailable"));
            }
            self.0.push(event);
            Ok(())
        }
    }

    fn item(
        kind: BackupArtifactKind,
        id: &str,
        path: &str,
        bytes: u64,
    ) -> BackupArtifactDescriptor {
        BackupArtifactDescriptor {
            kind,
            logical_id: id.to_string(),
            relative_logical_path: path.to_string(),
            length_bytes: bytes,
            sha256: [1; 32],
            mode: BackupArtifactMode::Public,
            required_for_restore: true,
        }
    }

    fn test_inventory() -> BackupSourceInventory {
        BackupSourceInventory {
            current_revision_id: ConfigRevisionId::new("rev-1"),
            admin_initialized: false,
            referenced_certificate_refs: vec![],
            referenced_trust_bundle_refs: vec![],
            source_fingerprint: "source-1".to_string(),
            artifacts: vec![
                item(
                    BackupArtifactKind::ConfigRevisionPointer,
                    "current",
                    "config/current",
                    3,
                ),
                item(
                    BackupArtifactKind::ConfigRevision,
                    "rev-1",
                    "config/revisions/rev-1",
                    4,
                ),
            ],
        }
    }

    struct Reader(Option<BackupArchiveRead>);
    impl BackupArchiveReader for Reader {
        fn read(
            &mut self,
            _: &SensitiveString,
            _: &BackupLimits,
        ) -> Result<BackupArchiveRead, AppError> {
            self.0
                .take()
                .ok_or_else(|| AppError::new(ErrorCode::BackupFormatInvalid, "missing fixture"))
        }
    }

    fn verified_archive() -> BackupArchiveRead {
        let inventory = test_inventory();
        let manifest = BackupManifest {
            schema_version: 1,
            archive_id: "archive-1".to_string(),
            created_at_epoch_seconds: 1234,
            source_app_version: "0.1.0".to_string(),
            source_layout_version: 1,
            current_revision_id: "rev-1".to_string(),
            admin_initialized: false,
            referenced_certificate_refs: vec![],
            referenced_trust_bundle_refs: vec![],
            artifact_count: 2,
            total_plaintext_bytes: 7,
            artifacts: inventory.artifacts.clone(),
            manifest_digest: [3; 32],
        };
        let records = inventory
            .artifacts
            .iter()
            .map(|item| BackupRecordSummary {
                relative_logical_path: item.relative_logical_path.clone(),
                length_bytes: item.length_bytes,
                sha256: item.sha256,
            })
            .collect();
        BackupArchiveRead { manifest, records }
    }

    struct Extractor {
        calls: Rc<RefCell<Vec<&'static str>>>,
    }
    impl RestoreArchiveExtractor for Extractor {
        fn extract(
            &mut self,
            _: &SensitiveString,
            _: &BackupLimits,
        ) -> Result<RestoreStageSummary, AppError> {
            self.calls.borrow_mut().push("extract");
            Ok(RestoreStageSummary {
                stage_identity: "stage-1".to_string(),
                archive_id: "archive-1".to_string(),
                revision_id: ConfigRevisionId::new("rev-1"),
                artifact_count: 2,
                certificate_count: 0,
                trust_bundle_count: 0,
                audit_segment_count: 0,
                admin_initialized: false,
                referenced_certificate_refs: vec![],
                referenced_trust_bundle_refs: vec![],
            })
        }
        fn cleanup(&mut self) -> Result<(), AppError> {
            self.calls.borrow_mut().push("cleanup");
            Ok(())
        }
    }
    struct Preflight {
        calls: Rc<RefCell<Vec<&'static str>>>,
        fail: bool,
    }
    impl RestorePreflight for Preflight {
        fn validate_config(&mut self, _: &RestoreStageSummary) -> Result<(), AppError> {
            self.calls.borrow_mut().push("config");
            Ok(())
        }
        fn validate_certificates(&mut self, _: &RestoreStageSummary) -> Result<(), AppError> {
            self.calls.borrow_mut().push("certificates");
            if self.fail {
                Err(AppError::new(
                    ErrorCode::RestoreCertificateInvalid,
                    "injected",
                ))
            } else {
                Ok(())
            }
        }
        fn validate_secrets(&mut self, _: &RestoreStageSummary) -> Result<(), AppError> {
            self.calls.borrow_mut().push("secrets");
            Ok(())
        }
        fn validate_audit(&mut self, _: &RestoreStageSummary) -> Result<(), AppError> {
            self.calls.borrow_mut().push("audit");
            Ok(())
        }
        fn preflight_runtime(&mut self, _: &RestoreStageSummary) -> Result<(), AppError> {
            self.calls.borrow_mut().push("runtime");
            Ok(())
        }
    }
    struct Publisher {
        calls: Rc<RefCell<Vec<&'static str>>>,
    }

    struct Transactions {
        calls: Rc<RefCell<Vec<&'static str>>>,
        value: Option<RestoreTransaction>,
    }
    impl RestoreTransactionStore for Transactions {
        fn persist(&mut self, value: &RestoreTransaction) -> Result<(), AppError> {
            self.calls.borrow_mut().push("persist");
            self.value = Some(value.clone());
            Ok(())
        }
        fn load(&mut self, _: &str) -> Result<Option<RestoreTransaction>, AppError> {
            self.calls.borrow_mut().push("load");
            Ok(self.value.clone())
        }
        fn delete(&mut self, _: &str) -> Result<(), AppError> {
            self.calls.borrow_mut().push("delete");
            self.value = None;
            Ok(())
        }
    }
    struct ReplacePublisher {
        calls: Rc<RefCell<Vec<&'static str>>>,
        fail_publish: bool,
        target: bool,
        rollback: bool,
    }
    impl RestoreReplacePublisher for ReplacePublisher {
        fn prepare_replace(
            &mut self,
            operation_id: &str,
            stage: &RestoreStageSummary,
        ) -> Result<RestoreTransaction, AppError> {
            self.calls.borrow_mut().push("prepare-replace");
            Ok(RestoreTransaction {
                operation_id: operation_id.to_string(),
                archive_id: stage.archive_id.clone(),
                target_identity: "target".to_string(),
                stage_identity: stage.stage_identity.clone(),
                rollback_identity: "rollback".to_string(),
                state: RestoreTransactionState::Prepared,
            })
        }
        fn move_target_to_rollback(&mut self, _: &RestoreTransaction) -> Result<(), AppError> {
            self.calls.borrow_mut().push("move-old");
            self.target = false;
            self.rollback = true;
            Ok(())
        }
        fn publish_stage(&mut self, _: &RestoreTransaction) -> Result<(), AppError> {
            self.calls.borrow_mut().push("publish-new");
            if self.fail_publish {
                Err(AppError::new(ErrorCode::RestoreCommitFailed, "injected"))
            } else {
                self.target = true;
                Ok(())
            }
        }
        fn verify_target(
            &mut self,
            _: &RestoreTransaction,
            _: &RestoreStageSummary,
        ) -> Result<(), AppError> {
            self.calls.borrow_mut().push("verify-target");
            Ok(())
        }
        fn rollback_after_failure(
            &mut self,
            _: &RestoreTransaction,
        ) -> Result<RestoreRollbackOutcome, AppError> {
            self.calls.borrow_mut().push("rollback");
            self.target = true;
            self.rollback = false;
            Ok(RestoreRollbackOutcome::Restored)
        }
        fn cleanup_committed(&mut self, _: &RestoreTransaction) -> Result<(), AppError> {
            self.calls.borrow_mut().push("cleanup-commit");
            self.rollback = false;
            Ok(())
        }
        fn target_valid(&mut self, _: &RestoreTransaction) -> Result<bool, AppError> {
            Ok(self.target)
        }
        fn rollback_valid(&mut self, _: &RestoreTransaction) -> Result<bool, AppError> {
            Ok(self.rollback)
        }
    }

    #[test]
    fn replace_restore_persists_each_crash_state_and_rolls_back_publish_failure() {
        let calls = Rc::new(RefCell::new(Vec::new()));
        let mut extractor = Extractor {
            calls: Rc::clone(&calls),
        };
        let mut preflight = Preflight {
            calls: Rc::clone(&calls),
            fail: false,
        };
        let mut transactions = Transactions {
            calls: Rc::clone(&calls),
            value: None,
        };
        let mut publisher = ReplacePublisher {
            calls: Rc::clone(&calls),
            fail_publish: false,
            target: true,
            rollback: false,
        };
        let receipt = ReplaceRestoreBackupUseCase::new(
            &Lock,
            &mut extractor,
            &mut preflight,
            &mut transactions,
            &mut publisher,
            &mut Provenance::default(),
            &Time,
            &mut Ids(0),
            &mut Logs::default(),
            BackupLimits::schema_v1(),
        )
        .execute(ReplaceRestoreBackupInput {
            passphrase: SensitiveString::new("secret").unwrap(),
        })
        .unwrap();
        assert_eq!(receipt.commit_mode, "replace_transaction");
        assert_eq!(
            calls
                .borrow()
                .iter()
                .filter(|call| **call == "persist")
                .count(),
            3
        );
        assert!(calls
            .borrow()
            .windows(3)
            .any(|items| items == ["persist", "move-old", "persist"]));
        assert!(transactions.value.is_none());

        calls.borrow_mut().clear();
        let mut extractor = Extractor {
            calls: Rc::clone(&calls),
        };
        let mut preflight = Preflight {
            calls: Rc::clone(&calls),
            fail: false,
        };
        let mut transactions = Transactions {
            calls: Rc::clone(&calls),
            value: None,
        };
        let mut publisher = ReplacePublisher {
            calls: Rc::clone(&calls),
            fail_publish: true,
            target: true,
            rollback: false,
        };
        let error = ReplaceRestoreBackupUseCase::new(
            &Lock,
            &mut extractor,
            &mut preflight,
            &mut transactions,
            &mut publisher,
            &mut Provenance::default(),
            &Time,
            &mut Ids(0),
            &mut Logs::default(),
            BackupLimits::schema_v1(),
        )
        .execute(ReplaceRestoreBackupInput {
            passphrase: SensitiveString::new("secret").unwrap(),
        })
        .unwrap_err();
        assert_eq!(error.code, ErrorCode::RestoreCommitFailed);
        assert!(calls.borrow().contains(&"rollback"));
        assert!(publisher.target);
        assert!(!publisher.rollback);
    }

    #[test]
    fn restore_recovery_decides_from_transaction_state_and_observed_paths() {
        let calls = Rc::new(RefCell::new(Vec::new()));
        let transaction = |state| RestoreTransaction {
            operation_id: "operation-1".to_string(),
            archive_id: "archive-1".to_string(),
            target_identity: "target".to_string(),
            stage_identity: "stage".to_string(),
            rollback_identity: "rollback".to_string(),
            state,
        };

        let mut store = Transactions {
            calls: Rc::clone(&calls),
            value: Some(transaction(RestoreTransactionState::Prepared)),
        };
        let mut publisher = ReplacePublisher {
            calls: Rc::clone(&calls),
            fail_publish: false,
            target: true,
            rollback: false,
        };
        let receipt = RecoverRestoreUseCase::new(
            &mut store,
            &mut publisher,
            &mut Provenance::default(),
            &Time,
            &mut Logs::default(),
        )
        .execute("operation-1")
        .unwrap();
        assert_eq!(receipt.outcome, "restore_aborted");

        let mut store = Transactions {
            calls: Rc::clone(&calls),
            value: Some(transaction(RestoreTransactionState::TargetMoved)),
        };
        let mut publisher = ReplacePublisher {
            calls: Rc::clone(&calls),
            fail_publish: false,
            target: false,
            rollback: true,
        };
        let receipt = RecoverRestoreUseCase::new(
            &mut store,
            &mut publisher,
            &mut Provenance::default(),
            &Time,
            &mut Logs::default(),
        )
        .execute("operation-1")
        .unwrap();
        assert_eq!(receipt.outcome, "rollback_restored");

        let mut store = Transactions {
            calls: Rc::clone(&calls),
            value: Some(transaction(RestoreTransactionState::StagePublished)),
        };
        let mut publisher = ReplacePublisher {
            calls,
            fail_publish: false,
            target: true,
            rollback: true,
        };
        let receipt = RecoverRestoreUseCase::new(
            &mut store,
            &mut publisher,
            &mut Provenance::default(),
            &Time,
            &mut Logs::default(),
        )
        .execute("operation-1")
        .unwrap();
        assert_eq!(receipt.outcome, "commit_completed");

        let ambiguous_calls = Rc::new(RefCell::new(Vec::new()));
        let mut store = Transactions {
            calls: Rc::clone(&ambiguous_calls),
            value: Some(transaction(RestoreTransactionState::TargetMoved)),
        };
        let mut publisher = ReplacePublisher {
            calls: Rc::clone(&ambiguous_calls),
            fail_publish: false,
            target: true,
            rollback: false,
        };
        let error = RecoverRestoreUseCase::new(
            &mut store,
            &mut publisher,
            &mut Provenance::default(),
            &Time,
            &mut Logs::default(),
        )
        .execute("operation-1")
        .unwrap_err();
        assert_eq!(error.code, ErrorCode::RestoreTransactionAmbiguous);
        assert!(!ambiguous_calls.borrow().contains(&"rollback"));
        assert!(!ambiguous_calls.borrow().contains(&"cleanup-commit"));
        assert!(!ambiguous_calls.borrow().contains(&"delete"));
    }
    impl RestorePublisher for Publisher {
        fn prepare_new_target(&mut self, _: &RestoreStageSummary) -> Result<(), AppError> {
            self.calls.borrow_mut().push("prepare");
            Ok(())
        }
        fn publish_new_target(&mut self, _: &RestoreStageSummary) -> Result<(), AppError> {
            self.calls.borrow_mut().push("publish");
            Ok(())
        }
        fn verify_published_target(&mut self, _: &RestoreStageSummary) -> Result<(), AppError> {
            self.calls.borrow_mut().push("verify-published");
            Ok(())
        }
    }

    #[test]
    fn restore_new_target_orders_preflight_before_publish_and_cleans_failure() {
        let calls = Rc::new(RefCell::new(Vec::new()));
        let mut extractor = Extractor {
            calls: Rc::clone(&calls),
        };
        let mut preflight = Preflight {
            calls: Rc::clone(&calls),
            fail: false,
        };
        let mut publisher = Publisher {
            calls: Rc::clone(&calls),
        };
        let mut ids = Ids(0);
        let mut logs = Logs::default();
        let mut provenance = Provenance::default();
        let receipt = RestoreBackupUseCase::new(
            &Lock,
            &mut extractor,
            &mut preflight,
            &mut publisher,
            &mut provenance,
            &Time,
            &mut ids,
            &mut logs,
            BackupLimits::schema_v1(),
        )
        .execute(RestoreBackupInput {
            passphrase: SensitiveString::new("must-not-appear").unwrap(),
        })
        .unwrap();
        assert_eq!(receipt.commit_mode, "new_target");
        assert_eq!(provenance.0.len(), 1);
        assert_eq!(
            provenance.0[0].action,
            AuditAction::MaintenanceRestoreImported
        );
        assert_eq!(
            provenance.0[0].context.operation_id.as_str(),
            receipt.operation_id
        );
        assert_eq!(
            *calls.borrow(),
            vec![
                "extract",
                "config",
                "certificates",
                "secrets",
                "audit",
                "runtime",
                "prepare",
                "publish",
                "verify-published"
            ]
        );
        assert!(logs
            .0
            .iter()
            .flat_map(|event| &event.fields)
            .all(|(_, value)| !value.contains("must-not-appear")));

        calls.borrow_mut().clear();
        let mut extractor = Extractor {
            calls: Rc::clone(&calls),
        };
        let mut preflight = Preflight {
            calls: Rc::clone(&calls),
            fail: true,
        };
        let mut publisher = Publisher {
            calls: Rc::clone(&calls),
        };
        let error = RestoreBackupUseCase::new(
            &Lock,
            &mut extractor,
            &mut preflight,
            &mut publisher,
            &mut Provenance::default(),
            &Time,
            &mut Ids(0),
            &mut Logs::default(),
            BackupLimits::schema_v1(),
        )
        .execute(RestoreBackupInput {
            passphrase: SensitiveString::new("secret").unwrap(),
        })
        .unwrap_err();
        assert_eq!(error.code, ErrorCode::RestoreCertificateInvalid);
        assert_eq!(
            *calls.borrow(),
            vec!["extract", "config", "certificates", "cleanup"]
        );
    }

    #[test]
    fn verify_backup_returns_safe_report_and_rejects_record_digest_mismatch() {
        let mut reader = Reader(Some(verified_archive()));
        let mut ids = Ids(0);
        let mut logs = Logs::default();
        let report = VerifyBackupUseCase::new(
            &mut reader,
            &Digester,
            &Time,
            &mut ids,
            &mut logs,
            BackupLimits::schema_v1(),
        )
        .execute(VerifyBackupInput {
            passphrase: SensitiveString::new("must-not-appear").unwrap(),
        })
        .unwrap();
        assert_eq!(report.archive_id, "archive-1");
        assert_eq!(report.artifact_count, 2);
        assert!(logs
            .0
            .iter()
            .flat_map(|event| &event.fields)
            .all(|(_, value)| !value.contains("must-not-appear")));

        let mut archive = verified_archive();
        archive.records[1].sha256 = [9; 32];
        let mut reader = Reader(Some(archive));
        let error = VerifyBackupUseCase::new(
            &mut reader,
            &Digester,
            &Time,
            &mut Ids(0),
            &mut Logs::default(),
            BackupLimits::schema_v1(),
        )
        .execute(VerifyBackupInput {
            passphrase: SensitiveString::new("secret").unwrap(),
        })
        .unwrap_err();
        assert_eq!(error.code, ErrorCode::BackupDigestMismatch);
    }

    #[test]
    fn create_backup_streams_validated_inventory_and_publishes_after_sync() {
        let mut source = Source {
            inventory: test_inventory(),
            payloads: vec![b"one".to_vec(), b"four".to_vec()],
            reads: 0,
        };
        let mut writer = Writer::default();
        let mut ids = Ids(0);
        let mut logs = Logs::default();
        let receipt = CreateBackupUseCase::new(
            &Lock,
            &mut source,
            &Digester,
            &mut writer,
            &Time,
            &mut ids,
            &mut logs,
            BackupLimits::schema_v1(),
        )
        .execute(CreateBackupInput {
            source_app_version: "0.1.0".to_string(),
            destination_identity: "edge.age".to_string(),
            passphrase: SensitiveString::new("test passphrase").unwrap(),
        })
        .unwrap();
        assert_eq!(
            writer.calls,
            vec!["open", "record", "record", "finalize", "sync", "publish"]
        );
        assert_eq!(receipt.operation_id, "id-1");
        assert_eq!(receipt.archive_id, "id-2");
        assert_eq!(receipt.artifact_count, 2);
        assert_eq!(receipt.encrypted_bytes, 512);
        assert_eq!(
            logs.0
                .iter()
                .map(|event| event.event.as_str())
                .collect::<Vec<_>>(),
            vec!["backup.create.started", "backup.create.succeeded"]
        );
        assert!(logs
            .0
            .iter()
            .flat_map(|event| &event.fields)
            .all(|(_, value)| !value.contains("passphrase")));
    }

    #[test]
    fn create_backup_failure_cleans_up_and_emits_only_stable_error_fields() {
        let mut source = Source {
            inventory: test_inventory(),
            payloads: vec![b"one".to_vec(), b"four".to_vec()],
            reads: 0,
        };
        let mut writer = Writer {
            fail_at: Some("sync"),
            ..Writer::default()
        };
        let mut ids = Ids(0);
        let mut logs = Logs::default();
        let error = CreateBackupUseCase::new(
            &Lock,
            &mut source,
            &Digester,
            &mut writer,
            &Time,
            &mut ids,
            &mut logs,
            BackupLimits::schema_v1(),
        )
        .execute(CreateBackupInput {
            source_app_version: "0.1.0".to_string(),
            destination_identity: "edge.age".to_string(),
            passphrase: SensitiveString::new("must-not-appear").unwrap(),
        })
        .unwrap_err();

        assert_eq!(error.code, ErrorCode::BackupWriteFailed);
        assert_eq!(writer.calls.last(), Some(&"cleanup"));
        let failed = logs.0.last().unwrap();
        assert_eq!(failed.event, "backup.create.failed");
        assert_eq!(
            failed.fields,
            vec![
                ("operation_id".to_string(), "id-1".to_string()),
                ("error_code".to_string(), "BACKUP_WRITE_FAILED".to_string())
            ]
        );
    }

    #[test]
    fn create_backup_lock_failure_is_terminal_and_emits_stable_failure() {
        let mut source = Source {
            inventory: test_inventory(),
            payloads: vec![],
            reads: 0,
        };
        let mut writer = Writer::default();
        let mut ids = Ids(0);
        let mut logs = Logs::default();

        let error = CreateBackupUseCase::new(
            &BusyLock,
            &mut source,
            &Digester,
            &mut writer,
            &Time,
            &mut ids,
            &mut logs,
            BackupLimits::schema_v1(),
        )
        .execute(CreateBackupInput {
            source_app_version: "0.1.0".to_string(),
            destination_identity: "edge.age".to_string(),
            passphrase: SensitiveString::new("must-not-appear").unwrap(),
        })
        .unwrap_err();

        assert_eq!(error.code, ErrorCode::DataDirectoryBusy);
        assert_eq!(writer.calls, vec!["cleanup"]);
        assert_eq!(logs.0.last().unwrap().event, "backup.create.failed");
        assert_eq!(
            logs.0.last().unwrap().fields[1],
            ("error_code".to_string(), "DATA_DIRECTORY_BUSY".to_string())
        );
    }

    #[test]
    fn committed_backup_remains_success_when_success_log_sink_fails() {
        let mut source = Source {
            inventory: test_inventory(),
            payloads: vec![b"one".to_vec(), b"four".to_vec()],
            reads: 0,
        };
        let mut writer = Writer::default();
        let mut ids = Ids(0);
        let mut logs = FailSuccessLog::default();

        let receipt = CreateBackupUseCase::new(
            &Lock,
            &mut source,
            &Digester,
            &mut writer,
            &Time,
            &mut ids,
            &mut logs,
            BackupLimits::schema_v1(),
        )
        .execute(CreateBackupInput {
            source_app_version: "0.1.0".to_string(),
            destination_identity: "edge.age".to_string(),
            passphrase: SensitiveString::new("test passphrase").unwrap(),
        })
        .unwrap();

        assert_eq!(receipt.archive_id, "id-2");
        assert_eq!(writer.calls.last(), Some(&"publish"));
        assert!(!writer.calls.contains(&"cleanup"));
    }
}
