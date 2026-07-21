use crate::{AppError, ErrorCode};
use std::collections::BTreeSet;
use std::fmt;
use zeroize::{Zeroize, Zeroizing};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum BackupArtifactKind {
    ConfigRevision,
    ConfigRevisionPointer,
    CertificateChain,
    CertificatePrivateKey,
    CertificateMetadata,
    TrustBundleRoots,
    TrustBundleMetadata,
    AdminPasswordHash,
    AuditLedgerSegment,
    Unknown(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackupArtifactMode {
    Public,
    OwnerOnly,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupArtifactDescriptor {
    pub kind: BackupArtifactKind,
    pub logical_id: String,
    pub relative_logical_path: String,
    pub length_bytes: u64,
    pub sha256: [u8; 32],
    pub mode: BackupArtifactMode,
    pub required_for_restore: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupManifest {
    pub schema_version: u32,
    pub archive_id: String,
    pub created_at_epoch_seconds: u64,
    pub source_app_version: String,
    pub source_layout_version: u32,
    pub current_revision_id: String,
    pub admin_initialized: bool,
    pub referenced_certificate_refs: Vec<String>,
    pub referenced_trust_bundle_refs: Vec<String>,
    pub artifact_count: u32,
    pub total_plaintext_bytes: u64,
    pub artifacts: Vec<BackupArtifactDescriptor>,
    pub manifest_digest: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackupLimits {
    pub max_schema_version: u32,
    pub max_artifacts: u32,
    pub max_total_plaintext_bytes: u64,
    pub max_single_artifact_bytes: u64,
    pub max_config_or_secret_bytes: u64,
    pub max_logical_path_bytes: usize,
    pub max_manifest_bytes: u64,
    pub max_nesting_depth: usize,
    pub max_audit_segments: u16,
    pub max_audit_segment_bytes: u64,
    pub max_audit_total_bytes: u64,
}

impl BackupLimits {
    pub const fn schema_v1() -> Self {
        Self {
            max_schema_version: 1,
            max_artifacts: 10_000,
            max_total_plaintext_bytes: 1024 * 1024 * 1024,
            max_single_artifact_bytes: 64 * 1024 * 1024,
            max_config_or_secret_bytes: 1024 * 1024,
            max_logical_path_bytes: 240,
            max_manifest_bytes: 8 * 1024 * 1024,
            max_nesting_depth: 8,
            max_audit_segments: 32,
            max_audit_segment_bytes: 4 * 1024 * 1024,
            max_audit_total_bytes: 128 * 1024 * 1024,
        }
    }

    pub const fn schema_v2() -> Self {
        Self {
            max_schema_version: 2,
            ..Self::schema_v1()
        }
    }

    pub const fn schema_v3() -> Self {
        Self {
            max_schema_version: 3,
            ..Self::schema_v1()
        }
    }
}

impl BackupManifest {
    pub fn validate(&self, limits: &BackupLimits) -> Result<(), AppError> {
        if !(1..=3).contains(&self.schema_version)
            || self.schema_version > limits.max_schema_version
            || self.source_layout_version != 1
        {
            return Err(error(ErrorCode::BackupSchemaUnsupported));
        }
        validate_identity(&self.archive_id)?;
        validate_identity(&self.current_revision_id)?;
        if self.source_app_version.is_empty()
            || self.artifact_count as usize != self.artifacts.len()
        {
            return Err(error(ErrorCode::BackupManifestInvalid));
        }
        if self.artifact_count > limits.max_artifacts {
            return Err(error(ErrorCode::BackupLimitExceeded));
        }
        let mut paths = BTreeSet::new();
        let mut identities = BTreeSet::new();
        let mut total = 0_u64;
        let mut pointers = 0;
        let mut current_found = false;
        let mut admin_hashes = 0;
        let mut chains = BTreeSet::new();
        let mut keys = BTreeSet::new();
        let mut metadata = BTreeSet::new();
        let mut trust_roots = BTreeSet::new();
        let mut trust_metadata = BTreeSet::new();
        let mut audit_segments = Vec::new();
        let mut audit_total = 0_u64;

        if self
            .artifacts
            .windows(2)
            .any(|items| items[0].relative_logical_path >= items[1].relative_logical_path)
        {
            return Err(error(ErrorCode::BackupManifestInvalid));
        }
        for artifact in &self.artifacts {
            validate_logical_path(&artifact.relative_logical_path, limits)?;
            validate_identity(&artifact.logical_id)?;
            validate_kind_path(artifact)?;
            if !paths.insert(artifact.relative_logical_path.as_str())
                || !identities.insert((&artifact.kind, artifact.logical_id.as_str()))
                || !artifact.required_for_restore
            {
                return Err(error(ErrorCode::BackupManifestInvalid));
            }
            validate_mode(artifact)?;
            if artifact.length_bytes > limits.max_single_artifact_bytes
                || (is_config_or_secret(&artifact.kind)
                    && artifact.length_bytes > limits.max_config_or_secret_bytes)
            {
                return Err(error(ErrorCode::BackupLimitExceeded));
            }
            total = total
                .checked_add(artifact.length_bytes)
                .ok_or_else(|| error(ErrorCode::BackupLimitExceeded))?;
            if total > limits.max_total_plaintext_bytes {
                return Err(error(ErrorCode::BackupLimitExceeded));
            }
            match &artifact.kind {
                BackupArtifactKind::ConfigRevisionPointer => pointers += 1,
                BackupArtifactKind::ConfigRevision
                    if artifact.logical_id == self.current_revision_id =>
                {
                    current_found = true
                }
                BackupArtifactKind::CertificateChain => {
                    chains.insert(artifact.logical_id.as_str());
                }
                BackupArtifactKind::CertificatePrivateKey => {
                    keys.insert(artifact.logical_id.as_str());
                }
                BackupArtifactKind::CertificateMetadata => {
                    metadata.insert(artifact.logical_id.as_str());
                }
                BackupArtifactKind::TrustBundleRoots => {
                    trust_roots.insert(artifact.logical_id.as_str());
                }
                BackupArtifactKind::TrustBundleMetadata => {
                    trust_metadata.insert(artifact.logical_id.as_str());
                }
                BackupArtifactKind::AdminPasswordHash => admin_hashes += 1,
                BackupArtifactKind::AuditLedgerSegment => {
                    let number = artifact
                        .logical_id
                        .parse::<u64>()
                        .map_err(|_| error(ErrorCode::BackupManifestInvalid))?;
                    if number == 0
                        || artifact.logical_id.len() != 16
                        || artifact.length_bytes > limits.max_audit_segment_bytes
                    {
                        return Err(error(ErrorCode::BackupLimitExceeded));
                    }
                    audit_total = audit_total
                        .checked_add(artifact.length_bytes)
                        .ok_or_else(|| error(ErrorCode::BackupLimitExceeded))?;
                    audit_segments.push(number);
                }
                BackupArtifactKind::Unknown(_) => {
                    return Err(error(ErrorCode::BackupManifestInvalid))
                }
                _ => {}
            }
        }
        if total != self.total_plaintext_bytes
            || pointers != 1
            || !current_found
            || (self.admin_initialized && admin_hashes != 1)
            || (!self.admin_initialized && admin_hashes != 0)
            || chains != keys
            || chains != metadata
            || trust_roots != trust_metadata
            || audit_segments.len() > limits.max_audit_segments as usize
            || audit_total > limits.max_audit_total_bytes
            || audit_segments
                .windows(2)
                .any(|items| items[0].checked_add(1) != Some(items[1]))
            || (self.schema_version == 1
                && (!trust_roots.is_empty() || !self.referenced_trust_bundle_refs.is_empty()))
            || (self.schema_version < 3 && !audit_segments.is_empty())
        {
            return Err(error(ErrorCode::BackupManifestInvalid));
        }
        let mut referenced = BTreeSet::new();
        for certificate_ref in &self.referenced_certificate_refs {
            validate_identity(certificate_ref)?;
            if !referenced.insert(certificate_ref.as_str())
                || !chains.contains(certificate_ref.as_str())
            {
                return Err(error(ErrorCode::BackupManifestInvalid));
            }
        }
        let mut referenced_trust = BTreeSet::new();
        for trust_bundle_ref in &self.referenced_trust_bundle_refs {
            validate_identity(trust_bundle_ref)?;
            if !referenced_trust.insert(trust_bundle_ref.as_str())
                || !trust_roots.contains(trust_bundle_ref.as_str())
            {
                return Err(error(ErrorCode::BackupManifestInvalid));
            }
        }
        Ok(())
    }
}

pub fn validate_manifest_encoded_size(
    length_bytes: u64,
    limits: &BackupLimits,
) -> Result<(), AppError> {
    if length_bytes > limits.max_manifest_bytes {
        return Err(error(ErrorCode::BackupLimitExceeded));
    }
    Ok(())
}

fn validate_logical_path(path: &str, limits: &BackupLimits) -> Result<(), AppError> {
    if path.len() > limits.max_logical_path_bytes {
        return Err(error(ErrorCode::BackupLimitExceeded));
    }
    if path.is_empty() || path.starts_with('/') || path.contains(['\\', '\0', ':']) {
        return Err(error(ErrorCode::BackupManifestInvalid));
    }
    let segments = path.split('/').collect::<Vec<_>>();
    if segments.len() > limits.max_nesting_depth {
        return Err(error(ErrorCode::BackupLimitExceeded));
    }
    if segments
        .iter()
        .any(|segment| segment.is_empty() || *segment == "." || *segment == "..")
    {
        return Err(error(ErrorCode::BackupManifestInvalid));
    }
    Ok(())
}

fn validate_identity(value: &str) -> Result<(), AppError> {
    if value.is_empty()
        || value.len() > 240
        || value.contains(['/', '\\', '\0', ':'])
        || value == "."
        || value == ".."
    {
        return Err(error(ErrorCode::BackupManifestInvalid));
    }
    Ok(())
}

fn validate_mode(artifact: &BackupArtifactDescriptor) -> Result<(), AppError> {
    let expected = match artifact.kind {
        BackupArtifactKind::CertificatePrivateKey | BackupArtifactKind::AdminPasswordHash => {
            BackupArtifactMode::OwnerOnly
        }
        BackupArtifactKind::AuditLedgerSegment => BackupArtifactMode::Public,
        BackupArtifactKind::Unknown(_) => return Err(error(ErrorCode::BackupManifestInvalid)),
        _ => BackupArtifactMode::Public,
    };
    if artifact.mode != expected {
        return Err(error(ErrorCode::BackupManifestInvalid));
    }
    Ok(())
}

fn validate_kind_path(artifact: &BackupArtifactDescriptor) -> Result<(), AppError> {
    if matches!(artifact.kind, BackupArtifactKind::ConfigRevisionPointer)
        && artifact.logical_id != "current"
    {
        return Err(error(ErrorCode::BackupManifestInvalid));
    }
    if matches!(artifact.kind, BackupArtifactKind::AdminPasswordHash)
        && artifact.logical_id != "admin-password-hash"
    {
        return Err(error(ErrorCode::BackupManifestInvalid));
    }
    let expected = match artifact.kind {
        BackupArtifactKind::ConfigRevision => format!("config/revisions/{}", artifact.logical_id),
        BackupArtifactKind::ConfigRevisionPointer => "config/current".to_string(),
        BackupArtifactKind::CertificateChain => {
            format!("certificates/{}/chain", artifact.logical_id)
        }
        BackupArtifactKind::CertificatePrivateKey => {
            format!("certificates/{}/private-key", artifact.logical_id)
        }
        BackupArtifactKind::CertificateMetadata => {
            format!("certificates/{}/metadata", artifact.logical_id)
        }
        BackupArtifactKind::TrustBundleRoots => {
            format!("trust-bundles/{}/roots", artifact.logical_id)
        }
        BackupArtifactKind::TrustBundleMetadata => {
            format!("trust-bundles/{}/metadata", artifact.logical_id)
        }
        BackupArtifactKind::AdminPasswordHash => "secrets/admin-password-hash".to_string(),
        BackupArtifactKind::AuditLedgerSegment => {
            format!("audit/segments/{}", artifact.logical_id)
        }
        BackupArtifactKind::Unknown(_) => return Err(error(ErrorCode::BackupManifestInvalid)),
    };
    if artifact.relative_logical_path != expected {
        return Err(error(ErrorCode::BackupManifestInvalid));
    }
    Ok(())
}

fn is_config_or_secret(kind: &BackupArtifactKind) -> bool {
    !matches!(
        kind,
        BackupArtifactKind::CertificateChain
            | BackupArtifactKind::TrustBundleRoots
            | BackupArtifactKind::AuditLedgerSegment
    )
}
fn error(code: ErrorCode) -> AppError {
    AppError::new(code, code.default_user_message())
}

pub struct SensitiveString(Zeroizing<String>);
impl SensitiveString {
    pub const MAX_BYTES: usize = 4096;
    pub fn new(value: impl Into<String>) -> Result<Self, AppError> {
        let value = value.into();
        if value.is_empty() || value.len() > Self::MAX_BYTES {
            return Err(error(ErrorCode::BackupSecretInputInvalid));
        }
        Ok(Self(Zeroizing::new(value)))
    }
    pub fn from_utf8(bytes: Vec<u8>) -> Result<Self, AppError> {
        match String::from_utf8(bytes) {
            Ok(value) => Self::new(value),
            Err(error_value) => {
                let mut bytes = error_value.into_bytes();
                bytes.zeroize();
                Err(error(ErrorCode::BackupSecretInputInvalid))
            }
        }
    }
    pub fn expose<T>(&self, operation: impl FnOnce(&str) -> T) -> T {
        operation(self.0.as_str())
    }
}
impl fmt::Debug for SensitiveString {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SensitiveString(<redacted>)")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BackupState {
    #[default]
    Idle,
    Locking,
    Inventorying,
    Validating,
    OpeningEncryptedEnvelope,
    StreamingEncryptedRecords,
    FinalizingEnvelope,
    Syncing,
    Publishing,
    Completed,
    CleaningUp {
        error_code: ErrorCode,
    },
    Failed {
        error_code: ErrorCode,
    },
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackupEvent {
    Start,
    LockAcquired,
    InventoryBuilt,
    InventoryValidated,
    EnvelopeOpened,
    EncryptedRecordWritten,
    EnvelopeAuthenticated,
    EnvelopeFinalized,
    FileSynced,
    RenameCommitted,
    OperationFailed(ErrorCode),
    CleanupFinished,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct BackupStateMachine {
    state: BackupState,
}
impl BackupStateMachine {
    pub fn state(&self) -> BackupState {
        self.state
    }
    pub fn transition(&mut self, event_value: BackupEvent) -> Result<(), AppError> {
        let next = match (self.state, event_value) {
            (BackupState::Idle, BackupEvent::Start) => BackupState::Locking,
            (BackupState::Locking, BackupEvent::LockAcquired) => BackupState::Inventorying,
            (BackupState::Inventorying, BackupEvent::InventoryBuilt) => BackupState::Validating,
            (BackupState::Validating, BackupEvent::InventoryValidated) => {
                BackupState::OpeningEncryptedEnvelope
            }
            (BackupState::OpeningEncryptedEnvelope, BackupEvent::EnvelopeOpened) => {
                BackupState::StreamingEncryptedRecords
            }
            (BackupState::StreamingEncryptedRecords, BackupEvent::EncryptedRecordWritten) => {
                BackupState::StreamingEncryptedRecords
            }
            (BackupState::StreamingEncryptedRecords, BackupEvent::EnvelopeAuthenticated) => {
                BackupState::FinalizingEnvelope
            }
            (BackupState::FinalizingEnvelope, BackupEvent::EnvelopeFinalized) => {
                BackupState::Syncing
            }
            (BackupState::Syncing, BackupEvent::FileSynced) => BackupState::Publishing,
            (BackupState::Publishing, BackupEvent::RenameCommitted) => BackupState::Completed,
            (state, BackupEvent::OperationFailed(error_code))
                if !matches!(
                    state,
                    BackupState::Completed
                        | BackupState::Failed { .. }
                        | BackupState::CleaningUp { .. }
                ) =>
            {
                BackupState::CleaningUp { error_code }
            }
            (BackupState::CleaningUp { error_code }, BackupEvent::CleanupFinished) => {
                BackupState::Failed { error_code }
            }
            _ => return Err(error(ErrorCode::BackupStateTransitionInvalid)),
        };
        self.state = next;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RestoreState {
    #[default]
    Idle,
    Locking,
    Opening,
    Authenticating,
    ReadingManifest,
    ExtractingStage,
    VerifyingArtifacts,
    ValidatingConfig,
    ValidatingCertificates,
    ValidatingSecrets,
    ValidatingAudit,
    PreflightingRuntime,
    PreparingCommit,
    WritingTransaction,
    Committing,
    VerifyingPublishedTarget,
    RecordingProvenance,
    Completed,
    AuditDegradedCommitted {
        error_code: ErrorCode,
    },
    RollingBack {
        error_code: ErrorCode,
    },
    RecoveringInterruptedCommit,
    CleaningUp {
        error_code: ErrorCode,
    },
    Failed {
        error_code: ErrorCode,
    },
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestoreEvent {
    Start,
    RecoveryRequested,
    LockAcquired,
    EnvelopeOpened,
    EnvelopeAuthenticated,
    ManifestRead,
    StageCreated,
    StageExtracted,
    ArtifactsVerified,
    ConfigValidated,
    CertificatesValidated,
    SecretsValidated,
    AuditValidated,
    RuntimePreflighted,
    CommitPrepared,
    NewTargetCommitPrepared,
    TransactionPersisted,
    TargetMovedToRollback,
    StagePublished,
    PublishedTargetVerified,
    ProvenancePersisted,
    ProvenanceNotRequired,
    ProvenanceAppendFailed(ErrorCode),
    RollbackRequested(ErrorCode),
    RollbackRestored,
    InterruptedTransactionRecovered,
    OperationFailed(ErrorCode),
    CleanupFinished,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RestoreStateMachine {
    state: RestoreState,
}
impl RestoreStateMachine {
    pub fn state(&self) -> RestoreState {
        self.state
    }
    pub fn transition(&mut self, event_value: RestoreEvent) -> Result<(), AppError> {
        let next = match (self.state, event_value) {
            (RestoreState::Idle, RestoreEvent::Start) => RestoreState::Locking,
            (RestoreState::Idle, RestoreEvent::RecoveryRequested) => {
                RestoreState::RecoveringInterruptedCommit
            }
            (RestoreState::Locking, RestoreEvent::LockAcquired) => RestoreState::Opening,
            (RestoreState::Opening, RestoreEvent::EnvelopeOpened) => RestoreState::Authenticating,
            (RestoreState::Authenticating, RestoreEvent::EnvelopeAuthenticated) => {
                RestoreState::ReadingManifest
            }
            (RestoreState::ReadingManifest, RestoreEvent::ManifestRead) => {
                RestoreState::ExtractingStage
            }
            (RestoreState::ExtractingStage, RestoreEvent::StageCreated) => {
                RestoreState::ExtractingStage
            }
            (RestoreState::ExtractingStage, RestoreEvent::StageExtracted) => {
                RestoreState::VerifyingArtifacts
            }
            (RestoreState::VerifyingArtifacts, RestoreEvent::ArtifactsVerified) => {
                RestoreState::ValidatingConfig
            }
            (RestoreState::ValidatingConfig, RestoreEvent::ConfigValidated) => {
                RestoreState::ValidatingCertificates
            }
            (RestoreState::ValidatingCertificates, RestoreEvent::CertificatesValidated) => {
                RestoreState::ValidatingSecrets
            }
            (RestoreState::ValidatingSecrets, RestoreEvent::SecretsValidated) => {
                RestoreState::ValidatingAudit
            }
            (RestoreState::ValidatingAudit, RestoreEvent::AuditValidated) => {
                RestoreState::PreflightingRuntime
            }
            (RestoreState::PreflightingRuntime, RestoreEvent::RuntimePreflighted) => {
                RestoreState::PreparingCommit
            }
            (RestoreState::PreparingCommit, RestoreEvent::NewTargetCommitPrepared) => {
                RestoreState::Committing
            }
            (RestoreState::PreparingCommit, RestoreEvent::CommitPrepared) => {
                RestoreState::WritingTransaction
            }
            (RestoreState::WritingTransaction, RestoreEvent::TransactionPersisted) => {
                RestoreState::Committing
            }
            (RestoreState::Committing, RestoreEvent::TargetMovedToRollback) => {
                RestoreState::Committing
            }
            (RestoreState::Committing, RestoreEvent::StagePublished) => {
                RestoreState::VerifyingPublishedTarget
            }
            (RestoreState::VerifyingPublishedTarget, RestoreEvent::PublishedTargetVerified) => {
                RestoreState::RecordingProvenance
            }
            (RestoreState::RecordingProvenance, RestoreEvent::ProvenancePersisted) => {
                RestoreState::Completed
            }
            (RestoreState::RecordingProvenance, RestoreEvent::ProvenanceNotRequired) => {
                RestoreState::Completed
            }
            (
                RestoreState::RecordingProvenance,
                RestoreEvent::ProvenanceAppendFailed(error_code),
            ) => RestoreState::AuditDegradedCommitted { error_code },
            (RestoreState::Committing, RestoreEvent::RollbackRequested(error_code)) => {
                RestoreState::RollingBack { error_code }
            }
            (RestoreState::RollingBack { error_code }, RestoreEvent::RollbackRestored) => {
                RestoreState::CleaningUp { error_code }
            }
            (
                RestoreState::RecoveringInterruptedCommit,
                RestoreEvent::InterruptedTransactionRecovered,
            ) => RestoreState::VerifyingPublishedTarget,
            (state, RestoreEvent::OperationFailed(error_code))
                if !matches!(
                    state,
                    RestoreState::Completed
                        | RestoreState::AuditDegradedCommitted { .. }
                        | RestoreState::Failed { .. }
                        | RestoreState::CleaningUp { .. }
                ) =>
            {
                RestoreState::CleaningUp { error_code }
            }
            (RestoreState::CleaningUp { error_code }, RestoreEvent::CleanupFinished) => {
                RestoreState::Failed { error_code }
            }
            _ => return Err(error(ErrorCode::RestoreStateTransitionInvalid)),
        };
        self.state = next;
        Ok(())
    }
}
