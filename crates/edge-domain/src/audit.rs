use std::fmt;

pub const AUDIT_IDENTIFIER_MAX_BYTES: usize = 128;
pub const AUDIT_QUERY_DEFAULT_LIMIT: u16 = 50;
pub const AUDIT_QUERY_MAX_LIMIT: u16 = 100;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditValidationError {
    IdentifierEmpty,
    IdentifierTooLong,
    IdentifierInvalidCharacter,
    QueryLimitInvalid,
    QueryTimeRangeInvalid,
    RecordInvariantInvalid,
    InvalidTransition,
}

impl AuditValidationError {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::IdentifierEmpty => "AUDIT_IDENTIFIER_EMPTY",
            Self::IdentifierTooLong => "AUDIT_IDENTIFIER_TOO_LONG",
            Self::IdentifierInvalidCharacter => "AUDIT_IDENTIFIER_INVALID_CHARACTER",
            Self::QueryLimitInvalid => "AUDIT_QUERY_LIMIT_INVALID",
            Self::QueryTimeRangeInvalid => "AUDIT_QUERY_TIME_RANGE_INVALID",
            Self::RecordInvariantInvalid => "AUDIT_RECORD_INVARIANT_INVALID",
            Self::InvalidTransition => "AUDIT_STATE_TRANSITION_INVALID",
        }
    }
}

impl fmt::Display for AuditValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

fn validate_audit_identifier(value: &str) -> Result<(), AuditValidationError> {
    if value.is_empty() {
        return Err(AuditValidationError::IdentifierEmpty);
    }
    if value.len() > AUDIT_IDENTIFIER_MAX_BYTES {
        return Err(AuditValidationError::IdentifierTooLong);
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        return Err(AuditValidationError::IdentifierInvalidCharacter);
    }
    Ok(())
}

macro_rules! audit_identifier {
    ($name:ident) => {
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(String);

        impl $name {
            pub fn parse(value: impl AsRef<str>) -> Result<Self, AuditValidationError> {
                let value = value.as_ref();
                validate_audit_identifier(value)?;
                Ok(Self(value.to_string()))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }
    };
}

audit_identifier!(AuditOperationId);
audit_identifier!(AuditRequestId);
audit_identifier!(AuditTargetId);
audit_identifier!(AuditStableErrorCode);

macro_rules! stable_enum {
    ($name:ident { $($variant:ident => $value:literal),+ $(,)? }) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub enum $name {
            $($variant),+
        }

        impl $name {
            pub fn as_str(self) -> &'static str {
                match self {
                    $(Self::$variant => $value),+
                }
            }
        }
    };
}

stable_enum!(AuditAction {
    ConfigApply => "config.apply",
    ConfigRollback => "config.rollback",
    ProxyHostCreate => "proxy_host.create",
    ProxyHostUpdate => "proxy_host.update",
    ProxyHostDelete => "proxy_host.delete",
    CertificateIssue => "certificate.issue",
    CertificateRenew => "certificate.renew",
    CertificateImport => "certificate.import",
    CertificateInstall => "certificate.install",
    TrustBundleImport => "trust_bundle.import",
    TrustBundleDelete => "trust_bundle.delete",
    AdminSetup => "admin.setup",
    AdminLoginSuccess => "admin.login.success",
    AdminLogout => "admin.logout",
    AdminLockout => "admin.lockout",
    AdminAuthFailureSampled => "admin.auth.failure_sampled",
    MaintenanceRestoreImported => "maintenance.restore_imported",
    SystemTrailingRecovery => "system.trailing_recovery",
    RetentionCheckpoint => "audit.retention.checkpoint",
});

stable_enum!(AuditOutcome {
    Succeeded => "succeeded",
    Failed => "failed",
    Observed => "observed",
    ReconciledCommitted => "reconciled_committed",
    ReconciledNotCommitted => "reconciled_not_committed",
    ReconciliationUnknown => "reconciliation_unknown",
});

stable_enum!(AuditRecordKind {
    Intent => "intent",
    Terminal => "terminal",
    Reconciliation => "reconciliation",
    SecurityObservation => "security_observation",
    RetentionCheckpoint => "retention_checkpoint",
    SystemRecovery => "system_recovery",
});

stable_enum!(AuditTargetKind {
    ConfigRevision => "config_revision",
    ProxyHost => "proxy_host",
    Certificate => "certificate",
    TrustBundle => "trust_bundle",
    AdminAccount => "admin_account",
    Restore => "restore",
    AuditLedger => "audit_ledger",
});

stable_enum!(AuditActorKind {
    BootstrapSetup => "bootstrap_setup",
    BootstrapAdmin => "bootstrap_admin",
    MaintenanceCli => "maintenance_cli",
    SystemRecovery => "system_recovery",
});

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditContext {
    pub operation_id: AuditOperationId,
    pub request_id: AuditRequestId,
    pub actor_kind: AuditActorKind,
    pub received_at_epoch_seconds: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditRecord {
    pub record_version: u16,
    pub record_kind: AuditRecordKind,
    pub context: AuditContext,
    pub action: AuditAction,
    pub target_kind: AuditTargetKind,
    pub target_id: AuditTargetId,
    pub before_revision: Option<AuditTargetId>,
    pub after_revision: Option<AuditTargetId>,
    pub outcome: Option<AuditOutcome>,
    pub error_code: Option<AuditStableErrorCode>,
}

impl AuditRecord {
    pub fn validate(&self) -> Result<(), AuditValidationError> {
        let valid = match self.record_kind {
            AuditRecordKind::Intent => {
                self.outcome.is_none() && self.error_code.is_none() && self.after_revision.is_none()
            }
            AuditRecordKind::Terminal => matches!(
                (self.outcome, self.error_code.is_some()),
                (Some(AuditOutcome::Succeeded), false) | (Some(AuditOutcome::Failed), true)
            ),
            AuditRecordKind::Reconciliation => matches!(
                self.outcome,
                Some(
                    AuditOutcome::ReconciledCommitted
                        | AuditOutcome::ReconciledNotCommitted
                        | AuditOutcome::ReconciliationUnknown
                )
            ),
            AuditRecordKind::SecurityObservation => {
                self.outcome == Some(AuditOutcome::Observed)
                    && self.target_kind == AuditTargetKind::AdminAccount
                    && self.before_revision.is_none()
                    && self.after_revision.is_none()
                    && self.error_code.is_none()
                    && matches!(
                        self.action,
                        AuditAction::AdminLoginSuccess
                            | AuditAction::AdminLogout
                            | AuditAction::AdminLockout
                            | AuditAction::AdminAuthFailureSampled
                    )
            }
            AuditRecordKind::RetentionCheckpoint => {
                self.action == AuditAction::RetentionCheckpoint
                    && self.target_kind == AuditTargetKind::AuditLedger
                    && self.outcome == Some(AuditOutcome::Succeeded)
            }
            AuditRecordKind::SystemRecovery => {
                self.action == AuditAction::SystemTrailingRecovery
                    && self.target_kind == AuditTargetKind::AuditLedger
                    && self.context.actor_kind == AuditActorKind::SystemRecovery
                    && self.outcome == Some(AuditOutcome::Succeeded)
                    && self.error_code.is_none()
            }
        };
        if self.record_version != 1 || !valid {
            return Err(AuditValidationError::RecordInvariantInvalid);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AuditLedgerHead {
    pub generation: u64,
    pub sequence: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuditCursor {
    pub ledger_generation: u64,
    pub before_sequence: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditRecordView {
    pub sequence: u64,
    pub record: AuditRecord,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditQuery {
    pub action: Option<AuditAction>,
    pub outcome: Option<AuditOutcome>,
    pub target_kind: Option<AuditTargetKind>,
    pub from_epoch_seconds: Option<u64>,
    pub to_epoch_seconds: Option<u64>,
    pub limit: u16,
    pub cursor: Option<AuditCursor>,
}

impl AuditQuery {
    pub fn new(
        action: Option<AuditAction>,
        outcome: Option<AuditOutcome>,
        target_kind: Option<AuditTargetKind>,
        from_epoch_seconds: Option<u64>,
        to_epoch_seconds: Option<u64>,
        limit: u16,
    ) -> Result<Self, AuditValidationError> {
        if limit == 0 || limit > AUDIT_QUERY_MAX_LIMIT {
            return Err(AuditValidationError::QueryLimitInvalid);
        }
        if matches!((from_epoch_seconds, to_epoch_seconds), (Some(from), Some(to)) if from > to) {
            return Err(AuditValidationError::QueryTimeRangeInvalid);
        }
        Ok(Self {
            action,
            outcome,
            target_kind,
            from_epoch_seconds,
            to_epoch_seconds,
            limit,
            cursor: None,
        })
    }

    pub fn with_cursor(mut self, cursor: AuditCursor) -> Self {
        self.cursor = Some(cursor);
        self
    }
}

impl Default for AuditQuery {
    fn default() -> Self {
        Self::new(None, None, None, None, None, AUDIT_QUERY_DEFAULT_LIMIT)
            .expect("default audit query must be valid")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditPage {
    pub records: Vec<AuditRecordView>,
    pub next_cursor: Option<AuditCursor>,
    pub head: AuditLedgerHead,
    pub admission_state: AuditAdmissionState,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditVerificationReport {
    pub head: AuditLedgerHead,
    pub record_count: u64,
    pub segment_count: u16,
    pub incomplete_operation_count: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditAuthoritativeFact {
    Committed,
    NotCommitted,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditOperationClass {
    PersistentMutation,
    EphemeralSecurityObservation,
    ReadOnly,
    OfflineRestore,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditEffectState {
    Committed,
    Rejected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditOperationState {
    Received,
    IntentPersisting,
    IntentPersisted,
    EffectRunning,
    EffectCommitted,
    EffectRejected,
    TerminalPersisting(AuditEffectState),
    Completed,
    RejectedNoEffect,
    AuditDegradedCommitted,
    AuditDegradedRejected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditOperationEvent {
    BeginIntent,
    IntentPersisted,
    IntentAppendFailed,
    BeginEffect,
    EffectCommitted,
    EffectRejected,
    BeginTerminal,
    TerminalPersisted,
    TerminalAppendFailed,
}

impl AuditOperationState {
    pub fn transition(self, event: AuditOperationEvent) -> Result<Self, AuditValidationError> {
        use AuditOperationEvent as Event;
        use AuditOperationState as State;
        match (self, event) {
            (State::Received, Event::BeginIntent) => Ok(State::IntentPersisting),
            (State::IntentPersisting, Event::IntentPersisted) => Ok(State::IntentPersisted),
            (State::IntentPersisting, Event::IntentAppendFailed) => Ok(State::RejectedNoEffect),
            (State::IntentPersisted, Event::BeginEffect) => Ok(State::EffectRunning),
            (State::EffectRunning, Event::EffectCommitted) => Ok(State::EffectCommitted),
            (State::EffectRunning, Event::EffectRejected) => Ok(State::EffectRejected),
            (State::EffectCommitted, Event::BeginTerminal) => {
                Ok(State::TerminalPersisting(AuditEffectState::Committed))
            }
            (State::EffectRejected, Event::BeginTerminal) => {
                Ok(State::TerminalPersisting(AuditEffectState::Rejected))
            }
            (State::TerminalPersisting(_), Event::TerminalPersisted) => Ok(State::Completed),
            (
                State::TerminalPersisting(AuditEffectState::Committed),
                Event::TerminalAppendFailed,
            ) => Ok(State::AuditDegradedCommitted),
            (
                State::TerminalPersisting(AuditEffectState::Rejected),
                Event::TerminalAppendFailed,
            ) => Ok(State::AuditDegradedRejected),
            _ => Err(AuditValidationError::InvalidTransition),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AuditAdmissionState {
    #[default]
    Starting,
    Verifying,
    Reconciling,
    Healthy,
    Degraded,
    FailedClosed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditAdmissionEvent {
    BeginVerification,
    VerificationPassed,
    IncompleteOperationsFound,
    VerificationFailed,
    AppendFailed,
    BeginReconciliation,
    ReconciliationCompleted,
    ReconciliationUnknown,
}

impl AuditAdmissionState {
    pub fn transition(self, event: AuditAdmissionEvent) -> Result<Self, AuditValidationError> {
        use AuditAdmissionEvent as Event;
        use AuditAdmissionState as State;
        match (self, event) {
            (State::Starting, Event::BeginVerification) => Ok(State::Verifying),
            (State::Verifying, Event::VerificationPassed) => Ok(State::Healthy),
            (State::Verifying, Event::IncompleteOperationsFound) => Ok(State::Reconciling),
            (State::Verifying, Event::VerificationFailed) => Ok(State::FailedClosed),
            (State::Healthy, Event::AppendFailed) => Ok(State::Degraded),
            (State::Degraded, Event::BeginReconciliation) => Ok(State::Reconciling),
            (State::Reconciling, Event::ReconciliationCompleted) => Ok(State::Healthy),
            (State::Reconciling, Event::ReconciliationUnknown) => Ok(State::FailedClosed),
            _ => Err(AuditValidationError::InvalidTransition),
        }
    }

    pub fn allows(self, operation: AuditOperationClass) -> bool {
        match operation {
            AuditOperationClass::PersistentMutation => self == Self::Healthy,
            AuditOperationClass::EphemeralSecurityObservation => true,
            AuditOperationClass::ReadOnly => true,
            AuditOperationClass::OfflineRestore => false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditReconciliationState {
    IncompleteIntent,
    Inspecting,
    Committed,
    NotCommitted,
    Unknown,
    Closed,
    MutationBlocked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditReconciliationEvent {
    BeginInspection,
    FoundCommitted,
    FoundNotCommitted,
    FactsUnknown,
    ReconciliationPersisted,
    UnknownPersisted,
}

impl AuditReconciliationState {
    pub fn transition(self, event: AuditReconciliationEvent) -> Result<Self, AuditValidationError> {
        use AuditReconciliationEvent as Event;
        use AuditReconciliationState as State;
        match (self, event) {
            (State::IncompleteIntent, Event::BeginInspection) => Ok(State::Inspecting),
            (State::Inspecting, Event::FoundCommitted) => Ok(State::Committed),
            (State::Inspecting, Event::FoundNotCommitted) => Ok(State::NotCommitted),
            (State::Inspecting, Event::FactsUnknown) => Ok(State::Unknown),
            (State::Committed | State::NotCommitted, Event::ReconciliationPersisted) => {
                Ok(State::Closed)
            }
            (State::Unknown, Event::UnknownPersisted) => Ok(State::MutationBlocked),
            _ => Err(AuditValidationError::InvalidTransition),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_identifier_enforces_ascii_and_128_byte_bound() {
        assert!(AuditOperationId::parse("operation-1").is_ok());
        assert!(AuditOperationId::parse("").is_err());
        assert!(AuditOperationId::parse("한글").is_err());
        assert!(AuditOperationId::parse("a".repeat(128)).is_ok());
        assert!(AuditOperationId::parse("a".repeat(129)).is_err());
    }

    #[test]
    fn audit_query_enforces_page_and_time_bounds() {
        assert!(AuditQuery::new(None, None, None, None, None, 1).is_ok());
        assert!(AuditQuery::new(None, None, None, None, None, 100).is_ok());
        assert!(AuditQuery::new(None, None, None, None, None, 0).is_err());
        assert!(AuditQuery::new(None, None, None, None, None, 101).is_err());
        assert!(AuditQuery::new(None, None, None, Some(20), Some(10), 50).is_err());
    }

    #[test]
    fn persistent_operation_requires_durable_intent_before_effect() {
        let state = AuditOperationState::Received
            .transition(AuditOperationEvent::BeginIntent)
            .unwrap()
            .transition(AuditOperationEvent::IntentPersisted)
            .unwrap()
            .transition(AuditOperationEvent::BeginEffect)
            .unwrap();

        assert_eq!(state, AuditOperationState::EffectRunning);
        assert!(AuditOperationState::Received
            .transition(AuditOperationEvent::BeginEffect)
            .is_err());
    }

    #[test]
    fn operation_preserves_actual_effect_when_terminal_append_fails() {
        let state = AuditOperationState::EffectRunning
            .transition(AuditOperationEvent::EffectCommitted)
            .unwrap()
            .transition(AuditOperationEvent::BeginTerminal)
            .unwrap()
            .transition(AuditOperationEvent::TerminalAppendFailed)
            .unwrap();

        assert_eq!(state, AuditOperationState::AuditDegradedCommitted);
        assert!(AuditOperationState::Completed
            .transition(AuditOperationEvent::TerminalPersisted)
            .is_err());
    }

    #[test]
    fn admission_blocks_mutation_until_verification_and_reconciliation_complete() {
        let state = AuditAdmissionState::Starting
            .transition(AuditAdmissionEvent::BeginVerification)
            .unwrap()
            .transition(AuditAdmissionEvent::IncompleteOperationsFound)
            .unwrap()
            .transition(AuditAdmissionEvent::ReconciliationCompleted)
            .unwrap();

        assert_eq!(state, AuditAdmissionState::Healthy);
        assert!(AuditAdmissionState::Degraded.allows(AuditOperationClass::ReadOnly));
        assert!(
            AuditAdmissionState::Degraded.allows(AuditOperationClass::EphemeralSecurityObservation)
        );
        assert!(!AuditAdmissionState::Degraded.allows(AuditOperationClass::PersistentMutation));
    }

    #[test]
    fn closed_enum_strings_are_stable() {
        assert_eq!(AuditAction::ConfigApply.as_str(), "config.apply");
        assert_eq!(
            AuditOutcome::ReconciledCommitted.as_str(),
            "reconciled_committed"
        );
        assert_eq!(AuditActorKind::SystemRecovery.as_str(), "system_recovery");
        assert_eq!(
            AuditRecordKind::SecurityObservation.as_str(),
            "security_observation"
        );
    }

    #[test]
    fn reconciliation_never_guesses_unknown_facts() {
        let unknown = AuditReconciliationState::IncompleteIntent
            .transition(AuditReconciliationEvent::BeginInspection)
            .unwrap()
            .transition(AuditReconciliationEvent::FactsUnknown)
            .unwrap()
            .transition(AuditReconciliationEvent::UnknownPersisted)
            .unwrap();

        assert_eq!(unknown, AuditReconciliationState::MutationBlocked);
        assert!(AuditReconciliationState::Unknown
            .transition(AuditReconciliationEvent::ReconciliationPersisted)
            .is_err());
    }

    #[test]
    fn audit_validation_errors_have_stable_codes() {
        assert_eq!(
            AuditOperationId::parse("bad value").unwrap_err().as_str(),
            "AUDIT_IDENTIFIER_INVALID_CHARACTER"
        );
        assert_eq!(
            AuditQuery::new(None, None, None, None, None, 101)
                .unwrap_err()
                .as_str(),
            "AUDIT_QUERY_LIMIT_INVALID"
        );
    }
}
