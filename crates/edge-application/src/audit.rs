use edge_domain::{
    AppError, AuditAction, AuditActorKind, AuditAdmissionEvent, AuditAdmissionState,
    AuditAuthoritativeFact, AuditContext, AuditEffectState, AuditLedgerHead, AuditOperationClass,
    AuditOperationEvent, AuditOperationId, AuditOperationState, AuditOutcome, AuditPage,
    AuditQuery, AuditRecord, AuditRecordKind, AuditRequestId, AuditStableErrorCode, AuditTargetId,
    AuditTargetKind, ErrorCode,
};
use edge_ports::{
    AuditAdmissionController, AuditAuthoritativeStateInspector, AuditLedgerReader,
    AuditLedgerWriter,
};
use std::collections::BTreeMap;

pub const AUTH_FAILURE_AUDIT_SAMPLE_INTERVAL_SECONDS: u64 = 60;
pub const AUTH_FAILURE_AUDIT_MAX_TARGETS: usize = 1_024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditPersistentOperationInput {
    pub context: AuditContext,
    pub action: AuditAction,
    pub target_kind: AuditTargetKind,
    pub target_id: AuditTargetId,
    pub before_revision: Option<AuditTargetId>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BeginAuditOperationOutput {
    pub head: AuditLedgerHead,
    pub state: AuditOperationState,
    pub intent: AuditRecord,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BeginAuditOperationFailure {
    pub error: AppError,
    pub state: AuditOperationState,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompleteAuditOperationInput {
    pub operation: AuditPersistentOperationInput,
    pub expected_head: AuditLedgerHead,
    pub effect_state: AuditEffectState,
    pub after_revision: Option<AuditTargetId>,
    pub error_code: Option<AuditStableErrorCode>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompleteAuditOperationOutput {
    pub head: AuditLedgerHead,
    pub state: AuditOperationState,
    pub terminal: AuditRecord,
    pub effect_state: AuditEffectState,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompleteAuditOperationFailure {
    pub error: AppError,
    pub state: AuditOperationState,
    pub effect_state: AuditEffectState,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditSecurityObservationInput {
    pub context: AuditContext,
    pub action: AuditAction,
    pub target_id: AuditTargetId,
    pub outcome: AuditOutcome,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditSecurityObservationOutput {
    pub head: Option<AuditLedgerHead>,
    pub admission_state: AuditAdmissionState,
    pub append_error: Option<AppError>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReconcileAuditOutput {
    pub head: AuditLedgerHead,
    pub fact: AuditAuthoritativeFact,
    pub admission_state: AuditAdmissionState,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InitializeAuditLedgerOutput {
    pub head: AuditLedgerHead,
    pub verified_record_count: u64,
    pub incomplete_count: u16,
    pub reconciled_count: u16,
    pub admission_state: AuditAdmissionState,
}

pub fn initialize_audit_ledger<L, I, A>(
    ledger: &mut L,
    inspector: &mut I,
    admission: &mut A,
) -> Result<InitializeAuditLedgerOutput, AppError>
where
    L: AuditLedgerWriter + AuditLedgerReader + edge_ports::AuditLedgerVerifier + ?Sized,
    I: AuditAuthoritativeStateInspector + ?Sized,
    A: AuditAdmissionController + ?Sized,
{
    let verifying = AuditAdmissionState::Starting
        .transition(AuditAdmissionEvent::BeginVerification)
        .map_err(|error| AppError::new(ErrorCode::AuditRecordInvalid, error.as_str()))?;
    admission.replace_state(verifying);
    let report = match ledger.verify() {
        Ok(report) => report,
        Err(error) => {
            let failed = verifying
                .transition(AuditAdmissionEvent::VerificationFailed)
                .unwrap_or(AuditAdmissionState::FailedClosed);
            admission.replace_state(failed);
            return Err(error);
        }
    };
    let unresolved = match ledger.unresolved_reconciliations() {
        Ok(unresolved) => unresolved,
        Err(error) => {
            admission.replace_state(AuditAdmissionState::FailedClosed);
            return Err(error);
        }
    };
    if !unresolved.is_empty() {
        admission.replace_state(AuditAdmissionState::FailedClosed);
        return Err(AppError::new(
            ErrorCode::AuditReconciliationUnknown,
            "audit ledger contains unresolved reconciliation records",
        ));
    }
    let incomplete = match ledger.incomplete_operations() {
        Ok(incomplete) => incomplete,
        Err(error) => {
            let failed = verifying
                .transition(AuditAdmissionEvent::VerificationFailed)
                .unwrap_or(AuditAdmissionState::FailedClosed);
            admission.replace_state(failed);
            return Err(error);
        }
    };
    let incomplete_count = incomplete.len().try_into().map_err(|_| {
        AppError::new(
            ErrorCode::AuditCapacityReached,
            "incomplete audit operation count exceeds startup bound",
        )
    })?;
    if incomplete.is_empty() {
        let healthy = verifying
            .transition(AuditAdmissionEvent::VerificationPassed)
            .map_err(audit_admission_transition_error)?;
        admission.replace_state(healthy);
        return Ok(InitializeAuditLedgerOutput {
            head: report.head,
            verified_record_count: report.record_count,
            incomplete_count,
            reconciled_count: 0,
            admission_state: healthy,
        });
    }

    let reconciling = verifying
        .transition(AuditAdmissionEvent::IncompleteOperationsFound)
        .map_err(audit_admission_transition_error)?;
    admission.replace_state(reconciling);
    let mut reconciled_count = 0_u16;
    for record in incomplete {
        let expected_head = ledger.head()?;
        let output =
            match reconcile_incomplete_audit(ledger, inspector, admission, record, expected_head) {
                Ok(output) => output,
                Err(error) => {
                    admission.replace_state(AuditAdmissionState::FailedClosed);
                    return Err(error);
                }
            };
        reconciled_count = reconciled_count.checked_add(1).ok_or_else(|| {
            AppError::new(
                ErrorCode::AuditCapacityReached,
                "reconciled audit operation count exceeds startup bound",
            )
        })?;
        if output.fact == AuditAuthoritativeFact::Unknown {
            admission.replace_state(AuditAdmissionState::FailedClosed);
            return Err(AppError::new(
                ErrorCode::AuditReconciliationUnknown,
                "audit reconciliation requires operator investigation",
            ));
        }
        admission.replace_state(reconciling);
    }
    let healthy = reconciling
        .transition(AuditAdmissionEvent::ReconciliationCompleted)
        .map_err(audit_admission_transition_error)?;
    admission.replace_state(healthy);
    Ok(InitializeAuditLedgerOutput {
        head: ledger.head()?,
        verified_record_count: report.record_count,
        incomplete_count,
        reconciled_count,
        admission_state: healthy,
    })
}

fn audit_admission_transition_error(error: edge_domain::AuditValidationError) -> AppError {
    AppError::new(ErrorCode::AuditRecordInvalid, error.as_str())
}

#[derive(Debug, Default)]
pub struct AuthFailureAuditSampler {
    last_observed: BTreeMap<AuditTargetId, u64>,
}

impl AuthFailureAuditSampler {
    pub fn should_record(&mut self, target: &AuditTargetId, now_epoch_seconds: u64) -> bool {
        if self.last_observed.get(target).is_some_and(|last| {
            now_epoch_seconds.saturating_sub(*last) < AUTH_FAILURE_AUDIT_SAMPLE_INTERVAL_SECONDS
        }) {
            return false;
        }
        if !self.last_observed.contains_key(target)
            && self.last_observed.len() >= AUTH_FAILURE_AUDIT_MAX_TARGETS
        {
            let oldest = self
                .last_observed
                .iter()
                .min_by_key(|(target, timestamp)| (**timestamp, (*target).clone()))
                .map(|(target, _)| target.clone());
            if let Some(oldest) = oldest {
                self.last_observed.remove(&oldest);
            }
        }
        self.last_observed.insert(target.clone(), now_epoch_seconds);
        true
    }

    pub fn tracked_target_count(&self) -> usize {
        self.last_observed.len()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditMutationEffect<T> {
    pub value: T,
    pub after_revision: Option<AuditTargetId>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditedMutationOutput<T> {
    pub value: T,
    pub audit: CompleteAuditOperationOutput,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditedMutationFailure<T> {
    pub error: AppError,
    pub effect_error: Option<AppError>,
    pub committed_value: Option<T>,
    pub state: AuditOperationState,
    pub effect_state: Option<AuditEffectState>,
    pub durable_head: Option<AuditLedgerHead>,
}

pub fn config_audit_operation(
    context: AuditContext,
    action: AuditAction,
    target_revision: AuditTargetId,
    before_revision: Option<AuditTargetId>,
) -> Result<AuditPersistentOperationInput, AppError> {
    if !matches!(
        action,
        AuditAction::ConfigApply | AuditAction::ConfigRollback
    ) {
        return Err(AppError::new(
            ErrorCode::AuditRecordInvalid,
            "config audit operation requires apply or rollback action",
        ));
    }
    Ok(AuditPersistentOperationInput {
        context,
        action,
        target_kind: AuditTargetKind::ConfigRevision,
        target_id: target_revision,
        before_revision,
    })
}

pub fn proxy_host_audit_operation(
    context: AuditContext,
    action: AuditAction,
    proxy_host_id: AuditTargetId,
    before_revision: Option<AuditTargetId>,
) -> Result<AuditPersistentOperationInput, AppError> {
    if !matches!(
        action,
        AuditAction::ProxyHostCreate | AuditAction::ProxyHostUpdate | AuditAction::ProxyHostDelete
    ) {
        return Err(AppError::new(
            ErrorCode::AuditRecordInvalid,
            "proxy host audit operation requires a CRUD action",
        ));
    }
    Ok(AuditPersistentOperationInput {
        context,
        action,
        target_kind: AuditTargetKind::ProxyHost,
        target_id: proxy_host_id,
        before_revision,
    })
}

pub fn certificate_audit_operation(
    context: AuditContext,
    action: AuditAction,
    certificate_ref: AuditTargetId,
) -> Result<AuditPersistentOperationInput, AppError> {
    if !matches!(
        action,
        AuditAction::CertificateIssue
            | AuditAction::CertificateRenew
            | AuditAction::CertificateImport
            | AuditAction::CertificateInstall
    ) {
        return Err(AppError::new(
            ErrorCode::AuditRecordInvalid,
            "certificate audit operation requires a certificate action",
        ));
    }
    Ok(AuditPersistentOperationInput {
        context,
        action,
        target_kind: AuditTargetKind::Certificate,
        target_id: certificate_ref,
        before_revision: None,
    })
}

pub fn trust_audit_operation(
    context: AuditContext,
    action: AuditAction,
    trust_ref: AuditTargetId,
) -> Result<AuditPersistentOperationInput, AppError> {
    if !matches!(
        action,
        AuditAction::TrustBundleImport | AuditAction::TrustBundleDelete
    ) {
        return Err(AppError::new(
            ErrorCode::AuditRecordInvalid,
            "trust audit operation requires import or delete action",
        ));
    }
    Ok(AuditPersistentOperationInput {
        context,
        action,
        target_kind: AuditTargetKind::TrustBundle,
        target_id: trust_ref,
        before_revision: None,
    })
}

pub fn admin_setup_audit_operation(
    context: AuditContext,
    admin_id: AuditTargetId,
) -> AuditPersistentOperationInput {
    AuditPersistentOperationInput {
        context,
        action: AuditAction::AdminSetup,
        target_kind: AuditTargetKind::AdminAccount,
        target_id: admin_id,
        before_revision: None,
    }
}

pub fn execute_audited_mutation<W, A, F, T>(
    writer: &mut W,
    admission: &mut A,
    operation: AuditPersistentOperationInput,
    effect: F,
) -> Result<AuditedMutationOutput<T>, AuditedMutationFailure<T>>
where
    W: AuditLedgerWriter + ?Sized,
    A: AuditAdmissionController + ?Sized,
    F: FnOnce() -> Result<AuditMutationEffect<T>, AppError>,
{
    let begin = begin_audit_operation(writer, admission, operation.clone()).map_err(|failure| {
        AuditedMutationFailure {
            error: failure.error,
            effect_error: None,
            committed_value: None,
            state: failure.state,
            effect_state: None,
            durable_head: None,
        }
    })?;
    begin
        .state
        .transition(AuditOperationEvent::BeginEffect)
        .map_err(|error| AuditedMutationFailure {
            error: AppError::new(ErrorCode::AuditRecordInvalid, error.as_str()),
            effect_error: None,
            committed_value: None,
            state: begin.state,
            effect_state: None,
            durable_head: Some(begin.head),
        })?;

    match effect() {
        Ok(effect) => {
            let completion = complete_audit_operation(
                writer,
                admission,
                CompleteAuditOperationInput {
                    operation,
                    expected_head: begin.head,
                    effect_state: AuditEffectState::Committed,
                    after_revision: effect.after_revision,
                    error_code: None,
                },
            );
            match completion {
                Ok(completion) => Ok(AuditedMutationOutput {
                    value: effect.value,
                    audit: completion,
                }),
                Err(failure) => Err(AuditedMutationFailure {
                    error: failure.error,
                    effect_error: None,
                    committed_value: Some(effect.value),
                    state: failure.state,
                    effect_state: Some(failure.effect_state),
                    durable_head: Some(begin.head),
                }),
            }
        }
        Err(effect_error) => {
            let stable_error =
                AuditStableErrorCode::parse(effect_error.code.as_str()).map_err(|_| {
                    admission.replace_state(AuditAdmissionState::Degraded);
                    AuditedMutationFailure {
                        error: AppError::new(
                            ErrorCode::InternalBug,
                            "application error code is not audit-safe",
                        ),
                        effect_error: Some(effect_error.clone()),
                        committed_value: None,
                        state: AuditOperationState::AuditDegradedRejected,
                        effect_state: Some(AuditEffectState::Rejected),
                        durable_head: Some(begin.head),
                    }
                })?;
            match complete_audit_operation(
                writer,
                admission,
                CompleteAuditOperationInput {
                    operation,
                    expected_head: begin.head,
                    effect_state: AuditEffectState::Rejected,
                    after_revision: None,
                    error_code: Some(stable_error),
                },
            ) {
                Ok(completion) => Err(AuditedMutationFailure {
                    error: effect_error.clone(),
                    effect_error: Some(effect_error),
                    committed_value: None,
                    state: completion.state,
                    effect_state: Some(AuditEffectState::Rejected),
                    durable_head: Some(completion.head),
                }),
                Err(failure) => Err(AuditedMutationFailure {
                    error: failure.error,
                    effect_error: Some(effect_error),
                    committed_value: None,
                    state: failure.state,
                    effect_state: Some(failure.effect_state),
                    durable_head: Some(begin.head),
                }),
            }
        }
    }
}

pub fn begin_audit_operation<W, A>(
    writer: &mut W,
    admission: &A,
    input: AuditPersistentOperationInput,
) -> Result<BeginAuditOperationOutput, BeginAuditOperationFailure>
where
    W: AuditLedgerWriter + ?Sized,
    A: AuditAdmissionController + ?Sized,
{
    if !admission
        .state()
        .allows(AuditOperationClass::PersistentMutation)
    {
        return Err(BeginAuditOperationFailure {
            error: AppError::new(
                ErrorCode::AuditMutationBlocked,
                "persistent mutation requires a healthy audit ledger",
            ),
            state: AuditOperationState::RejectedNoEffect,
        });
    }

    let state = AuditOperationState::Received
        .transition(AuditOperationEvent::BeginIntent)
        .map_err(transition_begin_failure)?;
    let intent = record_for_operation(&input, AuditRecordKind::Intent, None, None, None);
    let head =
        writer
            .append_intent(intent.clone())
            .map_err(|error| BeginAuditOperationFailure {
                error,
                state: state
                    .transition(AuditOperationEvent::IntentAppendFailed)
                    .expect("intent append failure transition is valid"),
            })?;
    let state = state
        .transition(AuditOperationEvent::IntentPersisted)
        .expect("intent persisted transition is valid");

    Ok(BeginAuditOperationOutput {
        head,
        state,
        intent,
    })
}

pub fn complete_audit_operation<W, A>(
    writer: &mut W,
    admission: &mut A,
    input: CompleteAuditOperationInput,
) -> Result<CompleteAuditOperationOutput, CompleteAuditOperationFailure>
where
    W: AuditLedgerWriter + ?Sized,
    A: AuditAdmissionController + ?Sized,
{
    let effect_event = match input.effect_state {
        AuditEffectState::Committed => AuditOperationEvent::EffectCommitted,
        AuditEffectState::Rejected => AuditOperationEvent::EffectRejected,
    };
    let state = AuditOperationState::EffectRunning
        .transition(effect_event)
        .and_then(|state| state.transition(AuditOperationEvent::BeginTerminal))
        .map_err(|_| CompleteAuditOperationFailure {
            error: AppError::new(
                ErrorCode::AuditRecordInvalid,
                "invalid audit terminal state",
            ),
            state: AuditOperationState::EffectRunning,
            effect_state: input.effect_state,
        })?;
    let outcome = match input.effect_state {
        AuditEffectState::Committed => AuditOutcome::Succeeded,
        AuditEffectState::Rejected => AuditOutcome::Failed,
    };
    if input.effect_state == AuditEffectState::Committed && input.error_code.is_some() {
        return Err(CompleteAuditOperationFailure {
            error: AppError::new(
                ErrorCode::AuditRecordInvalid,
                "committed audit terminal cannot include an error code",
            ),
            state,
            effect_state: input.effect_state,
        });
    }
    if input.effect_state == AuditEffectState::Rejected && input.error_code.is_none() {
        return Err(CompleteAuditOperationFailure {
            error: AppError::new(
                ErrorCode::AuditRecordInvalid,
                "rejected audit terminal requires a stable error code",
            ),
            state,
            effect_state: input.effect_state,
        });
    }
    let terminal = record_for_operation(
        &input.operation,
        AuditRecordKind::Terminal,
        Some(outcome),
        input.after_revision,
        input.error_code,
    );

    match writer.append_terminal(terminal.clone(), input.expected_head) {
        Ok(head) => Ok(CompleteAuditOperationOutput {
            head,
            state: state
                .transition(AuditOperationEvent::TerminalPersisted)
                .expect("terminal persisted transition is valid"),
            terminal,
            effect_state: input.effect_state,
        }),
        Err(error) => {
            admission.replace_state(AuditAdmissionState::Degraded);
            Err(CompleteAuditOperationFailure {
                error,
                state: state
                    .transition(AuditOperationEvent::TerminalAppendFailed)
                    .expect("terminal append failure transition is valid"),
                effect_state: input.effect_state,
            })
        }
    }
}

pub fn record_security_observation<W, A>(
    writer: &mut W,
    admission: &mut A,
    input: AuditSecurityObservationInput,
) -> Result<AuditSecurityObservationOutput, AppError>
where
    W: AuditLedgerWriter + ?Sized,
    A: AuditAdmissionController + ?Sized,
{
    if !is_security_observation(input.action) {
        return Err(AppError::new(
            ErrorCode::AuditRecordInvalid,
            "action is not a security observation",
        ));
    }
    if admission.state() != AuditAdmissionState::Healthy {
        return Ok(AuditSecurityObservationOutput {
            head: None,
            admission_state: admission.state(),
            append_error: None,
        });
    }
    let record = AuditRecord {
        record_version: 1,
        record_kind: AuditRecordKind::SecurityObservation,
        context: input.context,
        action: input.action,
        target_kind: AuditTargetKind::AdminAccount,
        target_id: input.target_id,
        before_revision: None,
        after_revision: None,
        outcome: Some(input.outcome),
        error_code: None,
    };
    match writer.append_security_observation(record) {
        Ok(head) => Ok(AuditSecurityObservationOutput {
            head: Some(head),
            admission_state: AuditAdmissionState::Healthy,
            append_error: None,
        }),
        Err(error) => {
            admission.replace_state(AuditAdmissionState::Degraded);
            Ok(AuditSecurityObservationOutput {
                head: None,
                admission_state: AuditAdmissionState::Degraded,
                append_error: Some(error),
            })
        }
    }
}

pub fn query_audit<R>(
    reader: &R,
    authenticated: bool,
    query: &AuditQuery,
) -> Result<AuditPage, AppError>
where
    R: AuditLedgerReader + ?Sized,
{
    if !authenticated {
        return Err(AppError::new(
            ErrorCode::AdminAuthRequired,
            "audit query requires authentication",
        ));
    }
    reader.query(query)
}

pub fn reconcile_incomplete_audit<W, I, A>(
    writer: &mut W,
    inspector: &mut I,
    admission: &mut A,
    incomplete: AuditRecord,
    expected_head: AuditLedgerHead,
) -> Result<ReconcileAuditOutput, AppError>
where
    W: AuditLedgerWriter + ?Sized,
    I: AuditAuthoritativeStateInspector + ?Sized,
    A: AuditAdmissionController + ?Sized,
{
    if incomplete.record_kind != AuditRecordKind::Intent {
        return Err(AppError::new(
            ErrorCode::AuditRecordInvalid,
            "only incomplete intent records can be reconciled",
        ));
    }
    let fact = inspector.inspect(
        &incomplete.context.operation_id,
        incomplete.action,
        &incomplete.target_id,
    )?;
    let outcome = match fact {
        AuditAuthoritativeFact::Committed => AuditOutcome::ReconciledCommitted,
        AuditAuthoritativeFact::NotCommitted => AuditOutcome::ReconciledNotCommitted,
        AuditAuthoritativeFact::Unknown => AuditOutcome::ReconciliationUnknown,
    };
    let mut record = incomplete;
    record.record_kind = AuditRecordKind::Reconciliation;
    record.outcome = Some(outcome);
    let head = writer.append_reconciliation(record, expected_head)?;
    let state = if fact == AuditAuthoritativeFact::Unknown {
        AuditAdmissionState::FailedClosed
    } else {
        AuditAdmissionState::Healthy
    };
    admission.replace_state(state);
    Ok(ReconcileAuditOutput {
        head,
        fact,
        admission_state: state,
    })
}

fn record_for_operation(
    input: &AuditPersistentOperationInput,
    record_kind: AuditRecordKind,
    outcome: Option<AuditOutcome>,
    after_revision: Option<AuditTargetId>,
    error_code: Option<AuditStableErrorCode>,
) -> AuditRecord {
    AuditRecord {
        record_version: 1,
        record_kind,
        context: input.context.clone(),
        action: input.action,
        target_kind: input.target_kind,
        target_id: input.target_id.clone(),
        before_revision: input.before_revision.clone(),
        after_revision,
        outcome,
        error_code,
    }
}

fn transition_begin_failure(
    error: edge_domain::AuditValidationError,
) -> BeginAuditOperationFailure {
    BeginAuditOperationFailure {
        error: AppError::new(ErrorCode::AuditRecordInvalid, error.as_str()),
        state: AuditOperationState::RejectedNoEffect,
    }
}

fn is_security_observation(action: AuditAction) -> bool {
    matches!(
        action,
        AuditAction::AdminLoginSuccess
            | AuditAction::AdminLogout
            | AuditAction::AdminLockout
            | AuditAction::AdminAuthFailureSampled
    )
}

pub fn audit_context(
    operation_id: AuditOperationId,
    request_id: AuditRequestId,
    actor_kind: AuditActorKind,
    received_at_epoch_seconds: u64,
) -> AuditContext {
    AuditContext {
        operation_id,
        request_id,
        actor_kind,
        received_at_epoch_seconds,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use edge_domain::{AuditCursor, AuditRecordView, AuditVerificationReport};
    use edge_ports::AuditLedgerVerifier;

    #[derive(Default)]
    struct FakeLedger {
        records: Vec<AuditRecord>,
        head: AuditLedgerHead,
        fail_append: bool,
        fail_on_attempt: Option<usize>,
        append_attempts: usize,
        fail_verify: bool,
    }

    impl FakeLedger {
        fn append(&mut self, record: AuditRecord) -> Result<AuditLedgerHead, AppError> {
            self.append_attempts += 1;
            if self.fail_append || self.fail_on_attempt == Some(self.append_attempts) {
                return Err(AppError::new(ErrorCode::AuditAppendFailed, "injected"));
            }
            self.head.sequence += 1;
            self.records.push(record);
            Ok(self.head)
        }
    }

    impl AuditLedgerWriter for FakeLedger {
        fn append_intent(&mut self, record: AuditRecord) -> Result<AuditLedgerHead, AppError> {
            self.append(record)
        }

        fn append_terminal(
            &mut self,
            record: AuditRecord,
            _expected_head: AuditLedgerHead,
        ) -> Result<AuditLedgerHead, AppError> {
            self.append(record)
        }

        fn append_reconciliation(
            &mut self,
            record: AuditRecord,
            _expected_head: AuditLedgerHead,
        ) -> Result<AuditLedgerHead, AppError> {
            self.append(record)
        }

        fn append_security_observation(
            &mut self,
            record: AuditRecord,
        ) -> Result<AuditLedgerHead, AppError> {
            self.append(record)
        }
    }

    impl AuditLedgerReader for FakeLedger {
        fn query(&self, _query: &AuditQuery) -> Result<AuditPage, AppError> {
            Ok(AuditPage {
                records: self
                    .records
                    .iter()
                    .cloned()
                    .enumerate()
                    .map(|(index, record)| AuditRecordView {
                        sequence: index as u64 + 1,
                        record,
                    })
                    .collect(),
                next_cursor: Some(AuditCursor {
                    ledger_generation: self.head.generation,
                    before_sequence: self.head.sequence,
                }),
                head: self.head,
                admission_state: AuditAdmissionState::Healthy,
            })
        }

        fn incomplete_operations(&self) -> Result<Vec<AuditRecord>, AppError> {
            let mut open = BTreeMap::new();
            for record in &self.records {
                match record.record_kind {
                    AuditRecordKind::Intent => {
                        open.insert(record.context.operation_id.clone(), record.clone());
                    }
                    AuditRecordKind::Terminal | AuditRecordKind::Reconciliation => {
                        open.remove(&record.context.operation_id);
                    }
                    _ => {}
                }
            }
            Ok(open.into_values().collect())
        }

        fn unresolved_reconciliations(&self) -> Result<Vec<AuditRecord>, AppError> {
            Ok(self
                .records
                .iter()
                .filter(|record| {
                    record.record_kind == AuditRecordKind::Reconciliation
                        && record.outcome == Some(AuditOutcome::ReconciliationUnknown)
                })
                .cloned()
                .collect())
        }

        fn head(&self) -> Result<AuditLedgerHead, AppError> {
            Ok(self.head)
        }
    }

    impl AuditLedgerVerifier for FakeLedger {
        fn verify(&mut self) -> Result<AuditVerificationReport, AppError> {
            if self.fail_verify {
                return Err(AppError::new(ErrorCode::AuditChainMismatch, "injected"));
            }
            Ok(AuditVerificationReport {
                head: self.head,
                record_count: self.records.len() as u64,
                segment_count: 1,
                incomplete_operation_count: 0,
            })
        }
    }

    #[derive(Default)]
    struct FakeAdmission(AuditAdmissionState);

    impl AuditAdmissionController for FakeAdmission {
        fn state(&self) -> AuditAdmissionState {
            self.0
        }

        fn replace_state(&mut self, state: AuditAdmissionState) {
            self.0 = state;
        }
    }

    struct FakeInspector(AuditAuthoritativeFact);

    impl AuditAuthoritativeStateInspector for FakeInspector {
        fn inspect(
            &mut self,
            _operation_id: &AuditOperationId,
            _action: AuditAction,
            _target_id: &AuditTargetId,
        ) -> Result<AuditAuthoritativeFact, AppError> {
            Ok(self.0)
        }
    }

    fn context() -> AuditContext {
        audit_context(
            AuditOperationId::parse("operation-1").unwrap(),
            AuditRequestId::parse("request-1").unwrap(),
            AuditActorKind::BootstrapAdmin,
            10,
        )
    }

    fn persistent_input() -> AuditPersistentOperationInput {
        AuditPersistentOperationInput {
            context: context(),
            action: AuditAction::ConfigApply,
            target_kind: AuditTargetKind::ConfigRevision,
            target_id: AuditTargetId::parse("revision-2").unwrap(),
            before_revision: Some(AuditTargetId::parse("revision-1").unwrap()),
        }
    }

    #[test]
    fn begin_rejects_without_effect_when_admission_is_not_healthy() {
        let mut ledger = FakeLedger::default();
        let admission = FakeAdmission(AuditAdmissionState::Degraded);

        let failure =
            begin_audit_operation(&mut ledger, &admission, persistent_input()).unwrap_err();

        assert_eq!(failure.error.code, ErrorCode::AuditMutationBlocked);
        assert_eq!(failure.state, AuditOperationState::RejectedNoEffect);
        assert!(ledger.records.is_empty());
    }

    #[test]
    fn begin_persists_exactly_one_intent_before_effect_is_allowed() {
        let mut ledger = FakeLedger::default();
        let admission = FakeAdmission(AuditAdmissionState::Healthy);

        let output = begin_audit_operation(&mut ledger, &admission, persistent_input()).unwrap();

        assert_eq!(output.state, AuditOperationState::IntentPersisted);
        assert_eq!(ledger.records.len(), 1);
        assert_eq!(ledger.records[0].record_kind, AuditRecordKind::Intent);
    }

    #[test]
    fn complete_preserves_committed_effect_when_terminal_append_fails() {
        let mut ledger = FakeLedger {
            fail_append: true,
            ..FakeLedger::default()
        };
        let mut admission = FakeAdmission(AuditAdmissionState::Healthy);
        let failure = complete_audit_operation(
            &mut ledger,
            &mut admission,
            CompleteAuditOperationInput {
                operation: persistent_input(),
                expected_head: AuditLedgerHead::default(),
                effect_state: AuditEffectState::Committed,
                after_revision: Some(AuditTargetId::parse("revision-2").unwrap()),
                error_code: None,
            },
        )
        .unwrap_err();

        assert_eq!(failure.effect_state, AuditEffectState::Committed);
        assert_eq!(failure.state, AuditOperationState::AuditDegradedCommitted);
        assert_eq!(admission.state(), AuditAdmissionState::Degraded);
    }

    #[test]
    fn rejected_terminal_requires_a_stable_error_code() {
        let mut ledger = FakeLedger::default();
        let mut admission = FakeAdmission(AuditAdmissionState::Healthy);

        let failure = complete_audit_operation(
            &mut ledger,
            &mut admission,
            CompleteAuditOperationInput {
                operation: persistent_input(),
                expected_head: AuditLedgerHead::default(),
                effect_state: AuditEffectState::Rejected,
                after_revision: None,
                error_code: None,
            },
        )
        .unwrap_err();

        assert_eq!(failure.error.code, ErrorCode::AuditRecordInvalid);
        assert!(ledger.records.is_empty());
    }

    #[test]
    fn observation_append_failure_does_not_become_auth_failure() {
        let mut ledger = FakeLedger {
            fail_append: true,
            ..FakeLedger::default()
        };
        let mut admission = FakeAdmission(AuditAdmissionState::Healthy);
        let output = record_security_observation(
            &mut ledger,
            &mut admission,
            AuditSecurityObservationInput {
                context: context(),
                action: AuditAction::AdminLoginSuccess,
                target_id: AuditTargetId::parse("bootstrap-admin").unwrap(),
                outcome: AuditOutcome::Observed,
            },
        )
        .unwrap();

        assert!(output.head.is_none());
        assert_eq!(output.admission_state, AuditAdmissionState::Degraded);
        assert_eq!(
            output.append_error.unwrap().code,
            ErrorCode::AuditAppendFailed
        );
    }

    #[test]
    fn query_requires_authentication_and_uses_reader_port() {
        let ledger = FakeLedger::default();
        assert_eq!(
            query_audit(&ledger, false, &AuditQuery::default())
                .unwrap_err()
                .code,
            ErrorCode::AdminAuthRequired
        );
        assert!(query_audit(&ledger, true, &AuditQuery::default()).is_ok());
    }

    #[test]
    fn unknown_reconciliation_persists_unknown_and_blocks_mutation() {
        let mut ledger = FakeLedger::default();
        let admission = FakeAdmission(AuditAdmissionState::Healthy);
        let incomplete = begin_audit_operation(&mut ledger, &admission, persistent_input())
            .unwrap()
            .intent;
        let mut admission = FakeAdmission(AuditAdmissionState::Reconciling);
        let mut inspector = FakeInspector(AuditAuthoritativeFact::Unknown);

        let output = reconcile_incomplete_audit(
            &mut ledger,
            &mut inspector,
            &mut admission,
            incomplete,
            AuditLedgerHead {
                generation: 0,
                sequence: 1,
            },
        )
        .unwrap();

        assert_eq!(output.fact, AuditAuthoritativeFact::Unknown);
        assert_eq!(output.admission_state, AuditAdmissionState::FailedClosed);
        assert_eq!(
            ledger.records.last().unwrap().outcome,
            Some(AuditOutcome::ReconciliationUnknown)
        );
    }

    #[test]
    fn audited_mutation_does_not_run_effect_when_intent_append_fails() {
        let mut ledger = FakeLedger {
            fail_append: true,
            ..FakeLedger::default()
        };
        let mut admission = FakeAdmission(AuditAdmissionState::Healthy);
        let mut effect_called = false;

        let failure =
            execute_audited_mutation(&mut ledger, &mut admission, persistent_input(), || {
                effect_called = true;
                Ok(AuditMutationEffect {
                    value: "revision-2",
                    after_revision: Some(AuditTargetId::parse("revision-2").unwrap()),
                })
            })
            .unwrap_err();

        assert!(!effect_called);
        assert_eq!(failure.error.code, ErrorCode::AuditAppendFailed);
        assert_eq!(failure.state, AuditOperationState::RejectedNoEffect);
        assert!(failure.committed_value.is_none());
    }

    #[test]
    fn audited_mutation_writes_exact_pair_for_success_and_rejection() {
        let mut ledger = FakeLedger::default();
        let mut admission = FakeAdmission(AuditAdmissionState::Healthy);
        let output =
            execute_audited_mutation(&mut ledger, &mut admission, persistent_input(), || {
                Ok(AuditMutationEffect {
                    value: "applied",
                    after_revision: Some(AuditTargetId::parse("revision-2").unwrap()),
                })
            })
            .unwrap();
        assert_eq!(output.value, "applied");
        assert_eq!(output.audit.state, AuditOperationState::Completed);
        assert_eq!(ledger.records.len(), 2);
        assert_eq!(ledger.records[0].record_kind, AuditRecordKind::Intent);
        assert_eq!(ledger.records[1].record_kind, AuditRecordKind::Terminal);
        assert_eq!(ledger.records[1].outcome, Some(AuditOutcome::Succeeded));

        let mut rejected_ledger = FakeLedger::default();
        let failure = execute_audited_mutation::<_, _, _, ()>(
            &mut rejected_ledger,
            &mut admission,
            persistent_input(),
            || Err(AppError::new(ErrorCode::ConfigStoreFailed, "rejected")),
        )
        .unwrap_err();
        assert_eq!(failure.error.code, ErrorCode::ConfigStoreFailed);
        assert_eq!(failure.state, AuditOperationState::Completed);
        assert_eq!(failure.durable_head.unwrap().sequence, 2);
        assert_eq!(rejected_ledger.records.len(), 2);
        assert_eq!(
            rejected_ledger.records[1].outcome,
            Some(AuditOutcome::Failed)
        );
        assert_eq!(
            rejected_ledger.records[1]
                .error_code
                .as_ref()
                .unwrap()
                .as_str(),
            "CONFIG_STORE_FAILED"
        );
    }

    #[test]
    fn audited_mutation_preserves_committed_value_when_terminal_append_fails() {
        let mut ledger = FakeLedger {
            fail_on_attempt: Some(2),
            ..FakeLedger::default()
        };
        let mut admission = FakeAdmission(AuditAdmissionState::Healthy);
        let failure =
            execute_audited_mutation(&mut ledger, &mut admission, persistent_input(), || {
                Ok(AuditMutationEffect {
                    value: "committed-revision",
                    after_revision: Some(AuditTargetId::parse("revision-2").unwrap()),
                })
            })
            .unwrap_err();

        assert_eq!(failure.error.code, ErrorCode::AuditAppendFailed);
        assert_eq!(failure.committed_value, Some("committed-revision"));
        assert_eq!(failure.state, AuditOperationState::AuditDegradedCommitted);
        assert_eq!(admission.state(), AuditAdmissionState::Degraded);
        assert_eq!(ledger.records.len(), 1);
    }

    #[test]
    fn config_and_proxy_mapping_accepts_only_its_closed_action_family() {
        for action in [AuditAction::ConfigApply, AuditAction::ConfigRollback] {
            let operation = config_audit_operation(
                context(),
                action,
                AuditTargetId::parse("revision-2").unwrap(),
                Some(AuditTargetId::parse("revision-1").unwrap()),
            )
            .unwrap();
            assert_eq!(operation.target_kind, AuditTargetKind::ConfigRevision);
            assert_eq!(operation.action, action);
        }
        for action in [
            AuditAction::ProxyHostCreate,
            AuditAction::ProxyHostUpdate,
            AuditAction::ProxyHostDelete,
        ] {
            let operation = proxy_host_audit_operation(
                context(),
                action,
                AuditTargetId::parse("proxy-1").unwrap(),
                None,
            )
            .unwrap();
            assert_eq!(operation.target_kind, AuditTargetKind::ProxyHost);
            assert_eq!(operation.action, action);
        }
        assert_eq!(
            config_audit_operation(
                context(),
                AuditAction::ProxyHostCreate,
                AuditTargetId::parse("revision-2").unwrap(),
                None,
            )
            .unwrap_err()
            .code,
            ErrorCode::AuditRecordInvalid
        );
        assert_eq!(
            proxy_host_audit_operation(
                context(),
                AuditAction::ConfigApply,
                AuditTargetId::parse("proxy-1").unwrap(),
                None,
            )
            .unwrap_err()
            .code,
            ErrorCode::AuditRecordInvalid
        );
    }

    #[test]
    fn certificate_trust_and_setup_mapping_exposes_only_bounded_targets() {
        let certificate = certificate_audit_operation(
            context(),
            AuditAction::CertificateIssue,
            AuditTargetId::parse("certificate-1").unwrap(),
        )
        .unwrap();
        let trust = trust_audit_operation(
            context(),
            AuditAction::TrustBundleImport,
            AuditTargetId::parse("private-root-1").unwrap(),
        )
        .unwrap();
        let setup = admin_setup_audit_operation(
            context(),
            AuditTargetId::parse("bootstrap-admin").unwrap(),
        );

        assert_eq!(certificate.target_kind, AuditTargetKind::Certificate);
        assert_eq!(trust.target_kind, AuditTargetKind::TrustBundle);
        assert_eq!(setup.target_kind, AuditTargetKind::AdminAccount);
        assert!(certificate.before_revision.is_none());
        assert!(trust.before_revision.is_none());
        assert!(setup.before_revision.is_none());

        for action in [
            AuditAction::CertificateIssue,
            AuditAction::CertificateRenew,
            AuditAction::CertificateImport,
            AuditAction::CertificateInstall,
        ] {
            assert_eq!(
                certificate_audit_operation(
                    context(),
                    action,
                    AuditTargetId::parse("certificate-1").unwrap(),
                )
                .unwrap()
                .action,
                action
            );
        }
        for action in [
            AuditAction::TrustBundleImport,
            AuditAction::TrustBundleDelete,
        ] {
            assert_eq!(
                trust_audit_operation(
                    context(),
                    action,
                    AuditTargetId::parse("private-root-1").unwrap(),
                )
                .unwrap()
                .action,
                action
            );
        }
        assert_eq!(
            certificate_audit_operation(
                context(),
                AuditAction::TrustBundleImport,
                AuditTargetId::parse("certificate-1").unwrap(),
            )
            .unwrap_err()
            .code,
            ErrorCode::AuditRecordInvalid
        );
        assert_eq!(
            trust_audit_operation(
                context(),
                AuditAction::CertificateImport,
                AuditTargetId::parse("private-root-1").unwrap(),
            )
            .unwrap_err()
            .code,
            ErrorCode::AuditRecordInvalid
        );
    }

    #[test]
    fn auth_observation_is_bounded_and_skipped_when_ledger_is_degraded() {
        let mut ledger = FakeLedger::default();
        let mut admission = FakeAdmission(AuditAdmissionState::Healthy);
        for action in [
            AuditAction::AdminLoginSuccess,
            AuditAction::AdminLogout,
            AuditAction::AdminLockout,
            AuditAction::AdminAuthFailureSampled,
        ] {
            let output = record_security_observation(
                &mut ledger,
                &mut admission,
                AuditSecurityObservationInput {
                    context: context(),
                    action,
                    target_id: AuditTargetId::parse("bootstrap-admin").unwrap(),
                    outcome: AuditOutcome::Observed,
                },
            )
            .unwrap();
            assert!(output.head.is_some());
        }
        assert_eq!(ledger.records.len(), 4);
        assert!(ledger.records.iter().all(|record| {
            record.record_kind == AuditRecordKind::SecurityObservation
                && record.target_id.as_str() == "bootstrap-admin"
                && record.error_code.is_none()
                && record.before_revision.is_none()
                && record.after_revision.is_none()
        }));

        admission.replace_state(AuditAdmissionState::Degraded);
        let output = record_security_observation(
            &mut ledger,
            &mut admission,
            AuditSecurityObservationInput {
                context: context(),
                action: AuditAction::AdminAuthFailureSampled,
                target_id: AuditTargetId::parse("bootstrap-admin").unwrap(),
                outcome: AuditOutcome::Observed,
            },
        )
        .unwrap();
        assert!(output.head.is_none());
        assert!(output.append_error.is_none());
        assert_eq!(ledger.records.len(), 4);
    }

    #[test]
    fn auth_failure_sampler_enforces_time_boundary_and_target_capacity() {
        let mut sampler = AuthFailureAuditSampler::default();
        let target = AuditTargetId::parse("bootstrap-admin").unwrap();
        assert!(sampler.should_record(&target, 100));
        assert!(!sampler.should_record(&target, 159));
        assert!(sampler.should_record(&target, 160));

        for index in 0..=AUTH_FAILURE_AUDIT_MAX_TARGETS {
            let target = AuditTargetId::parse(format!("admin-{index}")).unwrap();
            assert!(sampler.should_record(&target, index as u64));
        }
        assert_eq!(
            sampler.tracked_target_count(),
            AUTH_FAILURE_AUDIT_MAX_TARGETS
        );
    }

    #[test]
    fn startup_coordinator_verifies_before_publishing_healthy_admission() {
        let mut ledger = FakeLedger::default();
        let mut admission = FakeAdmission(AuditAdmissionState::Starting);
        let mut inspector = FakeInspector(AuditAuthoritativeFact::Committed);

        let output = initialize_audit_ledger(&mut ledger, &mut inspector, &mut admission).unwrap();

        assert_eq!(output.admission_state, AuditAdmissionState::Healthy);
        assert_eq!(output.incomplete_count, 0);
        assert_eq!(output.reconciled_count, 0);
        assert_eq!(admission.state(), AuditAdmissionState::Healthy);
    }

    #[test]
    fn startup_coordinator_reconciles_known_intent_and_fails_closed_on_unknown() {
        for (fact, expected_outcome) in [
            (
                AuditAuthoritativeFact::Committed,
                AuditOutcome::ReconciledCommitted,
            ),
            (
                AuditAuthoritativeFact::NotCommitted,
                AuditOutcome::ReconciledNotCommitted,
            ),
        ] {
            let mut ledger = FakeLedger::default();
            let admission = FakeAdmission(AuditAdmissionState::Healthy);
            begin_audit_operation(&mut ledger, &admission, persistent_input()).unwrap();
            let mut admission = FakeAdmission(AuditAdmissionState::Starting);
            let mut inspector = FakeInspector(fact);
            let output =
                initialize_audit_ledger(&mut ledger, &mut inspector, &mut admission).unwrap();
            assert_eq!(output.incomplete_count, 1);
            assert_eq!(output.reconciled_count, 1);
            assert_eq!(output.admission_state, AuditAdmissionState::Healthy);
            assert_eq!(
                ledger.records.last().unwrap().outcome,
                Some(expected_outcome)
            );
        }

        let mut ledger = FakeLedger::default();
        let admission = FakeAdmission(AuditAdmissionState::Healthy);
        begin_audit_operation(&mut ledger, &admission, persistent_input()).unwrap();
        let mut admission = FakeAdmission(AuditAdmissionState::Starting);
        let mut inspector = FakeInspector(AuditAuthoritativeFact::Unknown);
        assert_eq!(
            initialize_audit_ledger(&mut ledger, &mut inspector, &mut admission)
                .unwrap_err()
                .code,
            ErrorCode::AuditReconciliationUnknown
        );
        assert_eq!(admission.state(), AuditAdmissionState::FailedClosed);

        let mut restarted_admission = FakeAdmission(AuditAdmissionState::Starting);
        assert_eq!(
            initialize_audit_ledger(&mut ledger, &mut inspector, &mut restarted_admission,)
                .unwrap_err()
                .code,
            ErrorCode::AuditReconciliationUnknown
        );
        assert_eq!(
            restarted_admission.state(),
            AuditAdmissionState::FailedClosed
        );
    }

    #[test]
    fn startup_coordinator_fails_closed_when_verification_fails() {
        let mut ledger = FakeLedger {
            fail_verify: true,
            ..FakeLedger::default()
        };
        let mut admission = FakeAdmission(AuditAdmissionState::Starting);
        let mut inspector = FakeInspector(AuditAuthoritativeFact::Committed);

        assert_eq!(
            initialize_audit_ledger(&mut ledger, &mut inspector, &mut admission)
                .unwrap_err()
                .code,
            ErrorCode::AuditChainMismatch
        );
        assert_eq!(admission.state(), AuditAdmissionState::FailedClosed);
    }
}
