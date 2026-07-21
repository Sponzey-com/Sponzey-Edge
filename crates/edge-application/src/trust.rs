use edge_domain::{AppError, ClientAuthPolicy, ErrorCode, TrustBundleRef, UpstreamTlsPolicy};
use edge_ports::{
    RetainedConfigSnapshots, TrustBundleEventSink, TrustBundleMaterialValidator,
    TrustBundleMetadata, TrustBundleOperationEvent, TrustBundleStore,
};

const MAX_TRUST_BUNDLES: usize = 128;
const MAX_ENCODED_TRUST_BUNDLE_BYTES: usize = 384 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportTrustBundleInput {
    pub request_id: String,
    pub trust_bundle_ref: TrustBundleRef,
    pub encoded_material: Vec<u8>,
    pub imported_at_epoch_seconds: u64,
}

pub fn import_trust_bundle<V, S, E>(
    validator: &mut V,
    store: &mut S,
    events: &mut E,
    input: ImportTrustBundleInput,
) -> Result<TrustBundleMetadata, AppError>
where
    V: TrustBundleMaterialValidator,
    S: TrustBundleStore,
    E: TrustBundleEventSink,
{
    if input.encoded_material.len() > MAX_ENCODED_TRUST_BUNDLE_BYTES {
        let error = AppError::new(
            ErrorCode::TrustBundleLimitExceeded,
            "encoded trust bundle limit exceeded",
        );
        record_import_event(
            events,
            &input.trust_bundle_ref,
            None,
            "failure",
            Some(error.code),
        );
        return Err(error);
    }
    let validated = match validator.validate_trust_bundle(
        &input.trust_bundle_ref,
        &input.encoded_material,
        input.imported_at_epoch_seconds,
    ) {
        Ok(value) => value,
        Err(error) => {
            record_import_event(
                events,
                &input.trust_bundle_ref,
                None,
                "failure",
                Some(error.code),
            );
            return Err(error);
        }
    };
    let metadata = validated.metadata.clone();
    if let Err(error) = store.create_trust_bundle(validated) {
        record_import_event(
            events,
            &input.trust_bundle_ref,
            Some(metadata.certificate_count),
            "failure",
            Some(error.code),
        );
        return Err(error);
    }
    record_import_event(
        events,
        &input.trust_bundle_ref,
        Some(metadata.certificate_count),
        "success",
        None,
    );
    Ok(metadata)
}

fn record_import_event<E: TrustBundleEventSink>(
    events: &mut E,
    reference: &TrustBundleRef,
    certificate_count: Option<u8>,
    outcome: &'static str,
    error_code: Option<ErrorCode>,
) {
    let event = TrustBundleOperationEvent {
        event: "trust_bundle.import",
        trust_bundle_ref: reference.clone(),
        certificate_count,
        outcome,
        error_code,
    };
    events.record_trust_product_event(event.clone());
    events.record_trust_audit_event(event);
}

pub fn list_trust_bundles<S: TrustBundleStore>(
    store: &mut S,
) -> Result<Vec<TrustBundleMetadata>, AppError> {
    let mut items = store.list_trust_bundles()?;
    if items.len() > MAX_TRUST_BUNDLES {
        return Err(AppError::new(
            ErrorCode::TrustBundleLimitExceeded,
            "managed trust bundle limit exceeded",
        ));
    }
    items.sort_by(|left, right| left.trust_bundle_ref.cmp(&right.trust_bundle_ref));
    Ok(items)
}

pub fn delete_trust_bundle<S, R, E>(
    store: &mut S,
    revisions: &R,
    events: &mut E,
    trust_bundle_ref: TrustBundleRef,
) -> Result<(), AppError>
where
    S: TrustBundleStore,
    R: RetainedConfigSnapshots,
    E: TrustBundleEventSink,
{
    let referenced = revisions.retained_config_snapshots()?.iter().any(|snapshot| {
        snapshot.listeners.iter().any(|listener| matches!(&listener.client_auth, ClientAuthPolicy::Required { trust_bundle_ref: reference } if reference == &trust_bundle_ref))
            || snapshot.services.iter().any(|service| service.upstreams.iter().any(|upstream| matches!(&upstream.tls, UpstreamTlsPolicy::ServerAuthenticated { trust_bundle_ref: reference, .. } if reference == &trust_bundle_ref)))
    });
    if referenced {
        let error = AppError::new(
            ErrorCode::TrustBundleReferenced,
            "trust bundle is referenced by a retained config revision",
        );
        record_delete_event(events, &trust_bundle_ref, "rejected", Some(error.code));
        return Err(error);
    }
    match store.delete_trust_bundle(&trust_bundle_ref) {
        Ok(()) => {
            record_delete_event(events, &trust_bundle_ref, "success", None);
            Ok(())
        }
        Err(error) => {
            record_delete_event(events, &trust_bundle_ref, "failure", Some(error.code));
            Err(error)
        }
    }
}

fn record_delete_event<E: TrustBundleEventSink>(
    events: &mut E,
    reference: &TrustBundleRef,
    outcome: &'static str,
    error_code: Option<ErrorCode>,
) {
    let event = TrustBundleOperationEvent {
        event: "trust_bundle.delete",
        trust_bundle_ref: reference.clone(),
        certificate_count: None,
        outcome,
        error_code,
    };
    events.record_trust_product_event(event.clone());
    events.record_trust_audit_event(event);
}

#[cfg(test)]
mod tests {
    use super::*;
    use edge_domain::{ConfigSnapshot, ErrorCode, TrustBundleRef};
    use edge_ports::ValidatedTrustBundle;

    #[derive(Default)]
    struct FakeValidator;
    impl TrustBundleMaterialValidator for FakeValidator {
        fn validate_trust_bundle(
            &mut self,
            reference: &TrustBundleRef,
            bytes: &[u8],
            imported_at: u64,
        ) -> Result<ValidatedTrustBundle, AppError> {
            Ok(ValidatedTrustBundle::new(
                TrustBundleMetadata {
                    trust_bundle_ref: reference.clone(),
                    certificate_count: 1,
                    imported_at_epoch_seconds: imported_at,
                    content_sha256: [0; 32],
                },
                bytes.to_vec(),
            ))
        }
    }

    #[derive(Default)]
    struct FakeStore {
        items: Vec<TrustBundleMetadata>,
        created: Vec<TrustBundleRef>,
        deleted: Vec<TrustBundleRef>,
    }
    impl FakeStore {
        fn with_refs(values: impl IntoIterator<Item = usize>) -> Self {
            Self {
                items: values
                    .into_iter()
                    .map(|value| TrustBundleMetadata {
                        trust_bundle_ref: TrustBundleRef::parse(&format!("root-{value:03}"))
                            .unwrap(),
                        certificate_count: 1,
                        imported_at_epoch_seconds: value as u64,
                        content_sha256: [0; 32],
                    })
                    .collect(),
                ..Self::default()
            }
        }
    }
    impl TrustBundleStore for FakeStore {
        fn create_trust_bundle(&mut self, bundle: ValidatedTrustBundle) -> Result<(), AppError> {
            if self.created.contains(&bundle.metadata.trust_bundle_ref) {
                return Err(AppError::new(
                    ErrorCode::TrustBundleAlreadyExists,
                    "trust bundle already exists",
                ));
            }
            self.created.push(bundle.metadata.trust_bundle_ref);
            Ok(())
        }
        fn list_trust_bundles(&mut self) -> Result<Vec<TrustBundleMetadata>, AppError> {
            Ok(self.items.clone())
        }
        fn delete_trust_bundle(&mut self, reference: &TrustBundleRef) -> Result<(), AppError> {
            self.deleted.push(reference.clone());
            Ok(())
        }
    }

    #[derive(Default)]
    struct FakeRevisions {
        snapshots: Vec<ConfigSnapshot>,
    }
    impl RetainedConfigSnapshots for FakeRevisions {
        fn retained_config_snapshots(&self) -> Result<Vec<ConfigSnapshot>, AppError> {
            Ok(self.snapshots.clone())
        }
    }
    #[derive(Default)]
    struct FakeEvents {
        product: Vec<TrustBundleOperationEvent>,
        audit: Vec<TrustBundleOperationEvent>,
    }
    impl TrustBundleEventSink for FakeEvents {
        fn record_trust_product_event(&mut self, event: TrustBundleOperationEvent) {
            self.product.push(event);
        }
        fn record_trust_audit_event(&mut self, event: TrustBundleOperationEvent) {
            self.audit.push(event);
        }
    }

    fn input(bytes: Vec<u8>) -> ImportTrustBundleInput {
        ImportTrustBundleInput {
            request_id: "request-1".into(),
            trust_bundle_ref: TrustBundleRef::parse("root-v1").unwrap(),
            encoded_material: bytes,
            imported_at_epoch_seconds: 10,
        }
    }

    #[test]
    fn import_validates_then_rejects_existing_reference() {
        let (mut validator, mut store, mut events) =
            (FakeValidator, FakeStore::default(), FakeEvents::default());
        let output = import_trust_bundle(
            &mut validator,
            &mut store,
            &mut events,
            input(vec![1, 2, 3]),
        )
        .unwrap();
        assert_eq!(output.certificate_count, 1);
        assert_eq!(store.created.len(), 1);
        assert_eq!(events.product[0].outcome, "success");
        let error = import_trust_bundle(
            &mut validator,
            &mut store,
            &mut events,
            input(vec![1, 2, 3]),
        )
        .unwrap_err();
        assert_eq!(error.code, ErrorCode::TrustBundleAlreadyExists);
        assert_eq!(store.created.len(), 1);
        assert_eq!(events.product[1].outcome, "failure");
    }

    #[test]
    fn import_rejects_encoded_limit_before_validation_or_create() {
        let (mut validator, mut store, mut events) =
            (FakeValidator, FakeStore::default(), FakeEvents::default());
        let error = import_trust_bundle(
            &mut validator,
            &mut store,
            &mut events,
            input(vec![0; MAX_ENCODED_TRUST_BUNDLE_BYTES + 1]),
        )
        .unwrap_err();
        assert_eq!(error.code, ErrorCode::TrustBundleLimitExceeded);
        assert!(store.created.is_empty());
        assert_eq!(events.product[0].outcome, "failure");
    }

    #[test]
    fn list_is_stably_ordered_and_bounded() {
        let mut store = FakeStore::with_refs((0..129).rev());
        assert_eq!(
            list_trust_bundles(&mut store).unwrap_err().code,
            ErrorCode::TrustBundleLimitExceeded
        );
        store.items.pop();
        let items = list_trust_bundles(&mut store).unwrap();
        assert_eq!(items.len(), 128);
        assert!(items
            .windows(2)
            .all(|pair| pair[0].trust_bundle_ref < pair[1].trust_bundle_ref));
    }

    #[test]
    fn delete_rejects_any_retained_revision_reference_before_store_mutation() {
        let mut snapshot = crate::tests::valid_snapshot("retained");
        snapshot.services[0].upstreams[0].tls = UpstreamTlsPolicy::ServerAuthenticated {
            server_name: edge_domain::TlsServerName::parse("backend.test").unwrap(),
            http_host: edge_domain::UpstreamHttpHost::parse("backend.test").unwrap(),
            trust_bundle_ref: TrustBundleRef::parse("root-v1").unwrap(),
        };
        let (mut store, revisions, mut events) = (
            FakeStore::default(),
            FakeRevisions {
                snapshots: vec![snapshot],
            },
            FakeEvents::default(),
        );
        let error = delete_trust_bundle(
            &mut store,
            &revisions,
            &mut events,
            TrustBundleRef::parse("root-v1").unwrap(),
        )
        .unwrap_err();
        assert_eq!(error.code, ErrorCode::TrustBundleReferenced);
        assert!(store.deleted.is_empty());
        assert_eq!(events.product[0].outcome, "rejected");
    }
}
