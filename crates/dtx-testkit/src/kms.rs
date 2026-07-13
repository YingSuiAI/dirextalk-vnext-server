use std::{
    collections::{HashMap, VecDeque},
    fmt,
    future::Future,
    pin::Pin,
    sync::{Mutex, MutexGuard},
};

use dtx_security::{
    EncryptedDataKey, GeneratedDataKey, KeyManagement, KeyManagementError, KmsContext,
    KmsKeyVersion, SecretBytes,
};
use uuid::Uuid;
use zeroize::Zeroizing;

/// KMS operation recorded by the fake without request or key material.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KmsOperation {
    GenerateDataKey,
    DecryptDataKey,
}

/// Redacted outcome retained by [`FakeKms`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KmsCallOutcome {
    Succeeded,
    Failed(KeyManagementError),
}

/// A redacted KMS call record suitable for contract assertions.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KmsCallRecord {
    operation: KmsOperation,
    outcome: KmsCallOutcome,
    context: KmsContext,
    key_version: KmsKeyVersion,
}

impl KmsCallRecord {
    #[must_use]
    pub const fn operation(&self) -> KmsOperation {
        self.operation
    }

    #[must_use]
    pub const fn outcome(&self) -> KmsCallOutcome {
        self.outcome
    }

    #[must_use]
    pub const fn context(&self) -> &KmsContext {
        &self.context
    }

    #[must_use]
    pub const fn key_version(&self) -> &KmsKeyVersion {
        &self.key_version
    }
}

struct StoredDataKey {
    context: KmsContext,
    key_version: KmsKeyVersion,
    material: Zeroizing<Vec<u8>>,
}

struct FakeKmsState {
    queued_material: VecDeque<SecretBytes>,
    stored_keys: HashMap<Vec<u8>, StoredDataKey>,
    failures: VecDeque<(KmsOperation, KeyManagementError)>,
    calls: Vec<KmsCallRecord>,
    next_handle: u64,
}

/// Explicit test KMS backed by opaque `UUIDv7` handles and an in-memory key map.
///
/// This fake performs no encryption and provides no confidentiality. The encrypted-key bytes are
/// only lookup handles for deterministic contract tests.
pub struct FakeKms {
    key_version: KmsKeyVersion,
    state: Mutex<FakeKmsState>,
}

impl FakeKms {
    /// Creates a fake whose generation calls consume the supplied secret material in order.
    #[must_use]
    pub fn new(
        key_version: KmsKeyVersion,
        material: impl IntoIterator<Item = SecretBytes>,
    ) -> Self {
        Self {
            key_version,
            state: Mutex::new(FakeKmsState {
                queued_material: material.into_iter().collect(),
                stored_keys: HashMap::new(),
                failures: VecDeque::new(),
                calls: Vec::new(),
                next_handle: 1,
            }),
        }
    }

    /// Injects one stable error into the next matching operation.
    pub fn fail_next(&self, operation: KmsOperation, error: KeyManagementError) {
        self.state().failures.push_back((operation, error));
    }

    /// Returns a redacted snapshot of calls in observed order.
    #[must_use]
    pub fn calls(&self) -> Vec<KmsCallRecord> {
        self.state().calls.clone()
    }

    fn state(&self) -> MutexGuard<'_, FakeKmsState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl fmt::Debug for FakeKms {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FakeKms")
            .field("key_version", &self.key_version)
            .finish_non_exhaustive()
    }
}

impl KeyManagement for FakeKms {
    fn generate_data_key<'a>(
        &'a self,
        context: &'a KmsContext,
    ) -> Pin<Box<dyn Future<Output = Result<GeneratedDataKey, KeyManagementError>> + Send + 'a>>
    {
        Box::pin(async move {
            let mut state = self.state();
            if let Some(error) = take_failure(&mut state, KmsOperation::GenerateDataKey) {
                record_call(
                    &mut state,
                    KmsOperation::GenerateDataKey,
                    KmsCallOutcome::Failed(error),
                    context,
                    &self.key_version,
                );
                return Err(error);
            }

            let Some(plaintext) = state.queued_material.pop_front() else {
                let error = KeyManagementError::Unavailable;
                record_call(
                    &mut state,
                    KmsOperation::GenerateDataKey,
                    KmsCallOutcome::Failed(error),
                    context,
                    &self.key_version,
                );
                return Err(error);
            };

            let Some(opaque_handle) = next_handle(&mut state) else {
                let error = KeyManagementError::Unavailable;
                record_call(
                    &mut state,
                    KmsOperation::GenerateDataKey,
                    KmsCallOutcome::Failed(error),
                    context,
                    &self.key_version,
                );
                return Err(error);
            };
            let encrypted = EncryptedDataKey::new(self.key_version.clone(), opaque_handle.clone())
                .map_err(|_| KeyManagementError::Unavailable)?;
            let mut stored_material = Zeroizing::new(Vec::new());
            plaintext.expose(|bytes| stored_material.extend_from_slice(bytes));
            state.stored_keys.insert(
                opaque_handle,
                StoredDataKey {
                    context: context.clone(),
                    key_version: self.key_version.clone(),
                    material: stored_material,
                },
            );
            record_call(
                &mut state,
                KmsOperation::GenerateDataKey,
                KmsCallOutcome::Succeeded,
                context,
                &self.key_version,
            );
            Ok(GeneratedDataKey {
                plaintext,
                encrypted,
            })
        })
    }

    fn decrypt_data_key<'a>(
        &'a self,
        encrypted: &'a EncryptedDataKey,
        context: &'a KmsContext,
    ) -> Pin<Box<dyn Future<Output = Result<SecretBytes, KeyManagementError>> + Send + 'a>> {
        Box::pin(async move {
            let mut state = self.state();
            if let Some(error) = take_failure(&mut state, KmsOperation::DecryptDataKey) {
                record_call(
                    &mut state,
                    KmsOperation::DecryptDataKey,
                    KmsCallOutcome::Failed(error),
                    context,
                    encrypted.key_version(),
                );
                return Err(error);
            }
            if encrypted.key_version() != &self.key_version {
                let error = KeyManagementError::UnknownKeyVersion;
                record_call(
                    &mut state,
                    KmsOperation::DecryptDataKey,
                    KmsCallOutcome::Failed(error),
                    context,
                    encrypted.key_version(),
                );
                return Err(error);
            }

            let result = match state.stored_keys.get(encrypted.opaque_bytes()) {
                None => Err(KeyManagementError::InvalidCiphertext),
                Some(stored) if stored.key_version != *encrypted.key_version() => {
                    Err(KeyManagementError::UnknownKeyVersion)
                }
                Some(stored) if stored.context != *context => {
                    Err(KeyManagementError::ContextMismatch)
                }
                Some(stored) => SecretBytes::new(stored.material.as_slice().to_vec())
                    .map_err(|_| KeyManagementError::Unavailable),
            };
            let outcome = result.as_ref().map_or_else(
                |error| KmsCallOutcome::Failed(*error),
                |_| KmsCallOutcome::Succeeded,
            );
            record_call(
                &mut state,
                KmsOperation::DecryptDataKey,
                outcome,
                context,
                encrypted.key_version(),
            );
            result
        })
    }
}

fn take_failure(state: &mut FakeKmsState, operation: KmsOperation) -> Option<KeyManagementError> {
    let index = state
        .failures
        .iter()
        .position(|(candidate, _)| *candidate == operation)?;
    state.failures.remove(index).map(|(_, error)| error)
}

fn record_call(
    state: &mut FakeKmsState,
    operation: KmsOperation,
    outcome: KmsCallOutcome,
    context: &KmsContext,
    key_version: &KmsKeyVersion,
) {
    state.calls.push(KmsCallRecord {
        operation,
        outcome,
        context: context.clone(),
        key_version: key_version.clone(),
    });
}

fn next_handle(state: &mut FakeKmsState) -> Option<Vec<u8>> {
    let sequence = state.next_handle;
    state.next_handle = sequence.checked_add(1)?;
    let mut bytes = [0_u8; 16];
    bytes[8..].copy_from_slice(&sequence.to_be_bytes());
    bytes[6] = 0x70;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let candidate = Uuid::from_bytes(bytes).as_bytes().to_vec();
    (!state.stored_keys.contains_key(&candidate)).then_some(candidate)
}
