use std::{error::Error, fmt, future::Future, pin::Pin};

use dtx_domain::{SecretId, TenantId};
use dtx_wire::StableCode;
use zeroize::{ZeroizeOnDrop, Zeroizing};

/// Maximum secret size accepted at the in-memory security boundary.
pub const MAX_SECRET_BYTES: usize = 64 * 1024;
/// Maximum provider-encrypted data-key representation retained by the broker.
pub const MAX_ENCRYPTED_DATA_KEY_BYTES: usize = 8 * 1024;

/// Secret material that is zeroized on drop and cannot be cloned or formatted.
///
/// ```compile_fail
/// use dtx_security::SecretBytes;
/// let secret = SecretBytes::new(vec![1; 32]).unwrap();
/// let duplicated = secret.clone();
/// ```
///
/// ```compile_fail
/// use dtx_security::SecretBytes;
/// let secret = SecretBytes::new(vec![1; 32]).unwrap();
/// println!("{secret:?}");
/// ```
pub struct SecretBytes(Zeroizing<Vec<u8>>);

impl ZeroizeOnDrop for SecretBytes {}

impl SecretBytes {
    /// Creates a non-empty bounded secret.
    ///
    /// # Errors
    ///
    /// Returns [`SecretBoundaryError`] when the value is empty or exceeds the boundary.
    pub fn new(value: Vec<u8>) -> Result<Self, SecretBoundaryError> {
        let value = Zeroizing::new(value);
        if value.is_empty() || value.len() > MAX_SECRET_BYTES {
            Err(SecretBoundaryError::InvalidSecretLength)
        } else {
            Ok(Self(value))
        }
    }

    /// Exposes the secret only for the lexical lifetime of the supplied closure.
    pub fn expose<T>(&self, use_secret: impl FnOnce(&[u8]) -> T) -> T {
        use_secret(self.0.as_slice())
    }

    /// Returns the secret byte length without exposing its value.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns whether this value is empty. Valid instances always return `false`.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// A secret value or encrypted-key representation violated a size boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecretBoundaryError {
    /// Plaintext secret material was empty or too large.
    InvalidSecretLength,
    /// The encrypted data-key representation was empty or too large.
    InvalidEncryptedDataKeyLength,
}

impl fmt::Display for SecretBoundaryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidSecretLength => "secret length is outside the allowed boundary",
            Self::InvalidEncryptedDataKeyLength => {
                "encrypted data key length is outside the allowed boundary"
            }
        })
    }
}

impl Error for SecretBoundaryError {}

/// Stable provider key version used to wrap a data key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KmsKeyVersion(StableCode);

impl KmsKeyVersion {
    /// Creates a version from a bounded stable code.
    #[must_use]
    pub const fn new(value: StableCode) -> Self {
        Self(value)
    }

    /// Returns the stable version code.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

/// Typed, non-secret associated context bound to every data key operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KmsContext {
    tenant_id: TenantId,
    secret_id: SecretId,
    purpose: StableCode,
}

impl KmsContext {
    /// Creates context that prevents a wrapped key moving across tenant, secret, or purpose.
    #[must_use]
    pub const fn new(tenant_id: TenantId, secret_id: SecretId, purpose: StableCode) -> Self {
        Self {
            tenant_id,
            secret_id,
            purpose,
        }
    }

    #[must_use]
    pub const fn tenant_id(&self) -> TenantId {
        self.tenant_id
    }

    #[must_use]
    pub const fn secret_id(&self) -> SecretId {
        self.secret_id
    }

    #[must_use]
    pub const fn purpose(&self) -> &StableCode {
        &self.purpose
    }
}

/// Provider-encrypted data key safe to persist but not to interpret.
#[derive(Clone, Eq, PartialEq)]
pub struct EncryptedDataKey {
    key_version: KmsKeyVersion,
    opaque_bytes: Vec<u8>,
}

impl EncryptedDataKey {
    /// Creates a bounded opaque provider representation.
    ///
    /// # Errors
    ///
    /// Rejects empty and oversized representations.
    pub fn new(
        key_version: KmsKeyVersion,
        opaque_bytes: Vec<u8>,
    ) -> Result<Self, SecretBoundaryError> {
        if opaque_bytes.is_empty() || opaque_bytes.len() > MAX_ENCRYPTED_DATA_KEY_BYTES {
            Err(SecretBoundaryError::InvalidEncryptedDataKeyLength)
        } else {
            Ok(Self {
                key_version,
                opaque_bytes,
            })
        }
    }

    #[must_use]
    pub const fn key_version(&self) -> &KmsKeyVersion {
        &self.key_version
    }

    /// Returns provider ciphertext/handle bytes; this never returns plaintext key material.
    #[must_use]
    pub fn opaque_bytes(&self) -> &[u8] {
        &self.opaque_bytes
    }
}

impl fmt::Debug for EncryptedDataKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EncryptedDataKey")
            .field("key_version", &self.key_version)
            .field("opaque_bytes", &"[REDACTED]")
            .field("opaque_len", &self.opaque_bytes.len())
            .finish()
    }
}

/// Plaintext and encrypted halves returned by a data-key generation request.
pub struct GeneratedDataKey {
    pub plaintext: SecretBytes,
    pub encrypted: EncryptedDataKey,
}

/// Stable failure from a KMS/HSM boundary; errors never contain provider payloads or keys.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyManagementError {
    Unavailable,
    Throttled,
    UnknownKeyVersion,
    InvalidCiphertext,
    ContextMismatch,
}

impl fmt::Display for KeyManagementError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Unavailable => "key management service is unavailable",
            Self::Throttled => "key management service throttled the request",
            Self::UnknownKeyVersion => "key management key version is unknown",
            Self::InvalidCiphertext => "encrypted data key is invalid",
            Self::ContextMismatch => "encrypted data key context does not match",
        })
    }
}

impl Error for KeyManagementError {}

/// Async object-safe port implemented by production KMS/HSM adapters and test fakes.
pub trait KeyManagement: Send + Sync {
    fn generate_data_key<'a>(
        &'a self,
        context: &'a KmsContext,
    ) -> Pin<Box<dyn Future<Output = Result<GeneratedDataKey, KeyManagementError>> + Send + 'a>>;

    fn decrypt_data_key<'a>(
        &'a self,
        encrypted: &'a EncryptedDataKey,
        context: &'a KmsContext,
    ) -> Pin<Box<dyn Future<Output = Result<SecretBytes, KeyManagementError>> + Send + 'a>>;
}
