use std::{
    error::Error,
    fmt,
    fs::{self, File, OpenOptions},
    future::Future,
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
    pin::Pin,
};

use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, Payload},
};
use dtx_wire::StableCode;
use zeroize::Zeroizing;

use crate::{
    EncryptedDataKey, GeneratedDataKey, KeyManagement, KeyManagementError, KmsContext,
    KmsKeyVersion, SecretBytes,
};

const ROOT_KEY_BYTES: usize = 32;
const NONCE_BYTES: usize = 24;
const TAG_BYTES: usize = 16;
const ENVELOPE_DOMAIN: &[u8] = b"dtx.local-root-key-file-kms";
const ENVELOPE_HEADER: &[u8] = b"DTX-LRKF\x01";
const KEY_VERSION: &str = "local.root_key_file.v1";

mod production_sealed {
    pub trait Sealed {}
}

/// A key-management adapter that may satisfy a production broker's readiness boundary.
///
/// This trait is sealed. Test fakes can implement [`KeyManagement`], but cannot claim production
/// readiness outside this crate.
pub trait ProductionKeyManagement: KeyManagement + production_sealed::Sealed {}

/// Normalized error returned while loading a root wrapping-key file.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RootKeyFileError {
    InvalidPath,
    UnsafeFile,
    InvalidKeyLength,
    Unavailable,
}

impl fmt::Display for RootKeyFileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidPath => "root key file path is invalid",
            Self::UnsafeFile => "root key file does not satisfy required ownership and permissions",
            Self::InvalidKeyLength => "root key file has an invalid key length",
            Self::Unavailable => "root key file is unavailable",
        })
    }
}

impl Error for RootKeyFileError {}

/// Local Linux/WSL root-key-file KMS implementation.
///
/// [`Self::from_root_key_file`] requires a root-owned, non-symlink regular file with no group or
/// other permissions. [`Self::from_root_key_file_for_tests`] relaxes only the uid check and must
/// never be used for a production constructor.
pub struct LocalRootKeyFileKms {
    root_key: SecretBytes,
    key_version: KmsKeyVersion,
}

impl LocalRootKeyFileKms {
    /// Loads a production root wrapping key from an explicit absolute Linux/WSL file path.
    ///
    /// # Errors
    ///
    /// Returns [`RootKeyFileError`] when the path, file policy, key length, or local read fails.
    pub fn from_root_key_file(path: impl AsRef<Path>) -> Result<Self, RootKeyFileError> {
        Self::load(path.as_ref(), true)
    }

    /// Loads a test-only root wrapping key, retaining all file checks except root ownership.
    #[cfg(test)]
    pub(crate) fn from_root_key_file_for_tests(
        path: impl AsRef<Path>,
    ) -> Result<Self, RootKeyFileError> {
        Self::load(path.as_ref(), false)
    }

    fn load(path: &Path, require_root_owner: bool) -> Result<Self, RootKeyFileError> {
        if !path.is_absolute() {
            return Err(RootKeyFileError::InvalidPath);
        }

        // This preflight makes symlink rejection deterministic. The handle checks below remain
        // authoritative: O_NOFOLLOW and fstat protect against replacement after this check.
        let metadata = fs::symlink_metadata(path).map_err(|error| map_open_error(&error))?;
        validate_metadata(&metadata, require_root_owner)?;

        let mut file = open_without_following_symlinks(path)?;
        let handle_metadata = file.metadata().map_err(|_| RootKeyFileError::Unavailable)?;
        validate_metadata(&handle_metadata, require_root_owner)?;

        let root_key = read_root_key(&mut file)?;
        Ok(Self {
            root_key,
            key_version: KmsKeyVersion::new(
                StableCode::parse(KEY_VERSION).expect("constant key version is valid"),
            ),
        })
    }

    fn aad(context: &KmsContext) -> Zeroizing<Vec<u8>> {
        let mut aad = Zeroizing::new(Vec::with_capacity(128));
        aad.extend_from_slice(ENVELOPE_DOMAIN);
        append_aad_field(&mut aad, context.tenant_id().to_string().as_bytes());
        append_aad_field(&mut aad, context.secret_id().to_string().as_bytes());
        append_aad_field(&mut aad, context.purpose().as_str().as_bytes());
        aad
    }

    fn encrypt_dek(&self, dek: &[u8], context: &KmsContext) -> Result<Vec<u8>, KeyManagementError> {
        let mut nonce = [0_u8; NONCE_BYTES];
        getrandom::fill(&mut nonce).map_err(|_| KeyManagementError::Unavailable)?;
        let aad = Self::aad(context);
        let ciphertext = self.root_key.expose(|root_key| {
            let cipher = XChaCha20Poly1305::new_from_slice(root_key)
                .map_err(|_| KeyManagementError::Unavailable)?;
            cipher
                .encrypt(
                    &XNonce::from(nonce),
                    Payload {
                        msg: dek,
                        aad: &aad,
                    },
                )
                .map_err(|_| KeyManagementError::Unavailable)
        })?;
        let mut envelope =
            Vec::with_capacity(ENVELOPE_HEADER.len() + NONCE_BYTES + ciphertext.len());
        envelope.extend_from_slice(ENVELOPE_HEADER);
        envelope.extend_from_slice(&nonce);
        envelope.extend_from_slice(&ciphertext);
        Ok(envelope)
    }

    fn decrypt_dek(
        &self,
        encrypted: &EncryptedDataKey,
        context: &KmsContext,
    ) -> Result<SecretBytes, KeyManagementError> {
        if encrypted.key_version() != &self.key_version {
            return Err(KeyManagementError::UnknownKeyVersion);
        }
        let envelope = encrypted.opaque_bytes();
        let minimum = ENVELOPE_HEADER.len() + NONCE_BYTES + TAG_BYTES;
        if envelope.len() != minimum + ROOT_KEY_BYTES || !envelope.starts_with(ENVELOPE_HEADER) {
            return Err(KeyManagementError::InvalidCiphertext);
        }
        let nonce_start = ENVELOPE_HEADER.len();
        let nonce_end = nonce_start + NONCE_BYTES;
        let aad = Self::aad(context);
        let plaintext = self.root_key.expose(|root_key| {
            let cipher = XChaCha20Poly1305::new_from_slice(root_key)
                .map_err(|_| KeyManagementError::Unavailable)?;
            cipher
                .decrypt(
                    &XNonce::from(
                        <[u8; NONCE_BYTES]>::try_from(&envelope[nonce_start..nonce_end])
                            .map_err(|_| KeyManagementError::InvalidCiphertext)?,
                    ),
                    Payload {
                        msg: &envelope[nonce_end..],
                        aad: &aad,
                    },
                )
                .map_err(|_| KeyManagementError::InvalidCiphertext)
        })?;
        let plaintext = Zeroizing::new(plaintext);
        if plaintext.len() != ROOT_KEY_BYTES {
            return Err(KeyManagementError::InvalidCiphertext);
        }
        SecretBytes::new(plaintext.to_vec()).map_err(|_| KeyManagementError::InvalidCiphertext)
    }
}

impl production_sealed::Sealed for LocalRootKeyFileKms {}
impl ProductionKeyManagement for LocalRootKeyFileKms {}

impl KeyManagement for LocalRootKeyFileKms {
    fn generate_data_key<'a>(
        &'a self,
        context: &'a KmsContext,
    ) -> Pin<Box<dyn Future<Output = Result<GeneratedDataKey, KeyManagementError>> + Send + 'a>>
    {
        Box::pin(async move {
            let mut plaintext = Zeroizing::new(vec![0_u8; ROOT_KEY_BYTES]);
            getrandom::fill(&mut plaintext).map_err(|_| KeyManagementError::Unavailable)?;
            let encrypted = self.encrypt_dek(&plaintext, context)?;
            Ok(GeneratedDataKey {
                plaintext: SecretBytes::new(plaintext.to_vec())
                    .map_err(|_| KeyManagementError::Unavailable)?,
                encrypted: EncryptedDataKey::new(self.key_version.clone(), encrypted)
                    .map_err(|_| KeyManagementError::Unavailable)?,
            })
        })
    }

    fn decrypt_data_key<'a>(
        &'a self,
        encrypted: &'a EncryptedDataKey,
        context: &'a KmsContext,
    ) -> Pin<Box<dyn Future<Output = Result<SecretBytes, KeyManagementError>> + Send + 'a>> {
        Box::pin(async move { self.decrypt_dek(encrypted, context) })
    }
}

fn append_aad_field(aad: &mut Vec<u8>, value: &[u8]) {
    let length = u32::try_from(value.len()).expect("KMS context fields fit in u32");
    aad.extend_from_slice(&length.to_be_bytes());
    aad.extend_from_slice(value);
}

fn open_without_following_symlinks(path: &Path) -> Result<File, RootKeyFileError> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|error| map_open_error(&error))
}

fn map_open_error(error: &std::io::Error) -> RootKeyFileError {
    match error.kind() {
        std::io::ErrorKind::NotFound | std::io::ErrorKind::PermissionDenied => {
            RootKeyFileError::Unavailable
        }
        _ => RootKeyFileError::UnsafeFile,
    }
}

fn validate_metadata(
    metadata: &fs::Metadata,
    require_root_owner: bool,
) -> Result<(), RootKeyFileError> {
    validate_file_policy(
        metadata.file_type().is_file(),
        metadata.file_type().is_symlink(),
        metadata.mode(),
        metadata.uid(),
        require_root_owner,
    )?;
    if metadata.len() != ROOT_KEY_BYTES as u64 {
        return Err(RootKeyFileError::InvalidKeyLength);
    }
    Ok(())
}

fn read_root_key(reader: &mut impl Read) -> Result<SecretBytes, RootKeyFileError> {
    let mut bytes = Zeroizing::new([0_u8; ROOT_KEY_BYTES]);
    reader
        .read_exact(&mut *bytes)
        .map_err(|error| map_root_key_read_error(&error))?;

    let mut trailing = [0_u8; 1];
    match reader.read(&mut trailing) {
        Ok(0) => SecretBytes::new(bytes.to_vec()).map_err(|_| RootKeyFileError::InvalidKeyLength),
        Ok(_) => Err(RootKeyFileError::InvalidKeyLength),
        Err(error) => Err(map_root_key_read_error(&error)),
    }
}

fn map_root_key_read_error(error: &std::io::Error) -> RootKeyFileError {
    match error.kind() {
        std::io::ErrorKind::UnexpectedEof => RootKeyFileError::InvalidKeyLength,
        _ => RootKeyFileError::Unavailable,
    }
}

fn validate_file_policy(
    is_regular_file: bool,
    is_symlink: bool,
    mode: u32,
    uid: u32,
    require_root_owner: bool,
) -> Result<(), RootKeyFileError> {
    if !is_regular_file || is_symlink || mode & 0o077 != 0 || (require_root_owner && uid != 0) {
        return Err(RootKeyFileError::UnsafeFile);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        future::Future,
        os::unix::fs::PermissionsExt,
        task::{Context, Poll, Waker},
    };

    use super::*;
    use dtx_domain::{SecretId, TenantId};
    use dtx_wire::StableCode;

    fn context() -> KmsContext {
        KmsContext::new(
            TenantId::new(),
            SecretId::new(),
            // `StableCode` uses lower_snake_case segments; this is the internal AAD spelling
            // corresponding to the later runtime's `push-token.v1` purpose.
            StableCode::parse("push_token.v1").unwrap(),
        )
    }

    fn key_file(bytes: &[u8], mode: u32) -> tempfile::TempPath {
        let file = tempfile::NamedTempFile::new().unwrap();
        fs::write(file.path(), bytes).unwrap();
        fs::set_permissions(file.path(), fs::Permissions::from_mode(mode)).unwrap();
        file.into_temp_path()
    }

    fn block_on<F: Future>(future: F) -> F::Output {
        let waker: &Waker = Waker::noop();
        let mut context = Context::from_waker(waker);
        let mut future = Box::pin(future);
        match future.as_mut().poll(&mut context) {
            Poll::Ready(output) => output,
            Poll::Pending => panic!("local KMS future unexpectedly yielded"),
        }
    }

    #[test]
    fn test_constructor_enforces_absolute_symlink_mode_and_length() {
        assert!(matches!(
            LocalRootKeyFileKms::from_root_key_file_for_tests("relative-root-key"),
            Err(RootKeyFileError::InvalidPath)
        ));
        let path = key_file(&[7; ROOT_KEY_BYTES], 0o600);
        let link = path.with_extension("link");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(matches!(
            LocalRootKeyFileKms::from_root_key_file_for_tests(&link),
            Err(RootKeyFileError::UnsafeFile)
        ));
        let mode = key_file(&[7; ROOT_KEY_BYTES], 0o640);
        assert!(matches!(
            LocalRootKeyFileKms::from_root_key_file_for_tests(&mode),
            Err(RootKeyFileError::UnsafeFile)
        ));
        let length = key_file(&[7; ROOT_KEY_BYTES - 1], 0o600);
        assert!(matches!(
            LocalRootKeyFileKms::from_root_key_file_for_tests(&length),
            Err(RootKeyFileError::InvalidKeyLength)
        ));
        let oversized = key_file(&[7; ROOT_KEY_BYTES + 1], 0o600);
        assert!(matches!(
            LocalRootKeyFileKms::from_root_key_file_for_tests(&oversized),
            Err(RootKeyFileError::InvalidKeyLength)
        ));
    }

    #[test]
    fn bounded_root_key_reader_checks_one_trailing_byte_only() {
        struct CountingReader {
            bytes: Vec<u8>,
            offset: usize,
        }

        impl Read for CountingReader {
            fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
                let available = &self.bytes[self.offset..];
                let count = available.len().min(output.len());
                output[..count].copy_from_slice(&available[..count]);
                self.offset += count;
                Ok(count)
            }
        }

        let mut reader = CountingReader {
            bytes: vec![7; ROOT_KEY_BYTES + 4096],
            offset: 0,
        };
        assert!(matches!(
            read_root_key(&mut reader),
            Err(RootKeyFileError::InvalidKeyLength)
        ));
        assert_eq!(reader.offset, ROOT_KEY_BYTES + 1);
    }

    #[test]
    fn metadata_owner_policy_is_separate_from_test_constructor() {
        let path = key_file(&[7; ROOT_KEY_BYTES], 0o600);
        let metadata = fs::metadata(&path).unwrap();
        assert!(validate_metadata(&metadata, false).is_ok());
        assert_eq!(
            validate_file_policy(true, false, 0o600, 1, true),
            Err(RootKeyFileError::UnsafeFile)
        );
        assert!(validate_file_policy(true, false, 0o600, 0, true).is_ok());
        assert_eq!(
            validate_file_policy(false, false, 0o600, 0, true),
            Err(RootKeyFileError::UnsafeFile)
        );
    }

    #[test]
    fn wrapping_round_trip_is_fresh_and_context_bound() {
        let path = key_file(&[7; ROOT_KEY_BYTES], 0o600);
        let kms = LocalRootKeyFileKms::from_root_key_file_for_tests(&path).unwrap();
        let context = context();
        let first = block_on(kms.generate_data_key(&context)).unwrap();
        let second = block_on(kms.generate_data_key(&context)).unwrap();
        assert_ne!(
            first.encrypted.opaque_bytes(),
            second.encrypted.opaque_bytes()
        );
        first.plaintext.expose(|plain| {
            assert_eq!(plain.len(), ROOT_KEY_BYTES);
            assert_ne!(plain, &[]);
        });
        let mut same_plaintext = false;
        first.plaintext.expose(|left| {
            second
                .plaintext
                .expose(|right| same_plaintext = left == right);
        });
        assert!(!same_plaintext);
        let unwrapped = block_on(kms.decrypt_data_key(&first.encrypted, &context)).unwrap();
        let mut equal = false;
        first
            .plaintext
            .expose(|left| unwrapped.expose(|right| equal = left == right));
        assert!(equal);
        let mismatch = KmsContext::new(
            TenantId::new(),
            context.secret_id(),
            context.purpose().clone(),
        );
        assert!(matches!(
            block_on(kms.decrypt_data_key(&first.encrypted, &mismatch)),
            Err(KeyManagementError::InvalidCiphertext)
        ));
    }

    #[test]
    fn envelope_rejects_tampering_versions_truncation_trailing_and_bounds() {
        let path = key_file(&[7; ROOT_KEY_BYTES], 0o600);
        let kms = LocalRootKeyFileKms::from_root_key_file_for_tests(&path).unwrap();
        let context = context();
        let generated = block_on(kms.generate_data_key(&context)).unwrap();
        for offset in [
            0,
            ENVELOPE_HEADER.len(),
            ENVELOPE_HEADER.len() + NONCE_BYTES,
        ] {
            let mut tampered = generated.encrypted.opaque_bytes().to_vec();
            tampered[offset] ^= 1;
            let encrypted =
                EncryptedDataKey::new(generated.encrypted.key_version().clone(), tampered).unwrap();
            assert!(matches!(
                block_on(kms.decrypt_data_key(&encrypted, &context)),
                Err(KeyManagementError::InvalidCiphertext)
            ));
        }
        for length in [
            0,
            ENVELOPE_HEADER.len() - 1,
            generated.encrypted.opaque_bytes().len() - 1,
        ] {
            let encrypted = EncryptedDataKey::new(
                generated.encrypted.key_version().clone(),
                generated.encrypted.opaque_bytes()[..length].to_vec(),
            );
            if let Ok(encrypted) = encrypted {
                assert!(matches!(
                    block_on(kms.decrypt_data_key(&encrypted, &context)),
                    Err(KeyManagementError::InvalidCiphertext)
                ));
            }
        }
        let mut trailing = generated.encrypted.opaque_bytes().to_vec();
        trailing.push(0);
        let encrypted =
            EncryptedDataKey::new(generated.encrypted.key_version().clone(), trailing).unwrap();
        assert!(matches!(
            block_on(kms.decrypt_data_key(&encrypted, &context)),
            Err(KeyManagementError::InvalidCiphertext)
        ));
        let unknown = EncryptedDataKey::new(
            KmsKeyVersion::new(StableCode::parse("other.v1").unwrap()),
            generated.encrypted.opaque_bytes().to_vec(),
        )
        .unwrap();
        assert!(matches!(
            block_on(kms.decrypt_data_key(&unknown, &context)),
            Err(KeyManagementError::UnknownKeyVersion)
        ));
        assert!(
            EncryptedDataKey::new(
                generated.encrypted.key_version().clone(),
                vec![0; crate::MAX_ENCRYPTED_DATA_KEY_BYTES + 1]
            )
            .is_err()
        );
    }

    #[test]
    fn errors_are_normalized_and_redacted() {
        let error = RootKeyFileError::UnsafeFile;
        assert_eq!(
            error.to_string(),
            "root key file does not satisfy required ownership and permissions"
        );
        assert!(!format!("{error:?}").contains('/'));
    }

    #[test]
    fn local_adapter_is_the_sealed_production_ready_type() {
        fn requires_production<T: ProductionKeyManagement>() {}
        requires_production::<LocalRootKeyFileKms>();
    }
}
