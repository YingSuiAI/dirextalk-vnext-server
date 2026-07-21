use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, Payload},
};
use dtx_domain::{SecretId, TenantId};
use dtx_security::{
    EncryptedDataKey, KeyManagement, KeyManagementError, KmsContext, KmsKeyVersion,
};
use dtx_wire::StableCode;
use std::str::FromStr;
use zeroize::Zeroizing;

use crate::model::{PushError, RegistrationBinding, SecretToken};

pub const TOKEN_PURPOSE: &str = "push_token.v1";
pub const ENVELOPE_VERSION: u8 = 1;
const AAD_DOMAIN: &[u8] = b"dirextalk.opaque-push.token.v1";
const NONCE_BYTES: usize = 24;

/// Checked, persistence-safe representation of a token envelope.
#[derive(Clone, Eq, PartialEq)]
pub struct TokenEnvelopeParts {
    envelope_version: u8,
    nonce: [u8; NONCE_BYTES],
    ciphertext: Vec<u8>,
    encrypted_dek: Vec<u8>,
    key_version: String,
    context: Vec<u8>,
}
impl TokenEnvelopeParts {
    pub fn new(
        envelope_version: u8,
        nonce: Vec<u8>,
        ciphertext: Vec<u8>,
        encrypted_dek: Vec<u8>,
        key_version: String,
        context: Vec<u8>,
    ) -> Result<Self, PushError> {
        let nonce: [u8; NONCE_BYTES] = nonce.try_into().map_err(|_| PushError::EnvelopeInvalid)?;
        if envelope_version != ENVELOPE_VERSION
            || !(17..=4112).contains(&ciphertext.len())
            || encrypted_dek.is_empty()
            || encrypted_dek.len() > dtx_security::MAX_ENCRYPTED_DATA_KEY_BYTES
            || key_version.is_empty()
            || key_version.len() > 256
            || StableCode::parse(&key_version).is_err()
            || parse_context(&context).is_none()
        {
            return Err(PushError::EnvelopeInvalid);
        }
        Ok(Self {
            envelope_version,
            nonce,
            ciphertext,
            encrypted_dek,
            key_version,
            context,
        })
    }
    pub const fn envelope_version(&self) -> u8 {
        self.envelope_version
    }
    pub const fn nonce(&self) -> &[u8; NONCE_BYTES] {
        &self.nonce
    }
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }
    pub fn encrypted_dek(&self) -> &[u8] {
        &self.encrypted_dek
    }
    pub fn key_version(&self) -> &str {
        &self.key_version
    }
    pub fn context(&self) -> &[u8] {
        &self.context
    }
    pub fn registration_binding(&self) -> RegistrationBinding {
        parse_context(&self.context).expect("checked parts retain canonical context")
    }
}
impl std::fmt::Debug for TokenEnvelopeParts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenEnvelopeParts")
            .field("envelope_version", &self.envelope_version)
            .field("nonce", &"[REDACTED]")
            .field("ciphertext_len", &self.ciphertext.len())
            .field("encrypted_dek_len", &self.encrypted_dek.len())
            .field("key_version", &self.key_version)
            .field("context_len", &self.context.len())
            .finish()
    }
}

/// Persistable token envelope. None of its formatting methods include plaintext.
#[derive(Clone, Eq, PartialEq)]
pub struct TokenEnvelope {
    ciphertext: Vec<u8>,
    nonce: [u8; NONCE_BYTES],
    encrypted_dek: EncryptedDataKey,
    context: Vec<u8>,
}
impl std::fmt::Debug for TokenEnvelope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenEnvelope")
            .field("ciphertext_len", &self.ciphertext.len())
            .field("nonce", &"[REDACTED]")
            .field("encrypted_dek", &self.encrypted_dek)
            .field("context_len", &self.context.len())
            .finish()
    }
}
impl TokenEnvelope {
    pub fn into_parts(self) -> TokenEnvelopeParts {
        TokenEnvelopeParts {
            envelope_version: ENVELOPE_VERSION,
            nonce: self.nonce,
            ciphertext: self.ciphertext,
            encrypted_dek: self.encrypted_dek.opaque_bytes().to_vec(),
            key_version: self.encrypted_dek.key_version().as_str().to_owned(),
            context: self.context,
        }
    }
    pub fn try_from_parts(parts: TokenEnvelopeParts) -> Result<Self, PushError> {
        let key_version = KmsKeyVersion::new(
            StableCode::parse(&parts.key_version).map_err(|_| PushError::EnvelopeInvalid)?,
        );
        let encrypted_dek = EncryptedDataKey::new(key_version, parts.encrypted_dek)
            .map_err(|_| PushError::EnvelopeInvalid)?;
        Ok(Self {
            ciphertext: parts.ciphertext,
            nonce: parts.nonce,
            encrypted_dek,
            context: parts.context,
        })
    }
    pub fn registration_binding(&self) -> RegistrationBinding {
        parse_context(&self.context).expect("envelope construction checks canonical context")
    }
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }
    pub const fn nonce(&self) -> &[u8; NONCE_BYTES] {
        &self.nonce
    }
    pub fn encrypted_dek(&self) -> &EncryptedDataKey {
        &self.encrypted_dek
    }
    pub fn encryption_context(&self) -> &[u8] {
        &self.context
    }

    pub fn to_frame(&self) -> Vec<u8> {
        let version = self.encrypted_dek.key_version().as_str().as_bytes();
        let opaque = self.encrypted_dek.opaque_bytes();
        let mut out = Vec::new();
        out.push(ENVELOPE_VERSION);
        append_u16(&mut out, version);
        append_u16(&mut out, opaque);
        out.extend_from_slice(&self.nonce);
        append_u32(&mut out, &self.ciphertext);
        append_u32(&mut out, &self.context);
        out
    }

    pub fn from_frame(frame: &[u8]) -> Result<Self, PushError> {
        let mut cursor = Cursor {
            bytes: frame,
            offset: 0,
        };
        if cursor.take_u8()? != ENVELOPE_VERSION {
            return Err(PushError::EnvelopeInvalid);
        }
        let version = cursor.take_vec_u16_bounded(1, 256)?;
        let opaque = cursor.take_vec_u16_bounded(1, dtx_security::MAX_ENCRYPTED_DATA_KEY_BYTES)?;
        let nonce = cursor.take_array_24()?;
        let ciphertext = cursor.take_vec_u32_bounded(17, 4112)?;
        let context = cursor.take_vec_u32_bounded(1, 4096)?;
        if cursor.offset != frame.len() || parse_context(&context).is_none() {
            return Err(PushError::EnvelopeInvalid);
        }
        let text = std::str::from_utf8(&version).map_err(|_| PushError::EnvelopeInvalid)?;
        let key_version =
            KmsKeyVersion::new(StableCode::parse(text).map_err(|_| PushError::EnvelopeInvalid)?);
        let encrypted_dek =
            EncryptedDataKey::new(key_version, opaque).map_err(|_| PushError::EnvelopeInvalid)?;
        Ok(Self {
            ciphertext,
            nonce,
            encrypted_dek,
            context,
        })
    }
}

fn append_u16(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(
        &(u16::try_from(bytes.len()).expect("bounded envelope field")).to_be_bytes(),
    );
    out.extend_from_slice(bytes);
}
fn append_u32(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(
        &(u32::try_from(bytes.len()).expect("bounded envelope field")).to_be_bytes(),
    );
    out.extend_from_slice(bytes);
}
struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}
impl<'a> Cursor<'a> {
    fn take(&mut self, len: usize) -> Result<&'a [u8], PushError> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or(PushError::EnvelopeInvalid)?;
        let out = self
            .bytes
            .get(self.offset..end)
            .ok_or(PushError::EnvelopeInvalid)?;
        self.offset = end;
        Ok(out)
    }
    fn take_u8(&mut self) -> Result<u8, PushError> {
        Ok(*self.take(1)?.first().ok_or(PushError::EnvelopeInvalid)?)
    }
    fn take_u16(&mut self) -> Result<usize, PushError> {
        Ok(u16::from_be_bytes(
            self.take(2)?
                .try_into()
                .map_err(|_| PushError::EnvelopeInvalid)?,
        ) as usize)
    }
    fn take_u32(&mut self) -> Result<usize, PushError> {
        Ok(u32::from_be_bytes(
            self.take(4)?
                .try_into()
                .map_err(|_| PushError::EnvelopeInvalid)?,
        ) as usize)
    }
    fn take_vec_u16_bounded(&mut self, min: usize, max: usize) -> Result<Vec<u8>, PushError> {
        let len = self.take_u16()?;
        if !(min..=max).contains(&len) {
            return Err(PushError::EnvelopeInvalid);
        }
        Ok(self.take(len)?.to_vec())
    }
    fn take_vec_u32_bounded(&mut self, min: usize, max: usize) -> Result<Vec<u8>, PushError> {
        let len = self.take_u32()?;
        if !(min..=max).contains(&len) {
            return Err(PushError::EnvelopeInvalid);
        }
        Ok(self.take(len)?.to_vec())
    }
    fn take_array_24(&mut self) -> Result<[u8; NONCE_BYTES], PushError> {
        self.take(NONCE_BYTES)?
            .try_into()
            .map_err(|_| PushError::EnvelopeInvalid)
    }
}

/// Validate the serialized purpose and the *canonical* five-field AAD before
/// decrypting or handing its wrapped key to KMS.  This deliberately does not
/// merely prefix-match the purpose.
fn parse_context(context: &[u8]) -> Option<RegistrationBinding> {
    let aad_bytes = context.strip_prefix(TOKEN_PURPOSE.as_bytes())?;
    let aad_bytes = aad_bytes.strip_prefix(&[0])?;
    let rest = aad_bytes.strip_prefix(AAD_DOMAIN)?;
    let mut cursor = Cursor {
        bytes: rest,
        offset: 0,
    };
    let Ok(tenant) = cursor.take_vec_u32_bounded(36, 36) else {
        return None;
    };
    let Ok(identity) = cursor.take_vec_u32_bounded(1, 128) else {
        return None;
    };
    let Ok(device) = cursor.take_vec_u32_bounded(36, 36) else {
        return None;
    };
    let Ok(provider) = cursor.take_vec_u32_bounded(3, 3) else {
        return None;
    };
    let Ok(revision) = cursor.take_vec_u32_bounded(1, 16) else {
        return None;
    };
    if cursor.offset != rest.len() || provider != b"fcm" {
        return None;
    }
    let (Some(tenant), Some(identity), Some(device), Some(revision)) = (
        std::str::from_utf8(&tenant)
            .ok()
            .and_then(|value| TenantId::from_str(value).ok()),
        std::str::from_utf8(&identity)
            .ok()
            .and_then(|value| dtx_domain::IdentityId::from_str(value).ok()),
        std::str::from_utf8(&device)
            .ok()
            .and_then(|value| dtx_domain::DeviceId::from_str(value).ok()),
        std::str::from_utf8(&revision)
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .and_then(|value| dtx_domain::Revision::new(value).ok()),
    ) else {
        return None;
    };
    let canonical = aad(RegistrationBinding {
        tenant_id: tenant,
        identity_id: identity,
        device_id: device,
        provider: crate::Provider::Fcm,
        revision,
    });
    (canonical == aad_bytes).then_some(RegistrationBinding {
        tenant_id: tenant,
        identity_id: identity,
        device_id: device,
        provider: crate::Provider::Fcm,
        revision,
    })
}

fn field(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}
fn aad(binding: RegistrationBinding) -> Vec<u8> {
    let mut out = Vec::with_capacity(200);
    out.extend_from_slice(AAD_DOMAIN);
    field(&mut out, binding.tenant_id.to_string().as_bytes());
    field(&mut out, binding.identity_id.to_string().as_bytes());
    field(&mut out, binding.device_id.to_string().as_bytes());
    field(&mut out, binding.provider.as_str().as_bytes());
    field(&mut out, binding.revision.get().to_string().as_bytes());
    out
}
fn kms_context(tenant_id: TenantId, secret_id: SecretId) -> KmsContext {
    KmsContext::new(
        tenant_id,
        secret_id,
        StableCode::parse(TOKEN_PURPOSE).expect("constant purpose"),
    )
}

pub struct TokenEncryptionService<K> {
    kms: K,
}

pub struct ProductionTokenEncryptionService<K: dtx_security::ProductionKeyManagement> {
    inner: TokenEncryptionService<K>,
}
impl<K: dtx_security::ProductionKeyManagement> ProductionTokenEncryptionService<K> {
    pub fn new(kms: K) -> Self {
        Self {
            inner: TokenEncryptionService::new(kms),
        }
    }
    pub async fn seal(
        &self,
        binding: RegistrationBinding,
        secret_id: SecretId,
        token: &SecretToken,
    ) -> Result<TokenEnvelope, PushError> {
        self.inner.encrypt(binding, secret_id, token).await
    }
    pub async fn open(
        &self,
        binding: RegistrationBinding,
        secret_id: SecretId,
        envelope: &TokenEnvelope,
    ) -> Result<SecretToken, PushError> {
        self.inner.decrypt(binding, secret_id, envelope).await
    }
}
impl<K> TokenEncryptionService<K> {
    pub(crate) fn new(kms: K) -> Self {
        Self { kms }
    }
    #[cfg(test)]
    pub(crate) fn new_for_tests(kms: K) -> Self {
        Self::new(kms)
    }
}

impl<K: KeyManagement> TokenEncryptionService<K> {
    pub async fn encrypt(
        &self,
        binding: RegistrationBinding,
        secret_id: SecretId,
        token: &SecretToken,
    ) -> Result<TokenEnvelope, PushError> {
        let context = kms_context(binding.tenant_id, secret_id);
        let generated = self
            .kms
            .generate_data_key(&context)
            .await
            .map_err(|_| PushError::Encryption)?;
        let mut nonce = [0_u8; NONCE_BYTES];
        getrandom::fill(&mut nonce).map_err(|_| PushError::Encryption)?;
        let associated = aad(binding);
        let ciphertext = generated.plaintext.expose(|dek| {
            let cipher =
                XChaCha20Poly1305::new_from_slice(dek).map_err(|_| PushError::Encryption)?;
            token.expose(|plaintext| {
                cipher
                    .encrypt(
                        &XNonce::from(nonce),
                        Payload {
                            msg: plaintext,
                            aad: &associated,
                        },
                    )
                    .map_err(|_| PushError::Encryption)
            })
        })?;
        let mut context_bytes = Vec::with_capacity(64 + associated.len());
        context_bytes.extend_from_slice(TOKEN_PURPOSE.as_bytes());
        context_bytes.push(0);
        context_bytes.extend_from_slice(&associated);
        Ok(TokenEnvelope {
            ciphertext,
            nonce,
            encrypted_dek: generated.encrypted,
            context: context_bytes,
        })
    }

    pub async fn decrypt(
        &self,
        binding: RegistrationBinding,
        secret_id: SecretId,
        envelope: &TokenEnvelope,
    ) -> Result<SecretToken, PushError> {
        let context = kms_context(binding.tenant_id, secret_id);
        let associated = aad(binding);
        let mut expected_context = Vec::with_capacity(TOKEN_PURPOSE.len() + 1 + associated.len());
        expected_context.extend_from_slice(TOKEN_PURPOSE.as_bytes());
        expected_context.push(0);
        expected_context.extend_from_slice(&associated);
        if envelope.context != expected_context {
            return Err(PushError::ContextMismatch);
        }
        let dek = self
            .kms
            .decrypt_data_key(&envelope.encrypted_dek, &context)
            .await
            .map_err(map_kms_error)?;
        let plaintext: Zeroizing<Vec<u8>> = dek
            .expose(|key| {
                XChaCha20Poly1305::new_from_slice(key)
                    .map_err(|_| PushError::Decryption)
                    .and_then(|cipher| {
                        cipher
                            .decrypt(
                                &XNonce::from(envelope.nonce),
                                Payload {
                                    msg: &envelope.ciphertext,
                                    aad: &associated,
                                },
                            )
                            .map_err(|_| PushError::Decryption)
                    })
            })?
            .into();
        SecretToken::new(plaintext.to_vec())
    }
}

fn map_kms_error(error: KeyManagementError) -> PushError {
    match error {
        KeyManagementError::ContextMismatch => PushError::ContextMismatch,
        _ => PushError::Decryption,
    }
}
