use base64ct::{Base64UrlUnpadded, Encoding};
use dtx_wire::Sha256Digest;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use x509_parser::pem::parse_x509_pem;
use zeroize::Zeroize;

pub const CLIENT_BINDING_AUTHORIZATION_HASH_DOMAIN: &[u8] =
    b"dirextalk.client-binding-authorization.v1\0";
const MAX_IMPORT_BYTES: usize = 24 * 1024;
const MAX_CA_BYTES: usize = 12 * 1024;

/// A client-binding bearer capability.  It deliberately has no Debug or Clone.
pub struct ClientBindingAuthorization([u8; 32]);
impl Drop for ClientBindingAuthorization {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}
impl ClientBindingAuthorization {
    pub fn parse(value: &str) -> Result<Self, ClientBindingImportError> {
        if value.len() != 43 {
            return Err(ClientBindingImportError);
        }
        let mut raw = [0; 32];
        Base64UrlUnpadded::decode(value, &mut raw).map_err(|_| ClientBindingImportError)?;
        Ok(Self(raw))
    }
    #[must_use]
    pub fn digest(&self) -> Sha256Digest {
        Sha256Digest::hash_domain(CLIENT_BINDING_AUTHORIZATION_HASH_DOMAIN, &self.0)
    }
    #[must_use]
    pub fn encoded(&self) -> String {
        Base64UrlUnpadded::encode_string(&self.0)
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ImportWire {
    schema: String,
    schema_version: u8,
    binding_id: String,
    deployment_operation_id: String,
    tenant_id: String,
    server_origin: String,
    identity_tls_root_ca_pem: String,
    identity_tls_root_ca_sha256: String,
    expires_at_unix_ms: i64,
    authorization: String,
}

/// Strict, locally parsed import.  The authorization is retained only in this
/// non-debuggable value and is zeroized at drop.
pub struct ClientBindingImport {
    pub binding_id: Uuid,
    pub deployment_operation_id: Uuid,
    pub tenant_id: Uuid,
    pub server_origin: String,
    pub identity_tls_root_ca_pem: String,
    pub expires_at_unix_ms: i64,
    authorization: ClientBindingAuthorization,
}
impl ClientBindingImport {
    pub fn parse_exact(bytes: &[u8]) -> Result<Self, ClientBindingImportError> {
        if bytes.is_empty() || bytes.len() > MAX_IMPORT_BYTES || std::str::from_utf8(bytes).is_err()
        {
            return Err(ClientBindingImportError);
        };
        let wire: ImportWire =
            serde_json::from_slice(bytes).map_err(|_| ClientBindingImportError)?;
        if serde_json::to_vec(&wire).map_err(|_| ClientBindingImportError)? != bytes {
            return Err(ClientBindingImportError);
        }
        if wire.schema != "dirextalk.client-binding"
            || wire.schema_version != 1
            || !canonical_origin(&wire.server_origin)
            || wire.identity_tls_root_ca_pem.len() > MAX_CA_BYTES
        {
            return Err(ClientBindingImportError);
        }
        let binding_id = canonical_v7(&wire.binding_id)?;
        let deployment_operation_id = canonical_v7(&wire.deployment_operation_id)?;
        let tenant_id = canonical_v7(&wire.tenant_id)?;
        let digest = hex_digest(&wire.identity_tls_root_ca_sha256)?;
        let (_, pem) = parse_x509_pem(wire.identity_tls_root_ca_pem.as_bytes())
            .map_err(|_| ClientBindingImportError)?;
        if pem.parse_x509().is_err() {
            return Err(ClientBindingImportError);
        }
        use sha2::{Digest, Sha256};
        let actual = Sha256::digest(wire.identity_tls_root_ca_pem.as_bytes());
        if actual.as_slice() != digest.as_bytes() {
            return Err(ClientBindingImportError);
        }
        Ok(Self {
            binding_id,
            deployment_operation_id,
            tenant_id,
            server_origin: wire.server_origin,
            identity_tls_root_ca_pem: wire.identity_tls_root_ca_pem,
            expires_at_unix_ms: wire.expires_at_unix_ms,
            authorization: ClientBindingAuthorization::parse(&wire.authorization)?,
        })
    }
    #[must_use]
    pub fn authorization_digest(&self) -> Sha256Digest {
        self.authorization.digest()
    }
}
#[derive(Clone, Copy, Debug)]
pub struct ClientBindingImportError;
impl std::fmt::Display for ClientBindingImportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("invalid client binding")
    }
}
impl std::error::Error for ClientBindingImportError {}
fn canonical_v7(value: &str) -> Result<Uuid, ClientBindingImportError> {
    let id = Uuid::parse_str(value).map_err(|_| ClientBindingImportError)?;
    if id.to_string() != value || id.get_version_num() != 7 {
        Err(ClientBindingImportError)
    } else {
        Ok(id)
    }
}
fn canonical_origin(value: &str) -> bool {
    value.starts_with("https://")
        && value.len() > 8
        && !value[8..].contains(['/', '?', '#', '@'])
        && value == value.to_ascii_lowercase()
}
fn hex_digest(value: &str) -> Result<Sha256Digest, ClientBindingImportError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(ClientBindingImportError);
    }
    let mut out = [0; 32];
    for (i, slot) in out.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&value[i * 2..i * 2 + 2], 16)
            .map_err(|_| ClientBindingImportError)?;
    }
    Ok(Sha256Digest::from_bytes(out))
}
