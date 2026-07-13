use std::{
    fmt, fs,
    net::SocketAddr,
    path::{Path, PathBuf},
};

use serde::Deserialize;

const MAX_CONFIG_BYTES: u64 = 64 * 1_024;
const MAX_DATABASE_CONNECTIONS: u32 = 256;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BootstrapConfig {
    pub database_url_file: PathBuf,
    pub max_database_connections: u32,
    pub health: HealthEndpoint,
    pub enrollment: PublicTlsEndpoint,
    pub control: ControlTlsEndpoint,
    pub legacy_gateway: InternalServiceTlsEndpoint,
    pub connector_issuer: ConnectorIssuer,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HealthEndpoint {
    pub listen: SocketAddr,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicTlsEndpoint {
    pub listen: SocketAddr,
    pub certificate_chain_pem: PathBuf,
    pub private_key_pkcs8_pem: PathBuf,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ControlTlsEndpoint {
    pub listen: SocketAddr,
    pub certificate_chain_pem: PathBuf,
    pub private_key_pkcs8_pem: PathBuf,
    pub client_ca_bundle_pem: PathBuf,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InternalServiceTlsEndpoint {
    pub listen: SocketAddr,
    pub certificate_chain_pem: PathBuf,
    pub private_key_pkcs8_pem: PathBuf,
    pub client_ca_bundle_pem: PathBuf,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConnectorIssuer {
    pub certificate: PathBuf,
    pub private_key: PathBuf,
    pub response_intermediates: Option<PathBuf>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawBootstrapConfig {
    database_url_file: PathBuf,
    max_database_connections: u32,
    health: RawHealthEndpoint,
    enrollment: RawPublicTlsEndpoint,
    control: RawControlTlsEndpoint,
    legacy_gateway: RawControlTlsEndpoint,
    connector_issuer: RawConnectorIssuer,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawHealthEndpoint {
    listen: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPublicTlsEndpoint {
    listen: String,
    certificate_chain_pem: PathBuf,
    private_key_pkcs8_pem: PathBuf,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawControlTlsEndpoint {
    listen: String,
    certificate_chain_pem: PathBuf,
    private_key_pkcs8_pem: PathBuf,
    client_ca_bundle_pem: PathBuf,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConnectorIssuer {
    #[serde(rename = "certificate_pem")]
    certificate: PathBuf,
    #[serde(rename = "private_key_pkcs8_pem")]
    private_key: PathBuf,
    #[serde(rename = "response_intermediate_bundle_pem")]
    response_intermediates: Option<PathBuf>,
}

impl BootstrapConfig {
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let metadata = fs::metadata(path).map_err(|_| ConfigError::Read)?;
        if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAX_CONFIG_BYTES {
            return Err(ConfigError::Size);
        }
        let bytes = fs::read(path).map_err(|_| ConfigError::Read)?;
        if bytes.is_empty() || u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_CONFIG_BYTES {
            return Err(ConfigError::Size);
        }
        let raw: RawBootstrapConfig =
            serde_json::from_slice(&bytes).map_err(|_| ConfigError::Syntax)?;
        raw.resolve(path.parent().unwrap_or_else(|| Path::new(".")))
    }
}

impl RawBootstrapConfig {
    fn resolve(self, base: &Path) -> Result<BootstrapConfig, ConfigError> {
        if !(1..=MAX_DATABASE_CONNECTIONS).contains(&self.max_database_connections) {
            return Err(ConfigError::DatabasePoolSize);
        }
        let enrollment_listen = parse_listen(&self.enrollment.listen)?;
        let control_listen = parse_listen(&self.control.listen)?;
        let legacy_gateway_listen = parse_listen(&self.legacy_gateway.listen)?;
        let health_listen = parse_listen(&self.health.listen)?;
        if !listeners_are_distinct(&[
            enrollment_listen,
            control_listen,
            legacy_gateway_listen,
            health_listen,
        ]) {
            return Err(ConfigError::ListenerCollision);
        }
        Ok(BootstrapConfig {
            database_url_file: resolve_path(base, self.database_url_file)?,
            max_database_connections: self.max_database_connections,
            health: HealthEndpoint {
                listen: health_listen,
            },
            enrollment: PublicTlsEndpoint {
                listen: enrollment_listen,
                certificate_chain_pem: resolve_path(base, self.enrollment.certificate_chain_pem)?,
                private_key_pkcs8_pem: resolve_path(base, self.enrollment.private_key_pkcs8_pem)?,
            },
            control: ControlTlsEndpoint {
                listen: control_listen,
                certificate_chain_pem: resolve_path(base, self.control.certificate_chain_pem)?,
                private_key_pkcs8_pem: resolve_path(base, self.control.private_key_pkcs8_pem)?,
                client_ca_bundle_pem: resolve_path(base, self.control.client_ca_bundle_pem)?,
            },
            legacy_gateway: InternalServiceTlsEndpoint {
                listen: legacy_gateway_listen,
                certificate_chain_pem: resolve_path(
                    base,
                    self.legacy_gateway.certificate_chain_pem,
                )?,
                private_key_pkcs8_pem: resolve_path(
                    base,
                    self.legacy_gateway.private_key_pkcs8_pem,
                )?,
                client_ca_bundle_pem: resolve_path(base, self.legacy_gateway.client_ca_bundle_pem)?,
            },
            connector_issuer: ConnectorIssuer {
                certificate: resolve_path(base, self.connector_issuer.certificate)?,
                private_key: resolve_path(base, self.connector_issuer.private_key)?,
                response_intermediates: self
                    .connector_issuer
                    .response_intermediates
                    .map(|path| resolve_path(base, path))
                    .transpose()?,
            },
        })
    }
}

fn listeners_are_distinct(listeners: &[SocketAddr]) -> bool {
    listeners
        .iter()
        .enumerate()
        .all(|(index, listener)| !listeners[index + 1..].contains(listener))
}

fn parse_listen(value: &str) -> Result<SocketAddr, ConfigError> {
    let address = value
        .parse::<SocketAddr>()
        .map_err(|_| ConfigError::ListenAddress)?;
    if address.port() == 0 {
        Err(ConfigError::ListenAddress)
    } else {
        Ok(address)
    }
}

fn resolve_path(base: &Path, path: PathBuf) -> Result<PathBuf, ConfigError> {
    if path.as_os_str().is_empty() {
        return Err(ConfigError::EmptyPath);
    }
    Ok(if path.is_absolute() {
        path
    } else {
        base.join(path)
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfigError {
    Read,
    Size,
    Syntax,
    DatabasePoolSize,
    ListenAddress,
    ListenerCollision,
    EmptyPath,
}

impl fmt::Display for ConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Read => "bootstrap configuration could not be read",
            Self::Size => "bootstrap configuration size is invalid",
            Self::Syntax => "bootstrap configuration is invalid",
            Self::DatabasePoolSize => "database pool size is invalid",
            Self::ListenAddress => "listener address is invalid",
            Self::ListenerCollision => "listener addresses must be distinct",
            Self::EmptyPath => "bootstrap path is empty",
        })
    }
}

impl std::error::Error for ConfigError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw(enrollment: &str, control: &str) -> RawBootstrapConfig {
        serde_json::from_value(serde_json::json!({
            "database_url_file": "secrets/database-url",
            "max_database_connections": 16,
            "health": {
                "listen": "127.0.0.1:9080"
            },
            "enrollment": {
                "listen": enrollment,
                "certificate_chain_pem": "tls/enrollment-chain.pem",
                "private_key_pkcs8_pem": "tls/enrollment-key.pem"
            },
            "control": {
                "listen": control,
                "certificate_chain_pem": "tls/control-chain.pem",
                "private_key_pkcs8_pem": "tls/control-key.pem",
                "client_ca_bundle_pem": "tls/connector-roots.pem"
            },
            "legacy_gateway": {
                "listen": "127.0.0.1:9445",
                "certificate_chain_pem": "tls/gateway-server-chain.pem",
                "private_key_pkcs8_pem": "tls/gateway-server-key.pem",
                "client_ca_bundle_pem": "tls/internal-service-roots.pem"
            },
            "connector_issuer": {
                "certificate_pem": "tls/issuer.pem",
                "private_key_pkcs8_pem": "tls/issuer-key.pem"
            }
        }))
        .expect("test bootstrap JSON is valid")
    }

    #[test]
    fn resolves_relative_secret_paths_from_the_config_directory() {
        let resolved = raw("127.0.0.1:9443", "127.0.0.1:9444")
            .resolve(Path::new("/etc/dirextalk"))
            .expect("valid bootstrap config resolves");
        assert_eq!(
            resolved.database_url_file,
            Path::new("/etc/dirextalk/secrets/database-url")
        );
        assert_eq!(resolved.max_database_connections, 16);
    }

    #[test]
    fn rejects_listener_collisions_and_ephemeral_ports() {
        assert_eq!(
            raw("127.0.0.1:9443", "127.0.0.1:9443")
                .resolve(Path::new("."))
                .unwrap_err(),
            ConfigError::ListenerCollision
        );
        assert_eq!(
            raw("127.0.0.1:0", "127.0.0.1:9444")
                .resolve(Path::new("."))
                .unwrap_err(),
            ConfigError::ListenAddress
        );

        let mut health_collision = raw("127.0.0.1:9443", "127.0.0.1:9444");
        health_collision.health.listen = "127.0.0.1:9444".to_owned();
        assert_eq!(
            health_collision.resolve(Path::new(".")).unwrap_err(),
            ConfigError::ListenerCollision
        );

        let mut ephemeral_health = raw("127.0.0.1:9443", "127.0.0.1:9444");
        ephemeral_health.health.listen = "127.0.0.1:0".to_owned();
        assert_eq!(
            ephemeral_health.resolve(Path::new(".")).unwrap_err(),
            ConfigError::ListenAddress
        );

        let mut gateway_collision = raw("127.0.0.1:9443", "127.0.0.1:9444");
        gateway_collision.legacy_gateway.listen = "127.0.0.1:9443".to_owned();
        assert_eq!(
            gateway_collision.resolve(Path::new(".")).unwrap_err(),
            ConfigError::ListenerCollision
        );
    }
}
