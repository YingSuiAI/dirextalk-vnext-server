#[cfg(test)]
mod tests {
    use std::{error::Error, net::IpAddr, str::FromStr};

    use base64ct::{Base64, Encoding as _};
    use dtx_domain::{DeviceEnrollmentChallengeId, DeviceId, IdentityId};
    use dtx_wire::{Sha256Digest, UtcMillis};
    use rcgen::{
        BasicConstraints, CertificateParams, IsCa, KeyPair, KeyUsagePurpose, PKCS_ED25519,
    };
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    use super::{
        FederatedIdentityError, FederatedIdentityVerifier, MlsV5RecoveryAuthorityKind,
        MlsV5RecoveryAuthorizationProjection, MlsV5RecoveryAuthorizationQuery,
        decode_mls_v5_recovery_authorization, is_public_address,
    };

    #[test]
    fn recovery_authorization_projection_is_canonical_echo_bound_and_expiring()
    -> Result<(), Box<dyn Error>> {
        let identity_id =
            IdentityId::from_str("dtxi1eci4tbb6kk5wk4vwv5ckekifwqtxy7bdd5vbmd7vac45r5xwu4la")?;
        let request_id = DeviceEnrollmentChallengeId::new();
        let candidate_device_id = DeviceId::new();
        let controller_device_id = DeviceId::new();
        let query = MlsV5RecoveryAuthorizationQuery::new(
            identity_id,
            request_id,
            candidate_device_id,
            controller_device_id,
            Sha256Digest::from_bytes([1; 32]),
            Sha256Digest::from_bytes([2; 32]),
            Sha256Digest::from_bytes([3; 32]),
            Sha256Digest::from_bytes([4; 32]),
        );
        assert_eq!(
            query.canonical_query(),
            format!(
                "candidate_device_id={candidate_device_id}&controller_device_id={controller_device_id}&identity_head_digest={}&key_package_digest={}&recovery_request_digest={}&recovery_scope_digest={}",
                Sha256Digest::from_bytes([1; 32]),
                Sha256Digest::from_bytes([2; 32]),
                Sha256Digest::from_bytes([3; 32]),
                Sha256Digest::from_bytes([4; 32]),
            )
        );
        let projection = MlsV5RecoveryAuthorizationProjection::new(
            query,
            DeviceId::new(),
            MlsV5RecoveryAuthorityKind::Root,
            "authority-current-root".to_owned(),
            Sha256Digest::from_bytes([5; 32]),
            Sha256Digest::from_bytes([6; 32]),
            Sha256Digest::from_bytes([7; 32]),
            UtcMillis::new(2_000)?,
        )?;
        let bytes = projection.exact_bytes()?;
        assert_eq!(
            decode_mls_v5_recovery_authorization(&bytes, query, UtcMillis::new(1_999)?)?,
            projection
        );
        assert_eq!(
            decode_mls_v5_recovery_authorization(&bytes, query, UtcMillis::new(2_000)?),
            Err(FederatedIdentityError::InvalidRecoveryAuthorization)
        );
        let mismatched = MlsV5RecoveryAuthorizationQuery::new(
            identity_id,
            request_id,
            candidate_device_id,
            controller_device_id,
            Sha256Digest::from_bytes([8; 32]),
            Sha256Digest::from_bytes([2; 32]),
            Sha256Digest::from_bytes([3; 32]),
            Sha256Digest::from_bytes([4; 32]),
        );
        assert_eq!(
            decode_mls_v5_recovery_authorization(&bytes, mismatched, UtcMillis::new(1_999)?),
            Err(FederatedIdentityError::InvalidRecoveryAuthorization)
        );
        Ok(())
    }

    #[tokio::test]
    async fn recovery_authorization_fetch_does_not_follow_redirects() -> Result<(), Box<dyn Error>>
    {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let origin = format!("http://{}", listener.local_addr()?);
        let redirect_origin = origin.clone();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("redirect request");
            let mut request = [0_u8; 4096];
            let _ = stream.read(&mut request).await.expect("request bytes");
            let response = format!(
                "HTTP/1.1 302 Found\r\nLocation: {redirect_origin}/redirected\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            );
            stream
                .write_all(response.as_bytes())
                .await
                .expect("redirect response");
        });
        let verifier = FederatedIdentityVerifier::new([origin.clone()])?;
        let identity_id =
            IdentityId::from_str("dtxi1eci4tbb6kk5wk4vwv5ckekifwqtxy7bdd5vbmd7vac45r5xwu4la")?;
        let query = MlsV5RecoveryAuthorizationQuery::new(
            identity_id,
            DeviceEnrollmentChallengeId::new(),
            DeviceId::new(),
            DeviceId::new(),
            Sha256Digest::from_bytes([1; 32]),
            Sha256Digest::from_bytes([2; 32]),
            Sha256Digest::from_bytes([3; 32]),
            Sha256Digest::from_bytes([4; 32]),
        );
        assert_eq!(
            verifier
                .mls_v5_recovery_authorization(&origin, query, UtcMillis::new(1_000)?)
                .await,
            Err(FederatedIdentityError::RecoveryAuthorizationUnavailable)
        );
        server.await?;
        Ok(())
    }

    #[test]
    fn pinned_https_accepts_only_public_dns_answers() -> Result<(), Box<dyn Error>> {
        for value in ["1.1.1.1", "8.8.8.8", "2606:4700:4700::1111"] {
            assert!(is_public_address(value.parse::<IpAddr>()?), "{value}");
        }
        for value in [
            "0.0.0.0",
            "10.0.0.1",
            "100.64.0.1",
            "127.0.0.1",
            "169.254.169.254",
            "172.16.0.1",
            "192.0.2.1",
            "192.168.0.1",
            "198.18.0.1",
            "198.51.100.1",
            "203.0.113.1",
            "224.0.0.1",
            "::",
            "::1",
            "::ffff:127.0.0.1",
            "2001:db8::1",
            "3fff::1",
            "fe80::1",
            "fc00::1",
            "ff02::1",
        ] {
            assert!(!is_public_address(value.parse::<IpAddr>()?), "{value}");
        }
        Ok(())
    }

    #[test]
    fn additional_trust_root_requires_one_ca_pem() -> Result<(), Box<dyn Error>> {
        let ca_pem = ca_certificate_pem()?;
        let (_, public_origin) =
            FederatedIdentityVerifier::new_with_public_origin_and_additional_trust_root_pem(
                "https://group.test",
                std::iter::empty::<String>(),
                Some(ca_pem.as_bytes()),
            )?;
        assert_eq!(public_origin, "https://group.test");

        let leaf_key = KeyPair::generate_for(&PKCS_ED25519)?;
        let leaf = CertificateParams::new(vec!["localhost".to_owned()])?.self_signed(&leaf_key)?;
        let leaf_pem = pem_from_der(leaf.der().as_ref());
        assert_eq!(
            FederatedIdentityVerifier::new_with_public_origin_and_additional_trust_root_pem(
                "https://group.test",
                std::iter::empty::<String>(),
                Some(leaf_pem.as_bytes()),
            )
            .err(),
            Some(FederatedIdentityError::InvalidTrustRoot),
        );

        let duplicate_ca_pem = format!("{ca_pem}{ca_pem}");
        assert_eq!(
            FederatedIdentityVerifier::new_with_public_origin_and_additional_trust_root_pem(
                "https://group.test",
                std::iter::empty::<String>(),
                Some(duplicate_ca_pem.as_bytes()),
            )
            .err(),
            Some(FederatedIdentityError::InvalidTrustRoot),
        );
        assert_eq!(
            FederatedIdentityVerifier::new_with_public_origin_and_additional_trust_root_pem(
                "https://group.test",
                std::iter::empty::<String>(),
                Some(b"not a PEM certificate"),
            )
            .err(),
            Some(FederatedIdentityError::InvalidTrustRoot),
        );
        Ok(())
    }

    fn ca_certificate_pem() -> Result<String, Box<dyn Error>> {
        let key = KeyPair::generate_for(&PKCS_ED25519)?;
        let mut parameters = CertificateParams::default();
        parameters.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        parameters.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let certificate = parameters.self_signed(&key)?;
        Ok(pem_from_der(certificate.der().as_ref()))
    }

    fn pem_from_der(der: &[u8]) -> String {
        let encoded = Base64::encode_string(der);
        let mut pem = String::from("-----BEGIN CERTIFICATE-----\n");
        for line in encoded.as_bytes().chunks(64) {
            pem.push_str(std::str::from_utf8(line).expect("base64 output is ASCII"));
            pem.push('\n');
        }
        pem.push_str("-----END CERTIFICATE-----\n");
        pem
    }
}
