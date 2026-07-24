impl FederatedIdentityVerifier {
    /// Builds a verifier that permits HTTPS origins and the explicitly listed
    /// development-only HTTP origins.
    ///
    /// # Errors
    ///
    /// Returns an error when an HTTP origin is invalid or the hardened HTTP
    /// client cannot be constructed.
    pub fn new(
        allowed_http_origins: impl IntoIterator<Item = String>,
    ) -> Result<Self, FederatedIdentityError> {
        let mut canonical_http_origins = BTreeSet::new();
        for origin in allowed_http_origins {
            let canonical = canonical_origin(&origin, true)?;
            if canonical.scheme() != "http" {
                return Err(FederatedIdentityError::InvalidOrigin);
            }
            canonical_http_origins.insert(canonical.origin().ascii_serialization());
        }
        let client = build_client(None, None)?;
        Ok(Self {
            client,
            allowed_http_origins: canonical_http_origins,
            additional_trust_root: None,
        })
    }

    /// Builds a verifier and canonicalizes the local node's public origin.
    ///
    /// An optional CA certificate extends the platform trust store without
    /// replacing normal hostname and certificate-chain validation.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid public or allowed origin, an invalid CA
    /// certificate, or a failure to construct the hardened HTTP client.
    pub fn new_with_public_origin_and_additional_trust_root_pem(
        public_origin: &str,
        allowed_http_origins: impl IntoIterator<Item = String>,
        additional_trust_root_pem: Option<&[u8]>,
    ) -> Result<(Self, String), FederatedIdentityError> {
        let verifier = Self::new(allowed_http_origins)?;
        let verifier = match additional_trust_root_pem {
            Some(trust_root_pem) => verifier.with_additional_trust_root_pem(trust_root_pem)?,
            None => verifier,
        };
        let public_origin = canonical_origin(public_origin, true)?;
        let canonical_public_origin = public_origin.origin().ascii_serialization();
        if public_origin.scheme() == "http"
            && !verifier
                .allowed_http_origins
                .contains(&canonical_public_origin)
        {
            return Err(FederatedIdentityError::InvalidOrigin);
        }
        Ok((verifier, canonical_public_origin))
    }

    /// Extends the normal platform trust store with one explicitly configured CA root.
    ///
    /// The root is deliberately merged with the normal verifier instead of replacing it;
    /// Rustls therefore continues to enforce normal certificate-chain and hostname checks.
    fn with_additional_trust_root_pem(
        mut self,
        trust_root_pem: &[u8],
    ) -> Result<Self, FederatedIdentityError> {
        let trust_root = parse_additional_trust_root_pem(trust_root_pem)?;
        self.client = build_client(Some(trust_root.clone()), None)?;
        self.additional_trust_root = Some(trust_root);
        Ok(self)
    }

    /// Resolves the current active signing key for one remote device from its
    /// origin's canonical identity log.
    ///
    /// # Errors
    ///
    /// Returns an error when the origin is not allowed, the remote service is
    /// unavailable, the identity log is invalid, or the requested device is
    /// absent or no longer active.
    pub async fn active_device_signing_key(
        &self,
        origin: &str,
        identity_id: IdentityId,
        device_id: DeviceId,
    ) -> Result<SigningPublicKey, FederatedIdentityError> {
        Ok(self
            .active_device(origin, identity_id, device_id)
            .await?
            .signing_key())
    }

    /// Reduces the authoritative identity log and returns one active device
    /// together with the exact current head.
    ///
    /// # Errors
    ///
    /// Returns an error when the origin or log is invalid, the service is
    /// unavailable, or the requested device is not active at the current head.
    pub async fn active_device(
        &self,
        origin: &str,
        identity_id: IdentityId,
        device_id: DeviceId,
    ) -> Result<VerifiedActiveDevice, FederatedIdentityError> {
        let (log, _) = self
            .identity_log_with_terminal_event(origin, identity_id)
            .await?;
        Ok(VerifiedActiveDevice {
            identity_id,
            device_id,
            signing_key: active_signing_key(&log, device_id)?,
            head_sequence: log.head_sequence(),
            head_digest: log.head_hash(),
        })
    }

    /// Reduces one authoritative identity log and proves that its exact current
    /// terminal event revokes the requested leaf while the controller remains active.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid origin/log facts, a stale head, a non-active
    /// controller, or any terminal event other than the exact target revoke.
    pub async fn active_device_with_terminal_revoke(
        &self,
        origin: &str,
        identity_id: IdentityId,
        controller_device_id: DeviceId,
        revoked_device_id: DeviceId,
        expected_head_digest: Sha256Digest,
    ) -> Result<VerifiedActiveDevice, FederatedIdentityError> {
        let (log, terminal) = self
            .identity_log_with_terminal_event(origin, identity_id)
            .await?;
        if log.head_hash() != expected_head_digest
            || log.device_status(revoked_device_id) != Some(DeviceStatusV1::Revoked)
            || terminal.identity_id() != identity_id
            || terminal.sequence() != log.head_sequence()
            || terminal
                .entry_hash()
                .map_err(|_| FederatedIdentityError::InvalidIdentityLog)?
                != log.head_hash()
            || !matches!(
                terminal.payload(),
                IdentityLogEventPayloadV1::DeviceRevoke { device_id }
                    if *device_id == revoked_device_id
            )
        {
            return Err(FederatedIdentityError::DeviceUnavailable);
        }
        Ok(VerifiedActiveDevice {
            identity_id,
            device_id: controller_device_id,
            signing_key: active_signing_key(&log, controller_device_id)?,
            head_sequence: log.head_sequence(),
            head_digest: log.head_hash(),
        })
    }

    async fn identity_log_with_terminal_event(
        &self,
        origin: &str,
        identity_id: IdentityId,
    ) -> Result<(IdentityLogV1, IdentityLogEventV1), FederatedIdentityError> {
        let origin = self.parse_allowed_origin(origin)?;
        let client = self.client_for_origin(&origin).await?;
        let (mut after, mut total_bytes) = (0_u64, 0_usize);
        let mut advertised_head = None;
        let mut projection = None;
        let mut terminal_event = None;

        for _ in 0..MAX_IDENTITY_LOG_PAGES {
            let page_url = identity_log_page_url(&origin, identity_id, after)?;
            let response = client
                .get(page_url)
                .header(header::ACCEPT, IDENTITY_LOG_PAGE_CONTENT_TYPE)
                .header(header::CACHE_CONTROL, "no-store")
                .send()
                .await
                .map_err(|_| FederatedIdentityError::TemporarilyUnavailable)?;
            if response.status() != StatusCode::OK {
                return Err(if response.status().is_server_error() {
                    FederatedIdentityError::TemporarilyUnavailable
                } else {
                    FederatedIdentityError::DeviceUnavailable
                });
            }
            require_single_header(
                response.headers(),
                header::CONTENT_TYPE,
                IDENTITY_LOG_PAGE_CONTENT_TYPE,
            )?;
            require_single_header(response.headers(), header::CACHE_CONTROL, "no-store")?;
            require_single_header(
                response.headers(),
                header::X_CONTENT_TYPE_OPTIONS,
                "nosniff",
            )?;
            if response
                .content_length()
                .is_some_and(|length| length > MAX_IDENTITY_LOG_PAGE_BYTES as u64)
            {
                return Err(FederatedIdentityError::InvalidIdentityLog);
            }
            let mut response = response;
            let mut exact_page = Vec::new();
            while let Some(chunk) = response
                .chunk()
                .await
                .map_err(|_| FederatedIdentityError::TemporarilyUnavailable)?
            {
                total_bytes = total_bytes
                    .checked_add(chunk.len())
                    .ok_or(FederatedIdentityError::InvalidIdentityLog)?;
                if exact_page.len() + chunk.len() > MAX_IDENTITY_LOG_PAGE_BYTES
                    || total_bytes > MAX_IDENTITY_LOG_TOTAL_BYTES
                {
                    return Err(FederatedIdentityError::InvalidIdentityLog);
                }
                exact_page.extend_from_slice(&chunk);
            }
            let page = IdentityLogPageV1::decode_and_verify(&exact_page)
                .map_err(|_| FederatedIdentityError::InvalidIdentityLog)?;
            if page.identity_id() != identity_id || page.requested_after_sequence() != after {
                return Err(FederatedIdentityError::InvalidIdentityLog);
            }
            let page_head = (page.advertised_head_sequence(), page.advertised_head_hash());
            if advertised_head.is_some_and(|head| head != page_head) {
                return Err(FederatedIdentityError::InvalidIdentityLog);
            }
            advertised_head = Some(page_head);
            for exact_event in page.exact_events() {
                let event = IdentityLogEventV1::decode_and_verify(exact_event)
                    .map_err(|_| FederatedIdentityError::InvalidIdentityLog)?;
                match projection.as_mut() {
                    None => {
                        projection = Some(
                            IdentityLogV1::bootstrap(&event)
                                .map_err(|_| FederatedIdentityError::InvalidIdentityLog)?,
                        );
                    }
                    Some(log) => log
                        .append(&event)
                        .map_err(|_| FederatedIdentityError::InvalidIdentityLog)?,
                }
                terminal_event = Some(event);
            }
            after = page.next_after_sequence();
            if !page.has_more() {
                let log = projection.ok_or(FederatedIdentityError::InvalidIdentityLog)?;
                if advertised_head != Some((log.head_sequence(), log.head_hash())) {
                    return Err(FederatedIdentityError::InvalidIdentityLog);
                }
                return Ok((
                    log,
                    terminal_event.ok_or(FederatedIdentityError::InvalidIdentityLog)?,
                ));
            }
            if page.exact_events().len() != MAX_IDENTITY_LOG_PAGE_EVENTS {
                return Err(FederatedIdentityError::InvalidIdentityLog);
            }
        }
        Err(FederatedIdentityError::InvalidIdentityLog)
    }

    /// Fetches one fresh origin-authenticated MLS V5 recovery authorization.
    ///
    /// The returned projection is deliberately unsigned and non-portable: TLS
    /// origin authentication, DNS pinning, and response validation are repeated
    /// for every submission or replay.
    ///
    /// # Errors
    ///
    /// Returns an error for an unsafe origin, unavailable or malformed remote
    /// facts, a non-canonical response, or an already expired authorization.
    pub async fn mls_v5_recovery_authorization(
        &self,
        origin: &str,
        query: MlsV5RecoveryAuthorizationQuery,
        now: UtcMillis,
    ) -> Result<MlsV5RecoveryAuthorizationProjection, FederatedIdentityError> {
        let origin = self.parse_allowed_origin(origin)?;
        let client = self.client_for_origin(&origin).await?;
        let url = mls_v5_recovery_authorization_url(&origin, query)?;
        let response = client
            .get(url)
            .header(header::ACCEPT, MLS_V5_RECOVERY_AUTHORIZATION_CONTENT_TYPE)
            .header(header::CACHE_CONTROL, "no-store")
            .send()
            .await
            .map_err(|_| FederatedIdentityError::TemporarilyUnavailable)?;
        if response.status() != StatusCode::OK {
            return Err(if response.status().is_server_error() {
                FederatedIdentityError::TemporarilyUnavailable
            } else {
                FederatedIdentityError::RecoveryAuthorizationUnavailable
            });
        }
        require_recovery_authorization_header(
            response.headers(),
            header::CONTENT_TYPE,
            MLS_V5_RECOVERY_AUTHORIZATION_CONTENT_TYPE,
        )?;
        require_recovery_authorization_header(
            response.headers(),
            header::CACHE_CONTROL,
            "no-store",
        )?;
        require_recovery_authorization_header(
            response.headers(),
            header::X_CONTENT_TYPE_OPTIONS,
            "nosniff",
        )?;
        if response
            .content_length()
            .is_some_and(|length| length > MAX_MLS_V5_RECOVERY_AUTHORIZATION_BYTES as u64)
        {
            return Err(FederatedIdentityError::InvalidRecoveryAuthorization);
        }
        let mut response = response;
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| FederatedIdentityError::TemporarilyUnavailable)?
        {
            if bytes.len() + chunk.len() > MAX_MLS_V5_RECOVERY_AUTHORIZATION_BYTES {
                return Err(FederatedIdentityError::InvalidRecoveryAuthorization);
            }
            bytes.extend_from_slice(&chunk);
        }
        decode_mls_v5_recovery_authorization(&bytes, query, now)
    }

    fn parse_allowed_origin(&self, origin: &str) -> Result<Url, FederatedIdentityError> {
        let parsed = canonical_origin(origin, true)?;
        if parsed.scheme() == "https"
            || self
                .allowed_http_origins
                .contains(&parsed.origin().ascii_serialization())
        {
            Ok(parsed)
        } else {
            Err(FederatedIdentityError::InvalidOrigin)
        }
    }

    async fn client_for_origin(&self, origin: &Url) -> Result<Client, FederatedIdentityError> {
        if origin.scheme() == "http" {
            return Ok(self.client.clone());
        }
        let host = origin
            .host_str()
            .ok_or(FederatedIdentityError::InvalidOrigin)?;
        if host.parse::<IpAddr>().is_ok() {
            return Err(FederatedIdentityError::InvalidOrigin);
        }
        let port = origin
            .port_or_known_default()
            .ok_or(FederatedIdentityError::InvalidOrigin)?;
        let addresses = tokio::net::lookup_host((host, port))
            .await
            .map_err(|_| FederatedIdentityError::TemporarilyUnavailable)?
            .map(|socket| socket.ip())
            .collect::<BTreeSet<_>>();
        if addresses.is_empty()
            || addresses.len() > 16
            || addresses.iter().any(|address| !is_public_address(*address))
        {
            return Err(FederatedIdentityError::InvalidOrigin);
        }
        let pinned = SocketAddr::new(
            *addresses
                .first()
                .ok_or(FederatedIdentityError::InvalidOrigin)?,
            port,
        );
        build_client(self.additional_trust_root.clone(), Some((host, pinned)))
    }
}
