-- V40: narrow identity-origin projection for federated MLS V5 recovery.
-- The group runtime receives no identity or messaging table privileges. Only
-- the identity runtime may ask this SECURITY DEFINER function for redacted
-- current facts that its public HTTPS origin validates again against the
-- reduced identity log before returning canonical CBOR.

CREATE FUNCTION identity.mls_v5_recovery_authorization_projection(
    requested_identity_id text,
    requested_request_id uuid,
    requested_candidate_device_id uuid,
    requested_controller_device_id uuid,
    requested_head_digest bytea,
    requested_package_digest bytea,
    requested_request_digest bytea,
    requested_scope_digest bytea,
    at_ms bigint
) RETURNS TABLE(
    provider_device_id uuid,
    authority_kind text,
    authority_id text,
    history_grant_digest bytea,
    attachment_digest bytea,
    claim_receipt_digest bytea,
    authorization_expires_at_ms bigint
)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, identity, messaging
AS $$
    SELECT offer.provider_device_id,
           offer.authority_kind,
           offer.authority_id,
           offer.request_digest,
           offer.attachment_digest,
           receipt.receipt_digest,
           LEAST(
               challenge.expires_at_ms,
               package.expires_at_ms,
               offer.expires_at_ms,
               attachment.expires_at_ms
           )
      FROM identity.device_enrollment_challenges AS challenge
      JOIN identity.log_heads AS head
        ON head.identity_id = challenge.identity_id
       AND head.state = 'active'
       AND head.head_hash = requested_head_digest
       AND head.head_hash = challenge.approved_head_hash
      JOIN identity.key_packages AS package
        ON package.owner_identity_id = challenge.identity_id
       AND package.owner_device_id = challenge.target_device_id
       AND package.package_digest = requested_package_digest
       AND package.published_head_sequence = head.head_sequence
       AND package.published_head_hash = head.head_hash
       AND package.purpose = 'history_recovery'
       AND package.recovery_request_digest = requested_request_digest
       AND package.recovery_scope_digest = requested_scope_digest
       AND package.state = 'claimed'
       AND package.expires_at_ms > at_ms
      JOIN identity.key_package_claim_receipts AS receipt
        ON receipt.package_id = package.package_id
       AND receipt.claimant_identity_id = requested_identity_id
       AND receipt.claimant_device_id = requested_controller_device_id
       AND receipt.claimed_at_ms <= at_ms
      JOIN identity.key_package_claims AS claim
        ON claim.claimant_identity_id = receipt.claimant_identity_id
       AND claim.claimant_device_id = receipt.claimant_device_id
       AND claim.idempotency_key_hash = receipt.idempotency_key_hash
       AND claim.target_identity_id = requested_identity_id
       AND claim.target_device_id = requested_candidate_device_id
       AND claim.purpose = 'history_recovery'
       AND claim.recovery_request_digest = requested_request_digest
       AND claim.recovery_scope_digest = requested_scope_digest
      JOIN messaging.history_recovery_offers AS offer
        ON offer.identity_id = challenge.identity_id
       AND offer.request_id = challenge.challenge_id
       AND offer.recovery_request_digest = requested_request_digest
       AND offer.approved_head_hash = requested_head_digest
       AND offer.candidate_device_id = requested_candidate_device_id
       AND offer.expires_at_ms > at_ms
      JOIN LATERAL (
          SELECT max(candidate.expires_at_ms) AS expires_at_ms
            FROM messaging.attachment_objects AS candidate
           WHERE candidate.owner_identity_id = offer.identity_id
             AND candidate.expected_manifest_digest = offer.attachment_digest
             AND candidate.state = 'ready'
             AND candidate.expires_at_ms >= offer.expires_at_ms
             AND candidate.expires_at_ms > at_ms
      ) AS attachment ON attachment.expires_at_ms IS NOT NULL
     WHERE COALESCE(
               pg_has_role(
                   session_user,
                   to_regrole('dtx_identity_runtime'),
                   'MEMBER'
               ),
               false
           )
       AND challenge.identity_id = requested_identity_id
       AND challenge.challenge_id = requested_request_id
       AND challenge.target_device_id = requested_candidate_device_id
       AND challenge.protocol_version = 2
       AND challenge.state = 'approved'
       AND challenge.approved_at_ms IS NOT NULL
       AND challenge.approver_device_id IS NOT NULL
       AND challenge.recovery_request_digest = requested_request_digest
       AND challenge.expires_at_ms > at_ms
     LIMIT 1
$$;

REVOKE ALL ON FUNCTION identity.mls_v5_recovery_authorization_projection(
    text,uuid,uuid,uuid,bytea,bytea,bytea,bytea,bigint
) FROM PUBLIC;

DO $grants$ BEGIN
    IF to_regrole('dtx_identity_runtime') IS NOT NULL THEN
        GRANT EXECUTE ON FUNCTION identity.mls_v5_recovery_authorization_projection(
            text,uuid,uuid,uuid,bytea,bytea,bytea,bytea,bigint
        ) TO dtx_identity_runtime;
    END IF;
END $grants$;
