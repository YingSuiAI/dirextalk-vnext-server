-- Federated claimants do not exist in this node's identity log. Scope every
-- idempotent claim by the verified identity origin and remove the local-only
-- claimant FK; the HTTP boundary must authenticate either a local session or
-- a current remote identity-log device before reaching these tables.
ALTER TABLE identity.key_package_claim_receipts
    DROP CONSTRAINT identity_key_package_claim_receipts_claim_fk;

ALTER TABLE identity.key_package_claims
    DROP CONSTRAINT identity_key_package_claims_claimant_fk;

ALTER TABLE identity.key_package_claim_receipts
    DROP CONSTRAINT key_package_claim_receipts_pkey;
ALTER TABLE identity.key_package_claims
    DROP CONSTRAINT key_package_claims_pkey;

ALTER TABLE identity.key_package_claims
    ADD COLUMN claimant_identity_origin text NOT NULL DEFAULT '';
ALTER TABLE identity.key_package_claim_receipts
    ADD COLUMN claimant_identity_origin text NOT NULL DEFAULT '';

ALTER TABLE identity.key_package_claims
    ADD CONSTRAINT identity_key_package_claims_origin_bounded
        CHECK (
            claimant_identity_origin = ''
            OR octet_length(claimant_identity_origin) BETWEEN 8 AND 512
        ),
    ADD PRIMARY KEY (
        claimant_identity_origin,
        claimant_identity_id,
        claimant_device_id,
        idempotency_key_hash
    );

ALTER TABLE identity.key_package_claim_receipts
    ADD CONSTRAINT identity_key_package_claim_receipts_origin_bounded
        CHECK (
            claimant_identity_origin = ''
            OR octet_length(claimant_identity_origin) BETWEEN 8 AND 512
        ),
    ADD PRIMARY KEY (
        claimant_identity_origin,
        claimant_identity_id,
        claimant_device_id,
        idempotency_key_hash
    ),
    ADD CONSTRAINT identity_key_package_claim_receipts_claim_fk
        FOREIGN KEY (
            claimant_identity_origin,
            claimant_identity_id,
            claimant_device_id,
            idempotency_key_hash
        )
        REFERENCES identity.key_package_claims (
            claimant_identity_origin,
            claimant_identity_id,
            claimant_device_id,
            idempotency_key_hash
        )
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED;

CREATE OR REPLACE FUNCTION identity.prune_expired_key_packages(
    target_cutoff_ms bigint,
    maximum_rows integer DEFAULT 256
)
RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, identity
AS $$
DECLARE
    removed bigint := 0;
BEGIN
    IF target_cutoff_ms NOT BETWEEN -62135596800000 AND 253402301699999 THEN
        RAISE EXCEPTION 'key package retention cutoff is invalid'
            USING ERRCODE = '22003';
    END IF;
    IF maximum_rows NOT BETWEEN 1 AND 1024 THEN
        RAISE EXCEPTION 'key package retention batch is invalid'
            USING ERRCODE = '22023';
    END IF;

    PERFORM set_config('identity.key_package_retention_prune', 'on', true);
    WITH expired_packages AS MATERIALIZED (
        SELECT package_id
          FROM identity.key_packages
         WHERE retention_until_ms <= target_cutoff_ms
         ORDER BY retention_until_ms, package_id
         LIMIT maximum_rows
         FOR UPDATE SKIP LOCKED
    ), deleted_claim_receipts AS (
        DELETE FROM identity.key_package_claim_receipts AS receipt
         USING expired_packages AS expired
         WHERE receipt.package_id = expired.package_id
         RETURNING
             receipt.claimant_identity_origin,
             receipt.claimant_identity_id,
             receipt.claimant_device_id,
             receipt.idempotency_key_hash
    ), deleted_claims AS (
        DELETE FROM identity.key_package_claims AS claim
         USING deleted_claim_receipts AS receipt
         WHERE receipt.claimant_identity_origin = claim.claimant_identity_origin
           AND receipt.claimant_identity_id = claim.claimant_identity_id
           AND receipt.claimant_device_id = claim.claimant_device_id
           AND receipt.idempotency_key_hash = claim.idempotency_key_hash
         RETURNING 1
    ), deleted_publish_claims AS (
        DELETE FROM identity.key_package_publish_claims AS claim
         USING expired_packages AS expired
         WHERE claim.package_id = expired.package_id
         RETURNING 1
    ), deleted_packages AS (
        DELETE FROM identity.key_packages AS package
         USING expired_packages AS expired
         WHERE package.package_id = expired.package_id
         RETURNING 1
    )
    SELECT count(*) INTO removed FROM deleted_packages;
    RETURN removed;
END
$$;
