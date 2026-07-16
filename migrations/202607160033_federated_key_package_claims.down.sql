DO $$
BEGIN
    IF EXISTS (
        SELECT 1
          FROM identity.key_package_claims
         WHERE claimant_identity_origin <> ''
    ) THEN
        RAISE EXCEPTION 'cannot remove federated key package claims while federated receipts exist'
            USING ERRCODE = '55000';
    END IF;
END
$$;

ALTER TABLE identity.key_package_claim_receipts
    DROP CONSTRAINT identity_key_package_claim_receipts_claim_fk;
ALTER TABLE identity.key_package_claim_receipts
    DROP CONSTRAINT key_package_claim_receipts_pkey;
ALTER TABLE identity.key_package_claims
    DROP CONSTRAINT key_package_claims_pkey;

ALTER TABLE identity.key_package_claim_receipts
    DROP CONSTRAINT identity_key_package_claim_receipts_origin_bounded,
    DROP COLUMN claimant_identity_origin,
    ADD PRIMARY KEY (claimant_identity_id, claimant_device_id, idempotency_key_hash);
ALTER TABLE identity.key_package_claims
    DROP CONSTRAINT identity_key_package_claims_origin_bounded,
    DROP COLUMN claimant_identity_origin,
    ADD PRIMARY KEY (claimant_identity_id, claimant_device_id, idempotency_key_hash),
    ADD CONSTRAINT identity_key_package_claims_claimant_fk
        FOREIGN KEY (claimant_identity_id)
        REFERENCES identity.log_heads (identity_id)
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED;
ALTER TABLE identity.key_package_claim_receipts
    ADD CONSTRAINT identity_key_package_claim_receipts_claim_fk
        FOREIGN KEY (claimant_identity_id, claimant_device_id, idempotency_key_hash)
        REFERENCES identity.key_package_claims (
            claimant_identity_id, claimant_device_id, idempotency_key_hash
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
             receipt.claimant_identity_id,
             receipt.claimant_device_id,
             receipt.idempotency_key_hash
    ), deleted_claims AS (
        DELETE FROM identity.key_package_claims AS claim
         USING deleted_claim_receipts AS receipt
         WHERE receipt.claimant_identity_id = claim.claimant_identity_id
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
