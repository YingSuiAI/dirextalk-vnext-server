LOCK TABLE identity.recovery_scope_catalogs IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE identity.recovery_scope_catalog_preparations IN SHARE ROW EXCLUSIVE MODE;

DO $$ BEGIN
    IF EXISTS(SELECT 1 FROM identity.recovery_scope_catalog_preparations)
       OR EXISTS(SELECT 1 FROM identity.recovery_scope_catalogs) THEN
        RAISE EXCEPTION 'cannot downgrade recovery scope catalog V1 while V41 facts exist'
            USING ERRCODE='55000';
    END IF;
END $$;

DO $revoke$ BEGIN
    IF to_regrole('dtx_identity_runtime') IS NOT NULL THEN
        REVOKE ALL ON identity.recovery_scope_catalog_preparations FROM dtx_identity_runtime;
        REVOKE ALL ON identity.recovery_scope_catalogs FROM dtx_identity_runtime;
        REVOKE EXECUTE ON FUNCTION messaging.is_uuid_v7(uuid) FROM dtx_identity_runtime;
        REVOKE USAGE ON SCHEMA messaging FROM dtx_identity_runtime;
    END IF;
END $revoke$;

CREATE OR REPLACE FUNCTION identity.prune_expired_device_enrollment_challenges(
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
        RAISE EXCEPTION 'device enrollment retention cutoff is invalid'
            USING ERRCODE = '22003';
    END IF;
    IF maximum_rows NOT BETWEEN 1 AND 1024 THEN
        RAISE EXCEPTION 'device enrollment retention batch is invalid'
            USING ERRCODE = '22023';
    END IF;

    PERFORM set_config('identity.device_enrollment_retention_prune', 'on', true);
    WITH expired_challenges AS MATERIALIZED (
        SELECT challenge_id
          FROM identity.device_enrollment_challenges
         WHERE retention_until_ms <= target_cutoff_ms
         ORDER BY retention_until_ms, challenge_id
         LIMIT maximum_rows
         FOR UPDATE SKIP LOCKED
    ), deleted AS (
        DELETE FROM identity.device_enrollment_challenges AS challenge
         USING expired_challenges AS expired
         WHERE challenge.challenge_id = expired.challenge_id
         RETURNING 1
    )
    SELECT count(*) INTO removed FROM deleted;
    RETURN removed;
END
$$;

DROP TRIGGER identity_recovery_scope_catalog_preparation_transition
    ON identity.recovery_scope_catalog_preparations;
DROP FUNCTION identity.enforce_recovery_scope_catalog_preparation_transition();
DROP TABLE identity.recovery_scope_catalog_preparations;
DROP TABLE identity.recovery_scope_catalogs;
