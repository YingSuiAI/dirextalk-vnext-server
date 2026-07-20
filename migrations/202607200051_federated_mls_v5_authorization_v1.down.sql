DO $revoke$ BEGIN
    IF to_regrole('dtx_identity_runtime') IS NOT NULL THEN
        REVOKE ALL ON FUNCTION identity.mls_v5_recovery_authorization_projection(
            text,uuid,uuid,uuid,bytea,bytea,bytea,bytea,bigint
        ) FROM dtx_identity_runtime;
    END IF;
END $revoke$;

REVOKE ALL ON FUNCTION identity.mls_v5_recovery_authorization_projection(
    text,uuid,uuid,uuid,bytea,bytea,bytea,bytea,bigint
) FROM PUBLIC;
DROP FUNCTION identity.mls_v5_recovery_authorization_projection(
    text,uuid,uuid,uuid,bytea,bytea,bytea,bytea,bigint
);
