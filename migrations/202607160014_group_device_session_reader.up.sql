-- Group membership commands authenticate the caller in the same transaction
-- that reads/writes the durable saga.  The group runtime may therefore read
-- only the immutable identity projection needed by
-- `DeviceSessionRepository::authenticate_in_transaction`; it never receives
-- identity mutation, KeyPackage, or identity-owner capability.
CREATE FUNCTION identity.identity_group_reader_authorized()
RETURNS boolean
LANGUAGE sql
STABLE
PARALLEL SAFE
AS $$
    SELECT COALESCE(
        pg_has_role(current_user, to_regrole('dtx_group_runtime'), 'MEMBER'),
        false
    )
$$;

-- Preserve the mailbox reader branch introduced by migration 013.  The group
-- reader is SELECT-only: `WITH CHECK` deliberately continues to exclude it.
-- All role/owner checks are inlined because PostgreSQL validates RLS helper
-- EXECUTE privileges for every caller covered by a policy. The group branch
-- checks the dedicated reader function's grant without invoking it; the same
-- grant is the explicit ACL proof checked by `GroupPgStore`.
ALTER POLICY identity_runtime_only ON identity.log_heads
    USING (
        CASE
            WHEN COALESCE(
                pg_has_role(current_user, to_regrole('dtx_group_runtime'), 'MEMBER'),
                false
            ) THEN has_function_privilege(
                current_user,
                'identity.identity_group_reader_authorized()'::regprocedure,
                'EXECUTE'
            )
            ELSE COALESCE(
                    pg_has_role(
                        current_user,
                        to_regrole('dtx_identity_runtime'),
                        'MEMBER'
                    ),
                    false
                )
                OR COALESCE(
                    pg_has_role(
                        current_user,
                        to_regrole('dtx_mailbox_runtime'),
                        'MEMBER'
                    ),
                    false
                )
                OR current_user = (
                    SELECT pg_get_userbyid(nspowner)
                      FROM pg_namespace
                     WHERE nspname = 'identity'
                )
        END
    )
    WITH CHECK (
        COALESCE(
            pg_has_role(current_user, to_regrole('dtx_identity_runtime'), 'MEMBER'),
            false
        )
        OR current_user = (
            SELECT pg_get_userbyid(nspowner)
              FROM pg_namespace
             WHERE nspname = 'identity'
        )
    );

ALTER POLICY identity_runtime_only ON identity.log_entries
    USING (
        CASE
            WHEN COALESCE(
                pg_has_role(current_user, to_regrole('dtx_group_runtime'), 'MEMBER'),
                false
            ) THEN has_function_privilege(
                current_user,
                'identity.identity_group_reader_authorized()'::regprocedure,
                'EXECUTE'
            )
            ELSE COALESCE(
                    pg_has_role(
                        current_user,
                        to_regrole('dtx_identity_runtime'),
                        'MEMBER'
                    ),
                    false
                )
                OR COALESCE(
                    pg_has_role(
                        current_user,
                        to_regrole('dtx_mailbox_runtime'),
                        'MEMBER'
                    ),
                    false
                )
                OR current_user = (
                    SELECT pg_get_userbyid(nspowner)
                      FROM pg_namespace
                     WHERE nspname = 'identity'
                )
        END
    )
    WITH CHECK (
        COALESCE(
            pg_has_role(current_user, to_regrole('dtx_identity_runtime'), 'MEMBER'),
            false
        )
        OR current_user = (
            SELECT pg_get_userbyid(nspowner)
              FROM pg_namespace
             WHERE nspname = 'identity'
        )
    );

ALTER POLICY identity_runtime_only ON identity.device_sessions
    USING (
        CASE
            WHEN COALESCE(
                pg_has_role(current_user, to_regrole('dtx_group_runtime'), 'MEMBER'),
                false
            ) THEN has_function_privilege(
                current_user,
                'identity.identity_group_reader_authorized()'::regprocedure,
                'EXECUTE'
            )
            ELSE COALESCE(
                    pg_has_role(
                        current_user,
                        to_regrole('dtx_identity_runtime'),
                        'MEMBER'
                    ),
                    false
                )
                OR COALESCE(
                    pg_has_role(
                        current_user,
                        to_regrole('dtx_mailbox_runtime'),
                        'MEMBER'
                    ),
                    false
                )
                OR current_user = (
                    SELECT pg_get_userbyid(nspowner)
                      FROM pg_namespace
                     WHERE nspname = 'identity'
                )
        END
    )
    WITH CHECK (
        COALESCE(
            pg_has_role(current_user, to_regrole('dtx_identity_runtime'), 'MEMBER'),
            false
        )
        OR current_user = (
            SELECT pg_get_userbyid(nspowner)
              FROM pg_namespace
             WHERE nspname = 'identity'
        )
    );

-- Existing deployments can provision application roles before migrations; new
-- local/test environments may provision them later and grant the same narrow
-- matrix as part of their runtime setup.
DO $grant$
BEGIN
    IF to_regrole('dtx_group_runtime') IS NOT NULL THEN
        GRANT USAGE ON SCHEMA identity TO dtx_group_runtime;
        GRANT EXECUTE ON FUNCTION identity.identity_group_reader_authorized()
            TO dtx_group_runtime;
        GRANT SELECT ON identity.device_sessions, identity.log_heads, identity.log_entries
            TO dtx_group_runtime;
    END IF;
END
$grant$;

REVOKE ALL ON FUNCTION identity.identity_group_reader_authorized() FROM PUBLIC;
