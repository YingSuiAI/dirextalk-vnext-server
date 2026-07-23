-- Restore the exact V54 policy installed by migration 048.  This rollback
-- changes only the Agent reader branch; it retains identity/mailbox/group,
-- realtime, and identity-owner behavior and preserves writer-only WITH CHECK.
ALTER POLICY identity_runtime_only ON identity.log_heads
    USING (
        CASE
            WHEN COALESCE(
                pg_has_role(current_user,to_regrole('dtx_group_runtime'),'MEMBER'),
                false
            ) THEN has_function_privilege(
                current_user,
                'identity.identity_group_reader_authorized()'::regprocedure,
                'EXECUTE'
            )
            ELSE COALESCE(
                    pg_has_role(current_user,to_regrole('dtx_identity_runtime'),'MEMBER'),
                    false
                )
              OR COALESCE(
                    pg_has_role(current_user,to_regrole('dtx_mailbox_runtime'),'MEMBER'),
                    false
                )
              OR COALESCE(
                    pg_has_role(current_user,to_regrole('dtx_realtime_sync_runtime'),'MEMBER'),
                    false
                )
              OR current_user = (
                    SELECT pg_get_userbyid(nspowner)
                      FROM pg_namespace
                     WHERE nspname='identity'
                )
        END
    )
    WITH CHECK (
        COALESCE(
            pg_has_role(current_user,to_regrole('dtx_identity_runtime'),'MEMBER'),
            false
        )
        OR current_user = (
            SELECT pg_get_userbyid(nspowner)
              FROM pg_namespace
             WHERE nspname='identity'
        )
    );

ALTER POLICY identity_runtime_only ON identity.log_entries
    USING (
        CASE
            WHEN COALESCE(
                pg_has_role(current_user,to_regrole('dtx_group_runtime'),'MEMBER'),
                false
            ) THEN has_function_privilege(
                current_user,
                'identity.identity_group_reader_authorized()'::regprocedure,
                'EXECUTE'
            )
            ELSE COALESCE(
                    pg_has_role(current_user,to_regrole('dtx_identity_runtime'),'MEMBER'),
                    false
                )
              OR COALESCE(
                    pg_has_role(current_user,to_regrole('dtx_mailbox_runtime'),'MEMBER'),
                    false
                )
              OR COALESCE(
                    pg_has_role(current_user,to_regrole('dtx_realtime_sync_runtime'),'MEMBER'),
                    false
                )
              OR current_user = (
                    SELECT pg_get_userbyid(nspowner)
                      FROM pg_namespace
                     WHERE nspname='identity'
                )
        END
    )
    WITH CHECK (
        COALESCE(
            pg_has_role(current_user,to_regrole('dtx_identity_runtime'),'MEMBER'),
            false
        )
        OR current_user = (
            SELECT pg_get_userbyid(nspowner)
              FROM pg_namespace
             WHERE nspname='identity'
        )
    );

ALTER POLICY identity_runtime_only ON identity.device_sessions
    USING (
        CASE
            WHEN COALESCE(
                pg_has_role(current_user,to_regrole('dtx_group_runtime'),'MEMBER'),
                false
            ) THEN has_function_privilege(
                current_user,
                'identity.identity_group_reader_authorized()'::regprocedure,
                'EXECUTE'
            )
            ELSE COALESCE(
                    pg_has_role(current_user,to_regrole('dtx_identity_runtime'),'MEMBER'),
                    false
                )
              OR COALESCE(
                    pg_has_role(current_user,to_regrole('dtx_mailbox_runtime'),'MEMBER'),
                    false
                )
              OR COALESCE(
                    pg_has_role(current_user,to_regrole('dtx_realtime_sync_runtime'),'MEMBER'),
                    false
                )
              OR current_user = (
                    SELECT pg_get_userbyid(nspowner)
                      FROM pg_namespace
                     WHERE nspname='identity'
                )
        END
    )
    WITH CHECK (
        COALESCE(
            pg_has_role(current_user,to_regrole('dtx_identity_runtime'),'MEMBER'),
            false
        )
        OR current_user = (
            SELECT pg_get_userbyid(nspowner)
              FROM pg_namespace
             WHERE nspname='identity'
        )
    );
