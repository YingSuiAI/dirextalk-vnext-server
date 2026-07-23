-- Restore migration 019's narrow Agent identity-reader branch after migration
-- 048 replaced the identity policies while retaining group and realtime readers.
-- The Agent runtime has SELECT grants only; WITH CHECK stays identity-writer/owner-only.
ALTER POLICY identity_runtime_only ON identity.log_heads
    USING (
        CASE
            WHEN COALESCE(
                pg_has_role(current_user,to_regrole('dtx_agent_runtime'),'MEMBER'),
                false
            ) THEN has_function_privilege(
                current_user,
                'identity.identity_agent_reader_authorized()'::regprocedure,
                'EXECUTE'
            )
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
                pg_has_role(current_user,to_regrole('dtx_agent_runtime'),'MEMBER'),
                false
            ) THEN has_function_privilege(
                current_user,
                'identity.identity_agent_reader_authorized()'::regprocedure,
                'EXECUTE'
            )
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
                pg_has_role(current_user,to_regrole('dtx_agent_runtime'),'MEMBER'),
                false
            ) THEN has_function_privilege(
                current_user,
                'identity.identity_agent_reader_authorized()'::regprocedure,
                'EXECUTE'
            )
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
