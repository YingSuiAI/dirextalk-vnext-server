-- Cluster-global local runtime roles. Compose executes this once before any
-- per-database migration or grant job so parallel node provisioning cannot
-- race CREATE ROLE on an existing development volume.
DO $roles$
BEGIN
    IF to_regrole('dtx_identity_runtime') IS NULL THEN
        CREATE ROLE dtx_identity_runtime NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION;
    END IF;
    IF to_regrole('dtx_group_runtime') IS NULL THEN
        CREATE ROLE dtx_group_runtime NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION;
    END IF;
    IF to_regrole('dtx_mailbox_runtime') IS NULL THEN
        CREATE ROLE dtx_mailbox_runtime NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION;
    END IF;
    IF to_regrole('dtx_push_registration_runtime') IS NULL THEN
        CREATE ROLE dtx_push_registration_runtime NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION;
    END IF;
    IF to_regrole('dtx_push_identity_auth_runtime') IS NULL THEN
        CREATE ROLE dtx_push_identity_auth_runtime NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION;
    END IF;
    IF to_regrole('dtx_realtime_sync_runtime') IS NULL THEN
        CREATE ROLE dtx_realtime_sync_runtime NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION;
    END IF;
    IF to_regrole('dtx_push_broker_runtime') IS NULL THEN
        CREATE ROLE dtx_push_broker_runtime NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION;
    END IF;
    IF to_regrole('dtx_public_feed_runtime') IS NULL THEN
        CREATE ROLE dtx_public_feed_runtime NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION;
    END IF;
    IF to_regrole('dtx_identity_node') IS NULL THEN
        CREATE ROLE dtx_identity_node LOGIN IN ROLE dtx_identity_runtime NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION;
    END IF;
    IF to_regrole('dtx_group_node') IS NULL THEN
        CREATE ROLE dtx_group_node LOGIN IN ROLE dtx_group_runtime NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION;
    END IF;
    IF to_regrole('dtx_mailbox_node') IS NULL THEN
        CREATE ROLE dtx_mailbox_node LOGIN IN ROLE dtx_mailbox_runtime NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION;
    END IF;
    IF to_regrole('dtx_push_registration') IS NULL THEN
        CREATE ROLE dtx_push_registration LOGIN IN ROLE dtx_push_registration_runtime NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION;
    END IF;
    IF to_regrole('dtx_push_identity_auth') IS NULL THEN
        CREATE ROLE dtx_push_identity_auth LOGIN IN ROLE dtx_push_identity_auth_runtime NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION;
    END IF;
    IF to_regrole('dtx_realtime_sync_gateway') IS NULL THEN
        CREATE ROLE dtx_realtime_sync_gateway LOGIN IN ROLE dtx_realtime_sync_runtime NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION;
    END IF;
    IF to_regrole('dtx_push_broker') IS NULL THEN
        CREATE ROLE dtx_push_broker LOGIN IN ROLE dtx_push_broker_runtime NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION;
    END IF;
    IF to_regrole('dtx_public_feed_node') IS NULL THEN
        CREATE ROLE dtx_public_feed_node LOGIN NOINHERIT IN ROLE dtx_public_feed_runtime NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION;
    END IF;
    IF to_regrole('dtx_indexer_node') IS NULL THEN
        CREATE ROLE dtx_indexer_node LOGIN NOINHERIT IN ROLE dtx_public_feed_runtime NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION;
    END IF;
END
$roles$;
