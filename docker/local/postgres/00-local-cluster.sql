-- Local Compose only: these roles intentionally have no passwords because the
-- database is on an isolated Docker network with host ports bound to loopback.
-- Never reuse this topology, trust authentication, or principals in production.

CREATE ROLE dtx_identity_runtime NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION;
CREATE ROLE dtx_group_runtime NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION;
CREATE ROLE dtx_mailbox_runtime NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION;

CREATE ROLE dtx_identity_node LOGIN IN ROLE dtx_identity_runtime NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION;
CREATE ROLE dtx_group_node LOGIN IN ROLE dtx_group_runtime NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION;
CREATE ROLE dtx_mailbox_node LOGIN IN ROLE dtx_mailbox_runtime NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION;

CREATE DATABASE dtx_node_a OWNER postgres;
CREATE DATABASE dtx_node_b OWNER postgres;
