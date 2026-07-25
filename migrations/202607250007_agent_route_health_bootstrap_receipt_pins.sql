-- Credential-bound server receipt signer snapshots for RouteBootstrap.
-- These are distinct from the Agent/native request-verification key columns
-- introduced by 202607250001 and contain no private key material.
ALTER TABLE agent.agent_route_bootstraps
    ADD COLUMN server_receipt_key_id uuid,
    ADD COLUMN server_receipt_public_key bytea,
    ADD COLUMN server_receipt_public_key_digest bytea;

ALTER TABLE agent.agent_route_binding_heads
    ADD COLUMN server_receipt_key_id uuid,
    ADD COLUMN server_receipt_public_key bytea,
    ADD COLUMN server_receipt_public_key_digest bytea;

ALTER TABLE agent.agent_route_bootstraps
    ADD CONSTRAINT agent_route_bootstraps_server_receipt_pin_shape CHECK (
        (server_receipt_key_id IS NULL
         AND server_receipt_public_key IS NULL
         AND server_receipt_public_key_digest IS NULL)
        OR (server_receipt_key_id IS NOT NULL
            AND system.is_uuid_v7(server_receipt_key_id)
            AND server_receipt_public_key IS NOT NULL
            AND octet_length(server_receipt_public_key) = 32
            AND server_receipt_public_key_digest IS NOT NULL
            AND octet_length(server_receipt_public_key_digest) = 32)
    );

ALTER TABLE agent.agent_route_binding_heads
    ADD CONSTRAINT agent_route_binding_heads_server_receipt_pin_shape CHECK (
        (server_receipt_key_id IS NULL
         AND server_receipt_public_key IS NULL
         AND server_receipt_public_key_digest IS NULL)
        OR (server_receipt_key_id IS NOT NULL
            AND system.is_uuid_v7(server_receipt_key_id)
            AND server_receipt_public_key IS NOT NULL
            AND octet_length(server_receipt_public_key) = 32
            AND server_receipt_public_key_digest IS NOT NULL
            AND octet_length(server_receipt_public_key_digest) = 32)
    );

DO $grant$
BEGIN
    IF to_regrole('dtx_agent_runtime') IS NOT NULL THEN
        GRANT SELECT, INSERT, UPDATE ON agent.agent_route_bootstraps,
            agent.agent_route_binding_heads TO dtx_agent_runtime;
    END IF;
END
$grant$;
