-- Connector credential snapshots of the public Route Health receipt signer.
-- These are public authorization facts; private key material remains in the
-- Host Supervisor keyring and never enters PostgreSQL.
ALTER TABLE agent.connector_enrollment_intents
    ADD COLUMN route_health_receipt_key_id uuid,
    ADD COLUMN route_health_receipt_public_key bytea;

ALTER TABLE agent.connector_control_credentials
    ADD COLUMN route_health_receipt_key_id uuid,
    ADD COLUMN route_health_receipt_public_key bytea;

ALTER TABLE agent.connector_credential_reissue_intents
    ADD COLUMN route_health_receipt_key_id uuid,
    ADD COLUMN route_health_receipt_public_key bytea;

ALTER TABLE agent.connector_enrollment_intents
    ADD CONSTRAINT connector_enrollment_intents_receipt_pin_shape CHECK (
        (route_health_receipt_key_id IS NULL AND route_health_receipt_public_key IS NULL)
        OR (route_health_receipt_key_id IS NOT NULL
            AND route_health_receipt_public_key IS NOT NULL
            AND system.is_uuid_v7(route_health_receipt_key_id)
            AND octet_length(route_health_receipt_public_key) = 32)
    );

ALTER TABLE agent.connector_control_credentials
    ADD CONSTRAINT connector_control_credentials_receipt_pin_shape CHECK (
        (route_health_receipt_key_id IS NULL AND route_health_receipt_public_key IS NULL)
        OR (route_health_receipt_key_id IS NOT NULL
            AND route_health_receipt_public_key IS NOT NULL
            AND system.is_uuid_v7(route_health_receipt_key_id)
            AND octet_length(route_health_receipt_public_key) = 32)
    );

ALTER TABLE agent.connector_credential_reissue_intents
    ADD CONSTRAINT connector_credential_reissue_intents_receipt_pin_shape CHECK (
        (route_health_receipt_key_id IS NULL AND route_health_receipt_public_key IS NULL)
        OR (route_health_receipt_key_id IS NOT NULL
            AND route_health_receipt_public_key IS NOT NULL
            AND system.is_uuid_v7(route_health_receipt_key_id)
            AND octet_length(route_health_receipt_public_key) = 32)
    );

DO $grant$
BEGIN
    IF to_regrole('dtx_agent_runtime') IS NOT NULL THEN
        GRANT SELECT, INSERT, UPDATE ON agent.connector_enrollment_intents,
            agent.connector_credential_reissue_intents TO dtx_agent_runtime;
        GRANT SELECT, INSERT ON agent.connector_control_credentials TO dtx_agent_runtime;
    END IF;
END
$grant$;
