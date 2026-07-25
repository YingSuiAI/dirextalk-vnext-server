-- Agent Control 1.6 Route Health key binding.
-- The private Ed25519 key is native sidecar state and never enters this
-- relation.  These columns retain only the public authorization tuple.
ALTER TABLE agent.agent_route_bootstraps
    ADD COLUMN route_health_key_id uuid,
    ADD COLUMN route_health_public_key bytea,
    ADD COLUMN route_health_key_purpose text;

ALTER TABLE agent.agent_route_bootstraps
    ADD CONSTRAINT agent_route_bootstraps_health_key_shape CHECK (
        (route_health_key_id IS NULL
         AND route_health_public_key IS NULL
         AND route_health_key_purpose IS NULL)
        OR (route_health_key_id IS NOT NULL
            AND system.is_uuid_v7(route_health_key_id)
            AND route_health_public_key IS NOT NULL
            AND octet_length(route_health_public_key) = 32
            AND route_health_key_purpose IS NOT NULL
            AND route_health_key_purpose = 'agent-route-health')
    );

-- One key can authorize at most one current bootstrap.  Historical rejected,
-- expired, and revoked rows may retain no key and therefore do not block a
-- fresh bootstrap for the same installation/binding tuple.
CREATE UNIQUE INDEX agent_route_bootstraps_health_key_current_unique
    ON agent.agent_route_bootstraps (tenant_id, route_health_key_id)
    WHERE route_health_key_id IS NOT NULL
      AND state IN ('recipient_ready', 'pending_delivery', 'installed');

REVOKE ALL ON agent.agent_route_bootstraps FROM PUBLIC;
DO $grant$
BEGIN
    IF to_regrole('dtx_agent_runtime') IS NOT NULL THEN
        GRANT SELECT, INSERT, UPDATE ON agent.agent_route_bootstraps
            TO dtx_agent_runtime;
    END IF;
END
$grant$;
