-- RLS-safe startup preflight for the Route Health receipt signer snapshots.
-- This function intentionally exposes only the public signer tuple; tenant,
-- route, bootstrap, and credential identifiers never cross this boundary.
CREATE FUNCTION agent.route_health_receipt_preflight(now_ms bigint)
RETURNS TABLE (
    server_receipt_key_id uuid,
    server_receipt_public_key bytea,
    server_receipt_public_key_digest bytea
)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, agent
AS $$
    SELECT DISTINCT b.server_receipt_key_id,
           b.server_receipt_public_key,
           b.server_receipt_public_key_digest
      FROM agent.agent_route_bootstraps AS b
     WHERE b.expires_at_ms > now_ms
       AND b.state IN ('pending_recipient', 'recipient_ready', 'pending_delivery', 'installed')
    UNION
    SELECT DISTINCT h.server_receipt_key_id,
           h.server_receipt_public_key,
           h.server_receipt_public_key_digest
      FROM agent.agent_route_binding_heads AS h
      JOIN agent.agent_route_bootstraps AS b
        ON b.tenant_id = h.tenant_id AND b.bootstrap_id = h.bootstrap_id
     WHERE h.expires_at_ms > now_ms
       AND b.expires_at_ms > now_ms
       AND b.state IN ('pending_recipient', 'recipient_ready', 'pending_delivery', 'installed')
    UNION
    SELECT NULL::uuid, NULL::bytea, NULL::bytea
     WHERE EXISTS (
         SELECT 1
           FROM agent.agent_route_binding_heads AS h
           JOIN agent.agent_route_bootstraps AS b
             ON b.tenant_id = h.tenant_id AND b.bootstrap_id = h.bootstrap_id
          WHERE h.expires_at_ms > now_ms
            AND b.expires_at_ms > now_ms
            AND b.state IN ('pending_recipient', 'recipient_ready', 'pending_delivery', 'installed')
            AND (h.server_receipt_key_id IS DISTINCT FROM b.server_receipt_key_id
                 OR h.server_receipt_public_key IS DISTINCT FROM b.server_receipt_public_key
                 OR h.server_receipt_public_key_digest IS DISTINCT FROM b.server_receipt_public_key_digest)
     )
$$;

DO $grant$
BEGIN
    IF to_regrole('dtx_agent_runtime') IS NOT NULL THEN
        GRANT EXECUTE ON FUNCTION agent.route_health_receipt_preflight(bigint)
            TO dtx_agent_runtime;
    END IF;
END
$grant$;

REVOKE ALL ON FUNCTION agent.route_health_receipt_preflight(bigint) FROM PUBLIC;
