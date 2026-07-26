-- RLS-safe startup preflight for the Route Health receipt signer snapshots.
-- This function intentionally exposes only the public signer tuple; tenant,
-- route, bootstrap, and credential identifiers never cross this boundary.
DO $role$
DECLARE
    role_oid oid;
BEGIN
    SELECT oid INTO role_oid
      FROM pg_catalog.pg_roles
     WHERE rolname = 'dtx_agent_route_health_preflight';
    IF role_oid IS NULL THEN
        CREATE ROLE dtx_agent_route_health_preflight
            NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE
            NOREPLICATION;
    ELSE
        IF EXISTS (
            SELECT 1
              FROM pg_catalog.pg_roles
             WHERE oid = role_oid
               AND (rolcanlogin OR rolsuper OR rolbypassrls OR rolcreatedb
                    OR rolcreaterole OR rolreplication)
        ) OR EXISTS (
            SELECT 1
              FROM pg_catalog.pg_auth_members
             WHERE roleid = role_oid OR member = role_oid
        ) THEN
            RAISE EXCEPTION 'route health preflight role attributes or membership mismatch';
        END IF;
    END IF;
END
$role$;

REVOKE ALL ON SCHEMA agent FROM dtx_agent_route_health_preflight;
REVOKE ALL ON agent.agent_route_bootstraps,
    agent.agent_route_binding_heads FROM dtx_agent_route_health_preflight;
GRANT USAGE ON SCHEMA agent TO dtx_agent_route_health_preflight;
GRANT SELECT (
    tenant_id, bootstrap_id, state, expires_at_ms,
    server_receipt_key_id, server_receipt_public_key,
    server_receipt_public_key_digest
) ON agent.agent_route_bootstraps TO dtx_agent_route_health_preflight;
GRANT SELECT (
    tenant_id, bootstrap_id, expires_at_ms,
    server_receipt_key_id, server_receipt_public_key,
    server_receipt_public_key_digest
) ON agent.agent_route_binding_heads TO dtx_agent_route_health_preflight;

CREATE POLICY route_health_preflight_public_read
    ON agent.agent_route_bootstraps
    TO dtx_agent_route_health_preflight
    USING (true);
CREATE POLICY route_health_preflight_public_read
    ON agent.agent_route_binding_heads
    TO dtx_agent_route_health_preflight
    USING (true);

CREATE FUNCTION agent.route_health_receipt_preflight(now_ms bigint)
RETURNS TABLE (
    server_receipt_key_id uuid,
    server_receipt_public_key bytea,
    server_receipt_public_key_digest bytea
)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
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

ALTER FUNCTION agent.route_health_receipt_preflight(bigint)
    OWNER TO dtx_agent_route_health_preflight;

DO $grant$
BEGIN
    IF to_regrole('dtx_agent_runtime') IS NOT NULL THEN
        GRANT EXECUTE ON FUNCTION agent.route_health_receipt_preflight(bigint)
            TO dtx_agent_runtime;
    END IF;
END
$grant$;

REVOKE ALL ON FUNCTION agent.route_health_receipt_preflight(bigint) FROM PUBLIC;
