-- V42: PostgreSQL requires SELECT on the conflict target used by the
-- acceptance foundation's INSERT ... ON CONFLICT DO NOTHING statement.
DO $grant$
BEGIN
    IF to_regrole('dtx_agent_runtime') IS NOT NULL THEN
        GRANT SELECT ON system.tenant_stream_heads TO dtx_agent_runtime;
    END IF;
END
$grant$;
