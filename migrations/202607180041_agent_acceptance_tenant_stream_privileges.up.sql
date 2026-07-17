-- V41: acceptance-prepare establishes the Owner tenant stream head before
-- writing Host and Connector topology. Grant only the idempotent insert
-- boundary used by that operation; reads, mutation, and deletion remain unavailable.
DO $grant$
BEGIN
    IF to_regrole('dtx_agent_runtime') IS NOT NULL THEN
        GRANT INSERT ON system.tenant_stream_heads TO dtx_agent_runtime;
    END IF;
END
$grant$;
