DO $revoke$
BEGIN
    IF to_regrole('dtx_agent_runtime') IS NOT NULL THEN
        REVOKE INSERT ON system.tenant_stream_heads FROM dtx_agent_runtime;
    END IF;
END
$revoke$;
