DO $guard$ BEGIN
  LOCK TABLE agent.connector_bootstrap_issuances IN SHARE ROW EXCLUSIVE MODE;
  IF EXISTS (SELECT 1 FROM agent.connector_bootstrap_issuances) THEN
    RAISE EXCEPTION 'cannot downgrade Connector bootstrap issuance v1 while durable issuance facts exist'
      USING ERRCODE='55000';
  END IF;
END $guard$;

DO $grant$ BEGIN
  IF to_regrole('dtx_agent_runtime') IS NOT NULL THEN
    REVOKE ALL ON agent.connector_bootstrap_issuances FROM dtx_agent_runtime;
  END IF;
END $grant$;
DROP POLICY tenant_isolation ON agent.connector_bootstrap_issuances;
ALTER TABLE agent.connector_bootstrap_issuances DISABLE ROW LEVEL SECURITY;
DROP TRIGGER connector_bootstrap_issuances_fence ON agent.connector_bootstrap_issuances;
DROP FUNCTION agent.enforce_connector_bootstrap_issuance_fence();
DROP TRIGGER connector_bootstrap_issuances_append_only ON agent.connector_bootstrap_issuances;
DROP TABLE agent.connector_bootstrap_issuances;
