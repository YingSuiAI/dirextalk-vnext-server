DO $guard$ BEGIN
  LOCK TABLE identity.client_bindings IN SHARE ROW EXCLUSIVE MODE;
  IF EXISTS (SELECT 1 FROM identity.client_bindings) THEN
    RAISE EXCEPTION 'cannot downgrade client binding v1 while durable bindings exist' USING ERRCODE='55000';
  END IF;
END $guard$;
DO $grant$ BEGIN
  IF to_regrole('dtx_identity_runtime') IS NOT NULL THEN REVOKE ALL ON identity.client_bindings FROM dtx_identity_runtime; END IF;
END $grant$;
DROP POLICY identity_runtime_only ON identity.client_bindings;
ALTER TABLE identity.client_bindings DISABLE ROW LEVEL SECURITY;
DROP TABLE identity.client_bindings;
