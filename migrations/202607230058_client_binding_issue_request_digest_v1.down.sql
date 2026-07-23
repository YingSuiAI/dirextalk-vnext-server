DO $guard$ BEGIN
  LOCK TABLE identity.client_bindings IN SHARE ROW EXCLUSIVE MODE;
  IF EXISTS (SELECT 1 FROM identity.client_bindings) THEN
    RAISE EXCEPTION 'cannot downgrade client binding issue request digest while durable bindings exist' USING ERRCODE='55000';
  END IF;
END $guard$;
ALTER TABLE identity.client_bindings
  DROP CONSTRAINT client_bindings_issue_request_digest_length,
  DROP COLUMN issue_request_digest;
