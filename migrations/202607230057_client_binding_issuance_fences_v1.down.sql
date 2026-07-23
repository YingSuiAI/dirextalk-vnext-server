DO $guard$ BEGIN
  LOCK TABLE identity.client_bindings IN SHARE ROW EXCLUSIVE MODE;
  IF EXISTS (SELECT 1 FROM identity.client_bindings) THEN
    RAISE EXCEPTION 'cannot downgrade client binding issuance fences while durable bindings exist' USING ERRCODE='55000';
  END IF;
END $guard$;
DROP INDEX identity.client_bindings_live_operation_unique;
ALTER TABLE identity.client_bindings
  DROP CONSTRAINT client_bindings_device_id_v7,
  DROP CONSTRAINT client_bindings_authorization_digest_unique;
