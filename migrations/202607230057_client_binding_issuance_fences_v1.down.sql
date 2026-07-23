DROP INDEX identity.client_bindings_live_operation_unique;
ALTER TABLE identity.client_bindings
  DROP CONSTRAINT client_bindings_device_id_v7,
  DROP CONSTRAINT client_bindings_authorization_digest_unique;
