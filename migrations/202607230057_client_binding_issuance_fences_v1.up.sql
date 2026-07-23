-- Issuance remains correct across processes and restarts: no two durable
-- bindings can carry the same bearer digest, and an operation has one live
-- import at a time.
ALTER TABLE identity.client_bindings
  ADD CONSTRAINT client_bindings_authorization_digest_unique UNIQUE (authorization_digest),
  ADD CONSTRAINT client_bindings_device_id_v7 CHECK (device_id IS NULL OR system.is_uuid_v7(device_id));
CREATE UNIQUE INDEX client_bindings_live_operation_unique
  ON identity.client_bindings (tenant_id, deployment_operation_id)
  WHERE state IN ('issued', 'identity_bound');
