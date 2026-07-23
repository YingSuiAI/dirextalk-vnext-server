ALTER TABLE identity.client_bindings
  DROP CONSTRAINT client_bindings_issue_request_digest_length,
  DROP COLUMN issue_request_digest;
