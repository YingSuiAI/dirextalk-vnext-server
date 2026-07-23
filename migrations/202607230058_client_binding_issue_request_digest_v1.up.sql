-- Persist the exact domain-separated canonical issue request, including the
-- protected CA filepath. Existing rows intentionally remain NULL because
-- their historical request bytes are unavailable; they cannot be replayed.
ALTER TABLE identity.client_bindings
  ADD COLUMN issue_request_digest bytea;

ALTER TABLE identity.client_bindings
  ADD CONSTRAINT client_bindings_issue_request_digest_length
  CHECK (issue_request_digest IS NULL OR octet_length(issue_request_digest)=32);
