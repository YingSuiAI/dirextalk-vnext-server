DROP FUNCTION identity.prune_expired_device_sessions(bigint, integer);
DROP TABLE identity.device_session_receipts;
DROP TABLE identity.device_session_idempotency_claims;
ALTER TABLE identity.device_session_challenges
    DROP CONSTRAINT identity_device_session_challenges_session_fk;
DROP TABLE identity.device_sessions;
DROP TRIGGER identity_device_session_challenges_transition
    ON identity.device_session_challenges;
DROP FUNCTION identity.enforce_device_session_challenge_transition();
DROP FUNCTION identity.enforce_device_session_immutable_or_prunable();
DROP FUNCTION identity.device_session_retention_prune_authorized();
DROP TABLE identity.device_session_challenges;
