REVOKE ALL ON FUNCTION identity.prune_expired_device_enrollment_challenges(bigint, integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION identity.enforce_device_enrollment_challenge_transition() FROM PUBLIC;
REVOKE ALL ON FUNCTION identity.device_enrollment_retention_prune_authorized() FROM PUBLIC;
DROP TRIGGER identity_device_enrollment_challenges_transition
    ON identity.device_enrollment_challenges;
DROP FUNCTION identity.prune_expired_device_enrollment_challenges(bigint, integer);
DROP FUNCTION identity.enforce_device_enrollment_challenge_transition();
DROP FUNCTION identity.device_enrollment_retention_prune_authorized();
DROP TABLE identity.device_enrollment_challenges;
