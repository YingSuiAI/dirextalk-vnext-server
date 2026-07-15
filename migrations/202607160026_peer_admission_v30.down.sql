ALTER TABLE groups.mls_commit_intents
    DROP CONSTRAINT groups_mls_commit_intents_v3_admission_digests_valid,
    DROP CONSTRAINT groups_mls_commit_intents_protocol_version_valid,
    DROP COLUMN approval_request_digest,
    DROP COLUMN join_request_digest,
    DROP COLUMN protocol_version;

ALTER TABLE groups.membership_workflows
    DROP CONSTRAINT groups_membership_workflows_candidate_key_package_digest_size,
    DROP COLUMN candidate_key_package_digest;
