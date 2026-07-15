-- V30 binds every new membership workflow and MLS admission to one exact
-- candidate KeyPackage. Historical V17/V18 rows remain NULL and are rejected
-- by the V2/V3 production path instead of being guessed after the fact.
ALTER TABLE groups.membership_workflows
    ADD COLUMN candidate_key_package_digest bytea;

ALTER TABLE groups.membership_workflows
    ADD CONSTRAINT groups_membership_workflows_candidate_key_package_digest_size
    CHECK (candidate_key_package_digest IS NULL
           OR octet_length(candidate_key_package_digest) = 32);

-- V22 receipts remain readable. V30/V3 intents carry the durable candidate
-- join and Owner/Admin approval request digests that are covered by the signed
-- receipt. They are populated only for the V3 approved-identity path.
ALTER TABLE groups.mls_commit_intents
    ADD COLUMN protocol_version smallint NOT NULL DEFAULT 2,
    ADD COLUMN join_request_digest bytea,
    ADD COLUMN approval_request_digest bytea;

ALTER TABLE groups.mls_commit_intents
    ADD CONSTRAINT groups_mls_commit_intents_protocol_version_valid
    CHECK (protocol_version IN (2, 3)),
    ADD CONSTRAINT groups_mls_commit_intents_v3_admission_digests_valid
    CHECK ((protocol_version = 2
            AND join_request_digest IS NULL
            AND approval_request_digest IS NULL)
           OR (protocol_version = 3
               AND authorization_kind = 'approved_identity_join'
               AND join_request_digest IS NOT NULL
               AND approval_request_digest IS NOT NULL
               AND octet_length(join_request_digest) = 32
               AND octet_length(approval_request_digest) = 32));
