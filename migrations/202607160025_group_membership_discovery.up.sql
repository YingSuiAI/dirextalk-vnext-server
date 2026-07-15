-- V29 adds the candidate's authoritative identity-log origin to the durable
-- membership workflow. Existing rows deliberately remain NULL: discovery
-- fails closed for those rows instead of inventing an origin after the fact.
ALTER TABLE groups.membership_workflows
    ADD COLUMN candidate_identity_origin text;

ALTER TABLE groups.membership_workflows
    ADD CONSTRAINT groups_membership_workflows_candidate_origin_shape
    CHECK (candidate_identity_origin IS NULL OR (
        octet_length(candidate_identity_origin) BETWEEN 10 AND 512
        AND candidate_identity_origin ~ '^https?://[^/[:space:]]+$'
    ));

CREATE UNIQUE INDEX groups_membership_commands_request_workflow_unique
    ON groups.membership_commands (tenant_id, scope_kind, scope_id, workflow_id)
    WHERE kind = 'request_join' AND workflow_id IS NOT NULL;

CREATE INDEX groups_join_records_pending_page_idx
    ON groups.join_records (
        tenant_id,
        scope_kind,
        scope_id,
        requested_at_ms,
        request_id
    )
    WHERE state = 'pending';
