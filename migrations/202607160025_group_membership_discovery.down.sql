DROP INDEX IF EXISTS groups.groups_join_records_pending_page_idx;
DROP INDEX IF EXISTS groups.groups_membership_commands_request_workflow_unique;

ALTER TABLE groups.membership_workflows
    DROP CONSTRAINT IF EXISTS groups_membership_workflows_candidate_origin_shape,
    DROP COLUMN IF EXISTS candidate_identity_origin;
