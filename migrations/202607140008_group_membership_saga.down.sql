DROP TABLE groups.sequencer_outbox;
DROP TABLE groups.membership_workflows;
DROP TABLE groups.membership_commands;
DROP TABLE groups.join_records;
DROP TABLE groups.invites;
DROP TABLE groups.members;
DROP TABLE groups.admin_terms;
DROP TABLE groups.policy_heads;

DROP FUNCTION groups.reject_immutable_mutation();
DROP FUNCTION groups.group_owner_authorized();
DROP FUNCTION groups.group_runtime_authorized();

DROP SCHEMA groups;
