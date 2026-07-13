DROP TABLE agent.host_credential_authorization_heads;
DROP TABLE agent.host_credential_authorization_states;
DROP TABLE agent.host_credential_authorization_revisions;
DROP TABLE agent.host_credential_authorization_credentials;
DROP FUNCTION agent.enforce_host_auth_revision_published();
DROP FUNCTION agent.enforce_host_auth_state_insert();
DROP FUNCTION agent.enforce_host_auth_revision_insert();
DROP FUNCTION agent.enforce_host_auth_head_transition();
