DROP TRIGGER IF EXISTS agent_run_offer_notify ON agent.agent_run_offers;
DROP FUNCTION IF EXISTS agent.notify_agent_run_offer();

DROP TRIGGER IF EXISTS agent_run_state_bundle_from_lease ON agent.agent_run_leases;
DROP TRIGGER IF EXISTS agent_run_state_bundle_from_offer ON agent.agent_run_offers;
DROP TRIGGER IF EXISTS agent_run_state_bundle_from_run ON agent.agent_runs;
DROP FUNCTION IF EXISTS agent.enforce_agent_run_state_bundle();

DROP TRIGGER IF EXISTS agent_run_lease_bundle ON agent.agent_run_leases;
DROP FUNCTION IF EXISTS agent.enforce_agent_run_lease_bundle();
DROP TRIGGER IF EXISTS agent_run_offer_bundle ON agent.agent_run_offers;
DROP FUNCTION IF EXISTS agent.enforce_agent_run_offer_bundle();

DROP TRIGGER IF EXISTS agent_run_candidate_count_from_candidate ON agent.agent_run_candidates;
DROP TRIGGER IF EXISTS agent_run_candidate_count_from_run ON agent.agent_runs;
DROP FUNCTION IF EXISTS agent.enforce_agent_run_candidate_count();
DROP TRIGGER IF EXISTS agent_run_candidate_scope ON agent.agent_run_candidates;
DROP FUNCTION IF EXISTS agent.enforce_agent_run_candidate_scope();

DROP TRIGGER IF EXISTS binding_run_capacity_head_transition ON agent.binding_run_capacity_heads;
DROP TRIGGER IF EXISTS connector_run_capacity_head_transition ON agent.connector_run_capacity_heads;
DROP FUNCTION IF EXISTS agent.enforce_binding_run_capacity_head_transition();
DROP FUNCTION IF EXISTS agent.enforce_connector_run_capacity_head_transition();
DROP TRIGGER IF EXISTS agent_run_lease_transition ON agent.agent_run_leases;
DROP FUNCTION IF EXISTS agent.enforce_agent_run_lease_transition();
DROP TRIGGER IF EXISTS agent_run_offer_transition ON agent.agent_run_offers;
DROP FUNCTION IF EXISTS agent.enforce_agent_run_offer_transition();
DROP TRIGGER IF EXISTS agent_run_candidates_immutable ON agent.agent_run_candidates;
DROP TRIGGER IF EXISTS agent_run_head_transition ON agent.agent_runs;
DROP FUNCTION IF EXISTS agent.enforce_agent_run_head_transition();

ALTER TABLE agent.agent_runs DROP CONSTRAINT IF EXISTS agent_runs_current_lease_fk;
ALTER TABLE agent.agent_runs DROP CONSTRAINT IF EXISTS agent_runs_current_offer_fk;

DROP TABLE IF EXISTS agent.agent_run_leases;
DROP TABLE IF EXISTS agent.agent_run_offers;
DROP TABLE IF EXISTS agent.binding_run_capacity_heads;
DROP TABLE IF EXISTS agent.connector_run_capacity_heads;
DROP TABLE IF EXISTS agent.agent_run_candidates;
DROP TABLE IF EXISTS agent.agent_runs;
DROP FUNCTION IF EXISTS agent.router_stable_names(text[]);
