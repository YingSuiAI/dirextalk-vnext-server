-- AR3: fenced Agent Run checkpoints, output references, and exact terminal claims.

CREATE TABLE agent.agent_run_execution_heads (
    tenant_id uuid NOT NULL,
    run_id uuid NOT NULL,
    run_lease_id uuid NOT NULL,
    run_lease_epoch bigint NOT NULL,
    connector_id uuid NOT NULL,
    connector_boot_id uuid NOT NULL,
    connector_generation bigint NOT NULL,
    connector_lease_id uuid NOT NULL,
    connector_lease_epoch bigint NOT NULL,
    last_checkpoint_sequence bigint NOT NULL DEFAULT 0,
    last_output_sequence bigint NOT NULL DEFAULT 0,
    terminal_sequence bigint,
    terminal_kind text,
    state text NOT NULL,
    created_at_ms bigint NOT NULL,
    updated_at_ms bigint NOT NULL,
    PRIMARY KEY (tenant_id, run_id),
    CONSTRAINT agent_run_execution_heads_run_fk FOREIGN KEY (tenant_id, run_id)
        REFERENCES agent.agent_runs (tenant_id, run_id) ON DELETE RESTRICT,
    CONSTRAINT agent_run_execution_heads_lease_fk FOREIGN KEY (tenant_id, run_id, run_lease_id)
        REFERENCES agent.agent_run_leases (tenant_id, run_id, run_lease_id) ON DELETE RESTRICT,
    CONSTRAINT agent_run_execution_heads_ids_v7 CHECK (
        system.is_uuid_v7(tenant_id) AND system.is_uuid_v7(run_id)
        AND system.is_uuid_v7(run_lease_id) AND system.is_uuid_v7(connector_id)
        AND system.is_uuid_v7(connector_boot_id) AND system.is_uuid_v7(connector_lease_id)
    ),
    CONSTRAINT agent_run_execution_heads_values CHECK (
        run_lease_epoch BETWEEN 1 AND 9007199254740991
        AND connector_generation BETWEEN 1 AND 9007199254740991
        AND connector_lease_epoch BETWEEN 1 AND 9007199254740991
        AND last_checkpoint_sequence BETWEEN 0 AND 9007199254740991
        AND last_output_sequence BETWEEN 0 AND 9007199254740991
        AND (terminal_sequence IS NULL OR terminal_sequence BETWEEN 1 AND 9007199254740991)
        AND ((state = 'active' AND terminal_sequence IS NULL AND terminal_kind IS NULL)
          OR (state IN ('completed', 'failed') AND terminal_sequence IS NOT NULL
              AND terminal_kind = state))
        AND updated_at_ms >= created_at_ms
    )
);

CREATE TABLE agent.agent_run_checkpoints (
    tenant_id uuid NOT NULL,
    run_id uuid NOT NULL,
    checkpoint_sequence bigint NOT NULL,
    checkpoint_artifact_id uuid NOT NULL,
    checkpoint_digest bytea NOT NULL,
    created_at_ms bigint NOT NULL,
    PRIMARY KEY (tenant_id, run_id, checkpoint_sequence),
    UNIQUE (tenant_id, checkpoint_artifact_id),
    FOREIGN KEY (tenant_id, run_id) REFERENCES agent.agent_run_execution_heads (tenant_id, run_id),
    CHECK (checkpoint_sequence BETWEEN 1 AND 9007199254740991),
    CHECK (system.is_uuid_v7(checkpoint_artifact_id)),
    CHECK (octet_length(checkpoint_digest) = 32)
);

CREATE TABLE agent.agent_run_outputs (
    tenant_id uuid NOT NULL,
    run_id uuid NOT NULL,
    output_sequence bigint NOT NULL,
    output_event_id uuid NOT NULL,
    output_digest bytea NOT NULL,
    created_at_ms bigint NOT NULL,
    PRIMARY KEY (tenant_id, run_id, output_sequence),
    UNIQUE (tenant_id, output_event_id),
    FOREIGN KEY (tenant_id, run_id) REFERENCES agent.agent_run_execution_heads (tenant_id, run_id),
    CHECK (output_sequence BETWEEN 1 AND 9007199254740991),
    CHECK (system.is_uuid_v7(output_event_id)),
    CHECK (octet_length(output_digest) = 32)
);

CREATE TABLE agent.agent_run_terminals (
    tenant_id uuid NOT NULL,
    run_id uuid NOT NULL,
    terminal_sequence bigint NOT NULL,
    terminal_kind text NOT NULL,
    result_event_id uuid,
    stable_error_code text,
    evidence_artifact_id uuid,
    evidence_digest bytea,
    terminal_digest bytea NOT NULL,
    created_at_ms bigint NOT NULL,
    PRIMARY KEY (tenant_id, run_id),
    FOREIGN KEY (tenant_id, run_id) REFERENCES agent.agent_run_execution_heads (tenant_id, run_id),
    CHECK (terminal_sequence BETWEEN 1 AND 9007199254740991),
    CHECK (octet_length(terminal_digest) = 32),
    CHECK ((terminal_kind = 'completed' AND system.is_uuid_v7(result_event_id)
            AND stable_error_code IS NULL AND evidence_artifact_id IS NULL
            AND evidence_digest IS NULL)
        OR (terminal_kind = 'failed' AND result_event_id IS NULL
            AND stable_error_code ~ '^[A-Z][A-Z0-9_]{2,63}$'
            AND ((evidence_artifact_id IS NULL AND evidence_digest IS NULL)
              OR (system.is_uuid_v7(evidence_artifact_id) AND octet_length(evidence_digest) = 32))))
);

ALTER TABLE agent.agent_run_execution_heads ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent.agent_run_execution_heads FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON agent.agent_run_execution_heads
    USING (tenant_id = system.current_tenant_id()) WITH CHECK (tenant_id = system.current_tenant_id());
ALTER TABLE agent.agent_run_checkpoints ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent.agent_run_checkpoints FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON agent.agent_run_checkpoints
    USING (tenant_id = system.current_tenant_id()) WITH CHECK (tenant_id = system.current_tenant_id());
ALTER TABLE agent.agent_run_outputs ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent.agent_run_outputs FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON agent.agent_run_outputs
    USING (tenant_id = system.current_tenant_id()) WITH CHECK (tenant_id = system.current_tenant_id());
ALTER TABLE agent.agent_run_terminals ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent.agent_run_terminals FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON agent.agent_run_terminals
    USING (tenant_id = system.current_tenant_id()) WITH CHECK (tenant_id = system.current_tenant_id());

REVOKE ALL ON agent.agent_run_execution_heads FROM PUBLIC;
REVOKE ALL ON agent.agent_run_checkpoints FROM PUBLIC;
REVOKE ALL ON agent.agent_run_outputs FROM PUBLIC;
REVOKE ALL ON agent.agent_run_terminals FROM PUBLIC;
