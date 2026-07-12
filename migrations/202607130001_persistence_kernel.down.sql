DROP VIEW system.schema_versions;

DROP TABLE system.projection_cursors;
DROP TABLE system.audit_events;
DROP TABLE system.inbox_dedup;
DROP TABLE system.outbox_events;
DROP TABLE system.durable_events;
DROP TABLE system.tenant_stream_heads;

DROP FUNCTION system.enforce_completed_inbox();
DROP FUNCTION system.enforce_inbox_transition();
DROP FUNCTION system.is_stable_code(text, integer);
DROP FUNCTION system.is_uuid_v7(uuid);
DROP FUNCTION system.current_tenant_id();
DROP SCHEMA system;
