DO $$ BEGIN
 LOCK TABLE messaging.opaque_push_registrations, messaging.opaque_push_idempotency_claims, messaging.opaque_push_deliveries IN SHARE ROW EXCLUSIVE MODE;
 IF EXISTS(SELECT 1 FROM messaging.opaque_push_registrations) OR EXISTS(SELECT 1 FROM messaging.opaque_push_idempotency_claims) OR EXISTS(SELECT 1 FROM messaging.opaque_push_deliveries) THEN RAISE EXCEPTION 'cannot downgrade opaque push V1 while authoritative facts exist' USING ERRCODE='55000'; END IF;
END $$;
DROP POLICY opaque_push_identity_auth_entry_select ON identity.log_entries;
DROP POLICY opaque_push_identity_auth_head_select ON identity.log_heads;
DROP POLICY opaque_push_identity_auth_session_select ON identity.device_sessions;
DO $revoke$ BEGIN
 IF to_regrole('dtx_push_identity_auth_runtime') IS NOT NULL THEN REVOKE SELECT ON identity.device_sessions,identity.log_heads,identity.log_entries FROM dtx_push_identity_auth_runtime; REVOKE USAGE ON SCHEMA identity FROM dtx_push_identity_auth_runtime; END IF;
 IF to_regrole('dtx_push_registration_runtime') IS NOT NULL THEN REVOKE ALL ON FUNCTION messaging.opaque_push_prepare_mutation(uuid,bytea,text,text,bytea,bigint,bytea,uuid),messaging.opaque_push_commit_put(uuid,bytea,uuid,text,text,bytea,bigint,bytea,smallint,smallint,smallint,smallint,text,bigint,bytea,bytea,bytea,bytea,text,bytea),messaging.opaque_push_commit_delete(uuid,bytea,text,text,bytea,bigint,bytea,smallint,smallint,smallint,smallint,text,bigint,bytea) FROM dtx_push_registration_runtime; REVOKE USAGE ON SCHEMA messaging FROM dtx_push_registration_runtime; END IF;
 IF to_regrole('dtx_mailbox_runtime') IS NOT NULL THEN REVOKE ALL ON FUNCTION messaging.enqueue_opaque_push_intent(uuid,uuid,uuid) FROM dtx_mailbox_runtime; END IF;
 IF to_regrole('dtx_push_broker_runtime') IS NOT NULL THEN REVOKE ALL ON FUNCTION messaging.claim_opaque_push_deliveries(uuid,integer),messaging.prune_opaque_push_terminal(integer),messaging.authorize_opaque_push_send(uuid,uuid),messaging.finish_opaque_push_accepted(uuid,uuid),messaging.finish_opaque_push_permanent_failure(uuid,uuid,text),messaging.finish_opaque_push_transient(uuid,uuid,integer,text),messaging.finish_opaque_push_invalid_token(uuid,uuid,bigint) FROM dtx_push_broker_runtime; REVOKE USAGE ON SCHEMA messaging FROM dtx_push_broker_runtime; END IF;
END $revoke$;
DROP FUNCTION messaging.opaque_push_commit_delete(uuid,bytea,text,text,bytea,bigint,bytea,smallint,smallint,smallint,smallint,text,bigint,bytea);
DROP FUNCTION messaging.opaque_push_commit_put(uuid,bytea,uuid,text,text,bytea,bigint,bytea,smallint,smallint,smallint,smallint,text,bigint,bytea,bytea,bytea,bytea,text,bytea);
DROP FUNCTION messaging.opaque_push_prepare_mutation(uuid,bytea,text,text,bytea,bigint,bytea,uuid);
DROP FUNCTION messaging.opaque_push_canonical_receipt(bigint,text);
DROP FUNCTION messaging.opaque_push_cbor_uint(bigint);
DROP FUNCTION messaging.prune_opaque_push_terminal(integer);
DROP FUNCTION messaging.finish_opaque_push_invalid_token(uuid,uuid,bigint);
DROP FUNCTION messaging.finish_opaque_push_transient(uuid,uuid,integer,text);
DROP FUNCTION messaging.finish_opaque_push_permanent_failure(uuid,uuid,text);
DROP FUNCTION messaging.finish_opaque_push_accepted(uuid,uuid);
DROP FUNCTION messaging.authorize_opaque_push_send(uuid,uuid);
DROP FUNCTION messaging.claim_opaque_push_deliveries(uuid,integer);
DROP FUNCTION messaging.enqueue_opaque_push_intent(uuid,uuid,uuid);
DROP TABLE messaging.opaque_push_deliveries;
DROP TABLE messaging.opaque_push_idempotency_claims;
DROP TABLE messaging.opaque_push_registrations;
