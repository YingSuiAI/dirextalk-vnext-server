use super::*;

#[cfg(test)]
mod contract_tests {
    use super::*;

    const CDDL: &str =
        include_str!("../../../../protocol/cddl/mls-sequencer/v7/mls-sequencer-v7.cddl");
    const OPENAPI: &str =
        include_str!("../../../../protocol/openapi/mls-sequencer/v7/openapi.yaml");

    fn rejected(cddl: &str, openapi: &str, expected: &str) {
        let error = validate_sources(cddl, openapi).expect_err("mutation must be rejected");
        assert!(
            error.to_string().contains(expected),
            "expected diagnostic containing {expected:?}, got {error}"
        );
    }

    fn replace_once(source: &str, from: &str, to: &str) -> String {
        let mutated = source.replacen(from, to, 1);
        assert_ne!(mutated, source, "mutation fixture did not match {from:?}");
        mutated
    }

    #[test]
    fn frozen_mls_sequencer_v7_contract_passes() {
        validate_sources(CDDL, OPENAPI).expect("frozen MLS Sequencer V7 must validate");
    }

    #[test]
    fn rejects_add_ceiling_mutation() {
        let mutated = replace_once(
            OPENAPI,
            "  recovery-add-v7: 4489217",
            "  recovery-add-v7: 4489150",
        );
        rejected(CDDL, &mutated, "body ceiling drift");
    }

    #[test]
    fn rejects_required_field_type_and_key_mutations() {
        let missing = replace_once(CDDL, "  51: signature\n", "");
        rejected(&missing, OPENAPI, "required field/type/key");

        let changed_type = replace_once(CDDL, "  51: signature", "  51: digest");
        rejected(&changed_type, OPENAPI, "required field/type/key");

        let changed_key = replace_once(CDDL, "  51: signature", "  52: signature");
        rejected(&changed_key, OPENAPI, "required field/type/key");
    }

    #[test]
    fn rejects_domain_count_and_value_mutations() {
        let missing = replace_once(
            OPENAPI,
            "  raw-mls-welcome: \"dirextalk.mls-recovery.raw-mls-welcome.v7\\0\"\n",
            "",
        );
        rejected(CDDL, &missing, "domains key set drift");

        let changed = replace_once(
            OPENAPI,
            "dirextalk.mls-recovery.raw-mls-commit.v7\\0",
            "dirextalk.mls-recovery.raw-mls-commit.v8\\0",
        );
        rejected(CDDL, &changed, "domain value drift");

        let cddl_changed = replace_once(
            CDDL,
            "dirextalk.mls-recovery.raw-mls-welcome.v7\\0",
            "dirextalk.mls-recovery.raw-mls-welcome.v8\\0",
        );
        rejected(&cddl_changed, OPENAPI, "CDDL domain count/value drift");
    }

    #[test]
    fn rejects_closed_map_count_and_layout_mutations() {
        let wrapper = "signed-mls-recovery-completion-cache-receipt-v2 = {\n  1: mls-recovery-completion-cache-receipt-v2,\n  2: digest, 3: uuid-v7, 4: ed25519-public-key,\n  5: signature                    ; authority signs exact fields 1..4\n}";
        let missing_map = replace_once(
            CDDL,
            wrapper,
            "signed-mls-recovery-completion-cache-receipt-v2 = digest",
        );
        rejected(&missing_map, OPENAPI, "closed map inventory drift");

        let changed_layout = replace_once(
            CDDL,
            "  2: digest, 3: uuid-v7, 4: ed25519-public-key,\n  5: signature                    ; authority signs exact fields 1..4\n}",
            "  2: digest, 3: uuid-v7, 5: ed25519-public-key,\n  4: signature                    ; invalid field ordering\n}",
        );
        rejected(&changed_layout, OPENAPI, "required field/type/key");
    }

    #[test]
    fn rejects_raw_commit_and_welcome_type_mutations() {
        let commit = replace_once(CDDL, "  40: bstr .size (1..1048576),", "  40: digest,");
        rejected(&commit, OPENAPI, "required field/type/key");

        let welcome = replace_once(CDDL, "  42: bstr .size (1..1048576),", "  42: digest,");
        rejected(&welcome, OPENAPI, "required field/type/key");
    }

    #[test]
    fn rejects_imported_history_context_rehash_mutation() {
        let mutated = replace_once(
            OPENAPI,
            "  mls-domain-alias-second-hash-or-re-encoding: forbidden",
            "  mls-domain-alias-second-hash-or-re-encoding: allowed",
        );
        rejected(CDDL, &mutated, "imported History context binding drift");
    }

    #[test]
    fn rejects_openapi_path_operation_and_schema_maximum_mutations() {
        let path = replace_once(
            OPENAPI,
            "  /v2/groups/{scope_kind}/{scope_id}/mls-recovery-commits/{submission_id}:\n",
            "  /v3/groups/{scope_kind}/{scope_id}/mls-recovery-commits/{submission_id}:\n",
        );
        rejected(CDDL, &path, "paths key set drift");

        let operation = replace_once(
            OPENAPI,
            "operationId: submitMlsRecoveryCommitV7",
            "operationId: submitMlsRecoveryCommitV8",
        );
        rejected(CDDL, &operation, "operationId drift");

        let schema = replace_once(
            OPENAPI,
            "      maxLength: 4489217",
            "      maxLength: 4489150",
        );
        rejected(CDDL, &schema, "schema maximum/media rule drift");
    }

    #[test]
    fn rejects_openapi_media_relationship_mutation() {
        let mutated = replace_once(
            OPENAPI,
            "application/vnd.dirextalk.mls-recovery-commit.v7+cbor:",
            "application/vnd.dirextalk.mls-recovery-commit.v8+cbor:",
        );
        rejected(CDDL, &mutated, "key set drift");
    }

    #[test]
    fn rejects_snapshot_cas_and_revocation_binding_mutations() {
        let snapshot = replace_once(
            OPENAPI,
            "activation-receipt-and-readback: exact-private-issuance-time-snapshots",
            "activation-receipt-and-readback: current-readback",
        );
        rejected(CDDL, &snapshot, "cache operation snapshot binding drift");

        let revocation = replace_once(
            OPENAPI,
            "    - explicit-revocation-generations",
            "    - descriptor-generation-only",
        );
        rejected(
            CDDL,
            &revocation,
            "completion cache snapshot/CAS/revocation binding drift",
        );
    }
}
