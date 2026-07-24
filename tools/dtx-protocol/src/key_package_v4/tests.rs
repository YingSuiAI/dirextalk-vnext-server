use super::*;

#[cfg(test)]
mod contract_tests {
    use super::*;

    const CDDL: &str = include_str!("../../../../protocol/cddl/key-package/v4/key-package-v4.cddl");
    const OPENAPI: &str = include_str!("../../../../protocol/openapi/key-package/v4/openapi.yaml");

    fn rejected(cddl: &str, openapi: &str, expected: &str) {
        let error = validate_sources(cddl, openapi).expect_err("mutation must be rejected");
        assert!(
            error.to_string().contains(expected),
            "expected diagnostic containing {expected:?}, got {error}"
        );
    }

    #[test]
    fn frozen_key_package_v4_contract_passes() {
        validate_sources(CDDL, OPENAPI).expect("frozen Key Package V4 must validate");
    }

    #[test]
    fn rejects_cddl_ceiling_increment() {
        let mutated = CDDL.replacen(
            "exact-key-package-publish-v4 = bstr .size (1..67294)",
            "exact-key-package-publish-v4 = bstr .size (1..67295)",
            1,
        );
        rejected(&mutated, OPENAPI, "CDDL ceiling drift");
    }

    #[test]
    fn rejects_required_field_type_mutation() {
        let mutated = CDDL.replacen(
            "  24: digest                    ; publish Idempotency-Key digest",
            "  24: uuid-v7                   ; invalid required field type",
            1,
        );
        rejected(&mutated, OPENAPI, "required field/type drift");
    }

    #[test]
    fn rejects_domain_mutation() {
        let mutated = OPENAPI.replacen(
            "dirextalk.key-package.publish-signature.v4\\0",
            "dirextalk.key-package.publish-signature.v5\\0",
            1,
        );
        rejected(CDDL, &mutated, "domain value drift");
    }

    #[test]
    fn rejects_canonical_bstr_relationship_mutation() {
        let mutated = CDDL.replacen(
            "  5: exact-key-package-publish-v4,",
            "  5: key-package-publish-v4,",
            1,
        );
        rejected(&mutated, OPENAPI, "required field/type drift");
    }

    #[test]
    fn rejects_openapi_path_mutation() {
        let mutated = OPENAPI.replacen(
            "  /v4/key-packages/claim:\n",
            "  /v5/key-packages/claim:\n",
            1,
        );
        rejected(CDDL, &mutated, "paths key set drift");
    }

    #[test]
    fn rejects_openapi_schema_maximum_mutation() {
        let mutated = OPENAPI.replacen("maxLength: 128", "maxLength: 129", 1);
        rejected(CDDL, &mutated, "schema maximum drift");
    }
}
