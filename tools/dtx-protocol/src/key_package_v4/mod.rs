use std::{fs, path::Path};

use serde_json::Value;

use crate::ProtocolToolError;

mod cddl;
mod helpers;
mod openapi;
const CDDL_RELATIVE: &str = "protocol/cddl/key-package/v4/key-package-v4.cddl";
const OPENAPI_RELATIVE: &str = "protocol/openapi/key-package/v4/openapi.yaml";
const CDDL_SHA256: &str = "49ca347b7925933af5c920e772b073ad8e814166e84cada10fbb20e29076ab60";
const OPENAPI_SHA256: &str = "0fca685638b646bc1fb7a7455e3496479a2f3f1b8786c857162277b62ea716ba";

const DOMAINS: &[(&str, &str)] = &[
    (
        "publish-binding",
        "dirextalk.key-package.publish-binding.v4\0",
    ),
    (
        "publish-signature",
        "dirextalk.key-package.publish-signature.v4\0",
    ),
    (
        "publish-envelope",
        "dirextalk.key-package.publish-envelope.v4\0",
    ),
    (
        "publish-idempotency",
        "dirextalk.key-package.publish-idempotency.v4\0",
    ),
    (
        "publish-receipt",
        "dirextalk.key-package.publish-receipt.v4\0",
    ),
    ("claim", "dirextalk.key-package.claim.v4\0"),
    (
        "claim-idempotency",
        "dirextalk.key-package.claim-idempotency.v4\0",
    ),
    ("claim-receipt", "dirextalk.key-package.claim-receipt.v4\0"),
    ("opaque-package", "dirextalk.key-package.opaque-body.v4\0"),
];

#[derive(Clone, Copy)]
enum ExpectedType<'a> {
    Literal(u64),
    Name(&'a str),
    FixedSize(&'a str, u64),
    BoundedBstr(u64),
}

pub(crate) fn validate(root: &Path) -> Result<(), ProtocolToolError> {
    let cddl = fs::read_to_string(root.join(CDDL_RELATIVE))
        .map_err(|error| ProtocolToolError::new(format!("read {CDDL_RELATIVE}: {error}")))?;
    let openapi = fs::read_to_string(root.join(OPENAPI_RELATIVE))
        .map_err(|error| ProtocolToolError::new(format!("read {OPENAPI_RELATIVE}: {error}")))?;
    validate_sources(&cddl, &openapi)
}

fn validate_sources(cddl_source: &str, openapi_source: &str) -> Result<(), ProtocolToolError> {
    let cddl = cddl_cat::parse_cddl(cddl_source)
        .map_err(|error| ProtocolToolError::new(format!("parse Key Package V4 CDDL: {error}")))?;
    cddl::validate_contract(&cddl)?;

    let spec = oas3::from_yaml(openapi_source).map_err(|error| {
        ProtocolToolError::new(format!("parse Key Package V4 OpenAPI: {error}"))
    })?;
    if spec.openapi != "3.1.0" {
        return Err(ProtocolToolError::new(
            "Key Package V4 OpenAPI must declare 3.1.0",
        ));
    }
    let document: Value = yaml_serde::from_str(openapi_source).map_err(|error| {
        ProtocolToolError::new(format!("parse Key Package V4 OpenAPI tree: {error}"))
    })?;
    openapi::validate_contract(&document)?;

    helpers::require_sha256(cddl_source, CDDL_SHA256, "Key Package V4 CDDL")?;
    helpers::require_sha256(openapi_source, OPENAPI_SHA256, "Key Package V4 OpenAPI")
}

#[cfg(test)]
mod tests;
