use dtx_protocol::{parse_error_registry, parse_event_registry};

fn event_registry(event_type: &str, schema_version: u16) -> String {
    format!(
        r"
version: 1
events:
  - type: {event_type}
    rust_name: ExampleChangedV1
    schema_version: {schema_version}
    aggregate: example
    required_reader_capability: example.v1
    authorization: owner
    retention: tenant_policy
    redaction: identifiers_only
    snapshot_projection: examples
    unknown_version_policy: stop_cursor
    fields:
      - {{ key: 1, name: example_id, type: aggregate_id }}
"
    )
}

#[test]
fn event_registry_rejects_zero_versions_and_noncanonical_stable_types() {
    assert!(parse_event_registry(&event_registry("example.changed.v0", 0)).is_err());
    assert!(parse_event_registry(&event_registry("1example.changed.v1", 1)).is_err());
    assert!(parse_event_registry(&event_registry("example_.changed.v1", 1)).is_err());
    assert!(parse_event_registry(&event_registry("example..changed.v1", 1)).is_err());
}

#[test]
fn error_registry_rejects_codes_the_runtime_parser_cannot_accept() {
    let source = r"
version: 1
errors:
  - code: A
    rust_name: A
    http_status: 400
    default_retryable: false
    message: Invalid.
";

    assert!(parse_error_registry(source).is_err());
}
