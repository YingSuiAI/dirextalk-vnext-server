use super::*;

#[test]
fn database_secret_hash_is_fixed_and_redacted() {
    let credential = DeviceSessionCredential::new(DeviceSessionId::new(), [7; 32]).unwrap();
    let first = credential.database_secret_hash();
    let second = credential.database_secret_hash();
    assert_eq!(first, second);
    assert_eq!(first.for_database_binding(), second.for_database_binding());
    let debug = format!("{first:?}");
    assert!(debug.contains("REDACTED"));
    assert!(!debug.contains('7'));
}
