use dtx_domain::{Clock, IdGenerator, Revision, RevisionError, SystemClock, UuidV7Generator};
use uuid::Variant;

#[test]
fn revision_starts_at_one_and_advances_within_the_safe_range() {
    assert_eq!(Revision::INITIAL.get(), 1);
    assert_eq!(Revision::new(41).unwrap().checked_next().unwrap().get(), 42);
}

#[test]
fn revision_rejects_zero_and_cannot_advance_past_its_maximum() {
    assert_eq!(Revision::new(0), Err(RevisionError::OutOfRange));
    assert_eq!(
        Revision::new(Revision::MAX).unwrap().checked_next(),
        Err(RevisionError::Overflow)
    );
    assert_eq!(
        Revision::new(Revision::MAX + 1),
        Err(RevisionError::OutOfRange)
    );
}

#[test]
fn system_clock_returns_a_current_utc_millisecond_value() {
    let timestamp = SystemClock.now_utc_millis().unwrap();

    assert!(timestamp > 0);
}

#[test]
fn production_generator_returns_rfc_uuid_v7() {
    let uuid = UuidV7Generator.next_uuid_v7().unwrap();

    assert_eq!(uuid.get_version_num(), 7);
    assert_eq!(uuid.get_variant(), Variant::RFC4122);
}
