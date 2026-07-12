use std::str::FromStr;

use dtx_domain::{
    Clock, IdGenerationError, IdGenerator, Revision, RevisionError, SystemClock, UuidV7Generator,
    test_support::{FixedClock, SequenceIdGenerator},
};
use uuid::{Uuid, Variant};

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
fn fixed_clock_always_returns_the_configured_utc_millis() {
    let clock = FixedClock::new(1_721_234_567_890);

    assert_eq!(clock.now_utc_millis().unwrap(), 1_721_234_567_890);
    assert_eq!(clock.now_utc_millis().unwrap(), 1_721_234_567_890);
}

#[test]
fn system_clock_returns_a_current_utc_millisecond_value() {
    let timestamp = SystemClock.now_utc_millis().unwrap();

    assert!(timestamp > 0);
}

#[test]
fn sequence_id_generator_preserves_order_then_reports_exhaustion() {
    let first = Uuid::from_str("01890f3a-9d8b-7cc5-98c4-dc0c0c07398f").unwrap();
    let second = Uuid::from_str("01890f3a-9d8c-7cc5-98c4-dc0c0c07398f").unwrap();
    let generator = SequenceIdGenerator::try_new([first, second]).unwrap();

    assert_eq!(generator.next_uuid_v7().unwrap(), first);
    assert_eq!(generator.next_uuid_v7().unwrap(), second);
    assert_eq!(
        generator.next_uuid_v7().unwrap_err(),
        IdGenerationError::SequenceExhausted
    );
}

#[test]
fn sequence_id_generator_rejects_non_v7_without_echoing_it() {
    let non_v7 = Uuid::from_str("67e55044-10b1-426f-9247-bb680e5fe0c8").unwrap();

    let error = SequenceIdGenerator::try_new([non_v7]).unwrap_err();

    assert_eq!(error, IdGenerationError::InvalidUuidV7);
    assert_eq!(error.to_string(), "identifier is not a valid UUIDv7");
    assert!(!error.to_string().contains(&non_v7.to_string()));
}

#[test]
fn production_generator_returns_rfc_uuid_v7() {
    let uuid = UuidV7Generator.next_uuid_v7().unwrap();

    assert_eq!(uuid.get_version_num(), 7);
    assert_eq!(uuid.get_variant(), Variant::RFC4122);
}
