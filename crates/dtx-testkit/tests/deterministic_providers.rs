use std::str::FromStr;

use dtx_domain::{Clock, IdGenerationError, IdGenerator};
use dtx_testkit::{FixedClock, SequenceIdGenerator};
use uuid::Uuid;

#[test]
fn fixed_clock_and_uuid_sequence_are_deterministic_and_fail_closed() {
    let clock = FixedClock::new(1_721_234_567_890);
    assert_eq!(clock.now_utc_millis().unwrap(), 1_721_234_567_890);

    let first = Uuid::from_str("01890f3a-9d8b-7cc5-98c4-dc0c0c07398f").unwrap();
    let second = Uuid::from_str("01890f3a-9d8c-7cc5-98c4-dc0c0c07398f").unwrap();
    let generator = SequenceIdGenerator::try_new([first, second]).unwrap();
    assert_eq!(generator.next_uuid_v7().unwrap(), first);
    assert_eq!(generator.next_uuid_v7().unwrap(), second);
    assert_eq!(
        generator.next_uuid_v7().unwrap_err(),
        IdGenerationError::SequenceExhausted
    );

    let non_v7 = Uuid::from_str("67e55044-10b1-426f-9247-bb680e5fe0c8").unwrap();
    let error = SequenceIdGenerator::try_new([non_v7]).unwrap_err();
    assert_eq!(error, IdGenerationError::InvalidUuidV7);
    assert!(!error.to_string().contains(&non_v7.to_string()));
}
