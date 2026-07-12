use dtx_wire::{ProtocolVersion, VersionError, WireVersion, ensure_readable};

#[test]
fn reader_accepts_a_newer_writer_when_minimum_reader_is_supported() {
    let reader = ProtocolVersion::new(1, 2);
    let message = WireVersion::new(ProtocolVersion::new(1, 4), ProtocolVersion::new(1, 1));

    assert_eq!(ensure_readable(reader, message), Ok(()));
}

#[test]
fn reader_rejects_a_message_that_requires_a_newer_reader() {
    let reader = ProtocolVersion::new(1, 2);
    let message = WireVersion::new(ProtocolVersion::new(1, 4), ProtocolVersion::new(1, 3));

    assert_eq!(
        ensure_readable(reader, message),
        Err(VersionError::ReaderTooOld {
            reader,
            minimum: ProtocolVersion::new(1, 3),
        })
    );
}

#[test]
fn reader_rejects_a_different_protocol_major() {
    let reader = ProtocolVersion::new(1, 9);
    let message = WireVersion::new(ProtocolVersion::new(2, 0), ProtocolVersion::new(2, 0));

    assert_eq!(
        ensure_readable(reader, message),
        Err(VersionError::UnsupportedMajor {
            reader_major: 1,
            message_major: 2,
        })
    );
}

#[test]
fn reader_rejects_an_internally_invalid_version_range() {
    let reader = ProtocolVersion::new(1, 5);
    let message = WireVersion::new(ProtocolVersion::new(1, 2), ProtocolVersion::new(1, 3));

    assert_eq!(
        ensure_readable(reader, message),
        Err(VersionError::InvalidVersionRange {
            protocol: ProtocolVersion::new(1, 2),
            minimum: ProtocolVersion::new(1, 3),
        })
    );
}
