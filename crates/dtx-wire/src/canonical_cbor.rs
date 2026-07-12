use std::{error::Error, fmt};

const MAX_ENCODED_BYTES: usize = 1024 * 1024;
const MAX_DEPTH: usize = 32;
const MAX_CONTAINER_ENTRIES: usize = 4096;
const MAX_TOTAL_ITEMS: usize = 65_536;

/// The restricted CBOR value set supported by signed and hashed v1 contracts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CanonicalValue {
    /// An unsigned integer.
    Unsigned(u64),
    /// A negative integer. Non-negative values are rejected by the encoder.
    Negative(i64),
    /// A byte string.
    Bytes(Vec<u8>),
    /// A UTF-8 text string. No Unicode normalization is applied.
    Text(String),
    /// A definite-length array.
    Array(Vec<Self>),
    /// A definite-length map. Keys are sorted by their encoded bytes.
    Map(Vec<(Self, Self)>),
    /// A boolean.
    Bool(bool),
    /// An explicit null.
    Null,
}

/// Converts a typed contract value into the restricted canonical CBOR model.
pub trait CanonicalEncode {
    /// Returns the complete value that participates in hashing or signing.
    fn to_canonical_value(&self) -> CanonicalValue;
}

impl CanonicalEncode for CanonicalValue {
    fn to_canonical_value(&self) -> CanonicalValue {
        self.clone()
    }
}

/// Deterministic CBOR encoding or validation failed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CanonicalCborError {
    /// The encoded item exceeded the v1 byte limit.
    InputTooLarge,
    /// Nested values exceeded the v1 depth limit.
    DepthLimit,
    /// A container or the complete item tree exceeded its v1 entry budget.
    ContainerTooLarge,
    /// The encoded item ended before a declared value was complete.
    UnexpectedEnd,
    /// Additional-information values 28 through 30 are reserved.
    ReservedAdditionalInformation,
    /// Indefinite-length items are outside the deterministic profile.
    IndefiniteLength,
    /// An integer or length did not use its shortest representation.
    NonPreferredArgument,
    /// A negative [`CanonicalValue`] contained a non-negative integer.
    InvalidNegativeValue,
    /// An integer cannot be represented by the v1 signed field model.
    IntegerOutOfRange,
    /// A declared length cannot be represented safely on this host.
    LengthOutOfRange,
    /// A text string was not valid UTF-8.
    InvalidUtf8,
    /// Map keys were not in bytewise lexicographic order.
    MapKeyOrder,
    /// A map contained the same encoded key twice.
    DuplicateMapKey,
    /// CBOR tags are outside the v1 profile.
    TagNotAllowed,
    /// Floating-point values are outside signed and hashed v1 contracts.
    FloatingPointNotAllowed,
    /// Undefined or another unsupported simple value was present.
    SimpleValueNotAllowed,
    /// More than one top-level CBOR item was present.
    TrailingBytes,
}

impl fmt::Display for CanonicalCborError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InputTooLarge => "canonical CBOR exceeds the one MiB limit",
            Self::DepthLimit => "canonical CBOR exceeds the nesting depth limit",
            Self::ContainerTooLarge => "canonical CBOR exceeds a container or total item limit",
            Self::UnexpectedEnd => "canonical CBOR ended unexpectedly",
            Self::ReservedAdditionalInformation => "CBOR uses reserved additional information",
            Self::IndefiniteLength => "indefinite-length CBOR is not allowed",
            Self::NonPreferredArgument => "CBOR argument is not shortest-form",
            Self::InvalidNegativeValue => "negative CBOR value must be less than zero",
            Self::IntegerOutOfRange => "CBOR integer is outside the v1 field range",
            Self::LengthOutOfRange => "CBOR length cannot be represented safely",
            Self::InvalidUtf8 => "CBOR text is not valid UTF-8",
            Self::MapKeyOrder => "CBOR map keys are not in deterministic order",
            Self::DuplicateMapKey => "CBOR map contains a duplicate key",
            Self::TagNotAllowed => "CBOR tags are not allowed",
            Self::FloatingPointNotAllowed => "CBOR floating-point values are not allowed",
            Self::SimpleValueNotAllowed => "CBOR simple value is not allowed",
            Self::TrailingBytes => "bytes remain after the top-level CBOR item",
        })
    }
}

impl Error for CanonicalCborError {}

/// Encodes a typed value using the Dirextalk RFC 8949 core deterministic profile.
///
/// # Errors
///
/// Returns [`CanonicalCborError`] for duplicate keys, invalid negative values,
/// or profile size/depth violations.
pub fn encode_deterministic_cbor<T>(value: &T) -> Result<Vec<u8>, CanonicalCborError>
where
    T: CanonicalEncode + ?Sized,
{
    let mut encoder = Encoder::default();
    encoder.encode(&value.to_canonical_value(), 0)?;
    Ok(encoder.output)
}

/// Validates that `input` is exactly one item in the Dirextalk deterministic profile.
///
/// # Errors
///
/// Returns [`CanonicalCborError`] at the first structural or canonical violation.
pub fn validate_deterministic_cbor(input: &[u8]) -> Result<(), CanonicalCborError> {
    decode_deterministic_cbor(input).map(|_| ())
}

/// Decodes exactly one deterministic item into the restricted canonical model.
///
/// This is intentionally not a general-purpose CBOR decoder. It accepts the
/// same bounded profile emitted by [`encode_deterministic_cbor`] and is useful
/// when a security boundary must validate fields without losing the original
/// byte representation.
///
/// # Errors
///
/// Returns [`CanonicalCborError`] at the first structural or canonical violation.
pub fn decode_deterministic_cbor(input: &[u8]) -> Result<CanonicalValue, CanonicalCborError> {
    if input.len() > MAX_ENCODED_BYTES {
        return Err(CanonicalCborError::InputTooLarge);
    }
    let mut parser = Parser {
        input,
        position: 0,
        items: 0,
    };
    let value = parser.parse_value(0)?;
    if parser.position != input.len() {
        return Err(CanonicalCborError::TrailingBytes);
    }
    Ok(value)
}

#[derive(Default)]
struct Encoder {
    output: Vec<u8>,
    items: usize,
}

impl Encoder {
    fn encode(&mut self, value: &CanonicalValue, depth: usize) -> Result<(), CanonicalCborError> {
        if depth > MAX_DEPTH {
            return Err(CanonicalCborError::DepthLimit);
        }
        self.charge_items(1)?;
        match value {
            CanonicalValue::Unsigned(value) => self.write_head(0, *value),
            CanonicalValue::Negative(value) => {
                if *value >= 0 {
                    return Err(CanonicalCborError::InvalidNegativeValue);
                }
                let argument = u64::try_from(-1_i128 - i128::from(*value))
                    .map_err(|_| CanonicalCborError::IntegerOutOfRange)?;
                self.write_head(1, argument)
            }
            CanonicalValue::Bytes(value) => {
                self.write_length(2, value.len())?;
                self.write(value)
            }
            CanonicalValue::Text(value) => {
                self.write_length(3, value.len())?;
                self.write(value.as_bytes())
            }
            CanonicalValue::Array(values) => {
                Self::check_container(values.len())?;
                self.write_length(4, values.len())?;
                for value in values {
                    self.encode(value, depth + 1)?;
                }
                Ok(())
            }
            CanonicalValue::Map(entries) => {
                Self::check_container(entries.len())?;
                let mut sorted = Vec::with_capacity(entries.len());
                let mut pending_key_bytes = 0_usize;
                for (key, value) in entries {
                    let mut key_encoder = Self::default();
                    key_encoder.encode(key, depth + 1)?;
                    self.charge_items(key_encoder.items)?;
                    pending_key_bytes = pending_key_bytes
                        .checked_add(key_encoder.output.len())
                        .ok_or(CanonicalCborError::InputTooLarge)?;
                    let projected_bytes = self
                        .output
                        .len()
                        .checked_add(pending_key_bytes)
                        .ok_or(CanonicalCborError::InputTooLarge)?;
                    if projected_bytes > MAX_ENCODED_BYTES {
                        return Err(CanonicalCborError::InputTooLarge);
                    }
                    sorted.push((key_encoder.output, value));
                }
                sorted.sort_by(|left, right| left.0.cmp(&right.0));
                if sorted.windows(2).any(|pair| pair[0].0 == pair[1].0) {
                    return Err(CanonicalCborError::DuplicateMapKey);
                }
                self.write_length(5, sorted.len())?;
                for (key, value) in sorted {
                    self.write(&key)?;
                    self.encode(value, depth + 1)?;
                }
                Ok(())
            }
            CanonicalValue::Bool(false) => self.write(&[0xf4]),
            CanonicalValue::Bool(true) => self.write(&[0xf5]),
            CanonicalValue::Null => self.write(&[0xf6]),
        }
    }

    fn check_container(entries: usize) -> Result<(), CanonicalCborError> {
        if entries > MAX_CONTAINER_ENTRIES {
            Err(CanonicalCborError::ContainerTooLarge)
        } else {
            Ok(())
        }
    }

    fn charge_items(&mut self, count: usize) -> Result<(), CanonicalCborError> {
        self.items = self
            .items
            .checked_add(count)
            .ok_or(CanonicalCborError::ContainerTooLarge)?;
        if self.items > MAX_TOTAL_ITEMS {
            Err(CanonicalCborError::ContainerTooLarge)
        } else {
            Ok(())
        }
    }

    fn write_length(&mut self, major: u8, length: usize) -> Result<(), CanonicalCborError> {
        let length = u64::try_from(length).map_err(|_| CanonicalCborError::LengthOutOfRange)?;
        self.write_head(major, length)
    }

    fn write_head(&mut self, major: u8, argument: u64) -> Result<(), CanonicalCborError> {
        let marker = major << 5;
        if argument < 24 {
            self.write(&[marker | u8::try_from(argument).expect("argument below 24 fits u8")])
        } else if let Ok(value) = u8::try_from(argument) {
            self.write(&[marker | 0x18, value])
        } else if let Ok(value) = u16::try_from(argument) {
            self.write(&[marker | 0x19])?;
            self.write(&value.to_be_bytes())
        } else if let Ok(value) = u32::try_from(argument) {
            self.write(&[marker | 0x1a])?;
            self.write(&value.to_be_bytes())
        } else {
            self.write(&[marker | 0x1b])?;
            self.write(&argument.to_be_bytes())
        }
    }

    fn write(&mut self, bytes: &[u8]) -> Result<(), CanonicalCborError> {
        let new_length = self
            .output
            .len()
            .checked_add(bytes.len())
            .ok_or(CanonicalCborError::InputTooLarge)?;
        if new_length > MAX_ENCODED_BYTES {
            return Err(CanonicalCborError::InputTooLarge);
        }
        self.output.extend_from_slice(bytes);
        Ok(())
    }
}

struct Parser<'a> {
    input: &'a [u8],
    position: usize,
    items: usize,
}

impl Parser<'_> {
    fn parse_value(&mut self, depth: usize) -> Result<CanonicalValue, CanonicalCborError> {
        if depth > MAX_DEPTH {
            return Err(CanonicalCborError::DepthLimit);
        }
        self.items = self
            .items
            .checked_add(1)
            .ok_or(CanonicalCborError::ContainerTooLarge)?;
        if self.items > MAX_TOTAL_ITEMS {
            return Err(CanonicalCborError::ContainerTooLarge);
        }

        let initial = self.read_byte()?;
        let major = initial >> 5;
        let additional = initial & 0x1f;
        match major {
            0 => {
                let value = self.read_argument(additional)?;
                Ok(CanonicalValue::Unsigned(value))
            }
            1 => {
                let argument = self.read_argument(additional)?;
                if argument > i64::MAX as u64 {
                    return Err(CanonicalCborError::IntegerOutOfRange);
                }
                let value = i64::try_from(-1_i128 - i128::from(argument))
                    .map_err(|_| CanonicalCborError::IntegerOutOfRange)?;
                Ok(CanonicalValue::Negative(value))
            }
            2 | 3 => {
                let length = self.read_length(additional)?;
                let bytes = self.read_exact(length)?;
                if major == 2 {
                    Ok(CanonicalValue::Bytes(bytes.to_vec()))
                } else {
                    let text =
                        std::str::from_utf8(bytes).map_err(|_| CanonicalCborError::InvalidUtf8)?;
                    Ok(CanonicalValue::Text(text.to_owned()))
                }
            }
            4 => {
                let length = self.read_container_length(additional)?;
                let mut values = Vec::with_capacity(length);
                for _ in 0..length {
                    values.push(self.parse_value(depth + 1)?);
                }
                Ok(CanonicalValue::Array(values))
            }
            5 => {
                let length = self.read_container_length(additional)?;
                let mut previous_key: Option<Vec<u8>> = None;
                let mut entries = Vec::with_capacity(length);
                for _ in 0..length {
                    let key_start = self.position;
                    let key_value = self.parse_value(depth + 1)?;
                    let key = self.input[key_start..self.position].to_vec();
                    if let Some(previous) = &previous_key {
                        match previous.as_slice().cmp(&key) {
                            std::cmp::Ordering::Equal => {
                                return Err(CanonicalCborError::DuplicateMapKey);
                            }
                            std::cmp::Ordering::Greater => {
                                return Err(CanonicalCborError::MapKeyOrder);
                            }
                            std::cmp::Ordering::Less => {}
                        }
                    }
                    previous_key = Some(key);
                    let value = self.parse_value(depth + 1)?;
                    entries.push((key_value, value));
                }
                Ok(CanonicalValue::Map(entries))
            }
            6 => Err(CanonicalCborError::TagNotAllowed),
            7 => match additional {
                20 => Ok(CanonicalValue::Bool(false)),
                21 => Ok(CanonicalValue::Bool(true)),
                22 => Ok(CanonicalValue::Null),
                25..=27 => Err(CanonicalCborError::FloatingPointNotAllowed),
                31 => Err(CanonicalCborError::IndefiniteLength),
                _ => Err(CanonicalCborError::SimpleValueNotAllowed),
            },
            _ => unreachable!("CBOR major type is three bits"),
        }
    }

    fn read_container_length(&mut self, additional: u8) -> Result<usize, CanonicalCborError> {
        let length = self.read_length(additional)?;
        if length > MAX_CONTAINER_ENTRIES {
            return Err(CanonicalCborError::ContainerTooLarge);
        }
        Ok(length)
    }

    fn read_length(&mut self, additional: u8) -> Result<usize, CanonicalCborError> {
        let length = self.read_argument(additional)?;
        let length = usize::try_from(length).map_err(|_| CanonicalCborError::LengthOutOfRange)?;
        if length > MAX_ENCODED_BYTES {
            return Err(CanonicalCborError::InputTooLarge);
        }
        Ok(length)
    }

    fn read_argument(&mut self, additional: u8) -> Result<u64, CanonicalCborError> {
        match additional {
            0..=23 => Ok(u64::from(additional)),
            24 => {
                let value = u64::from(self.read_byte()?);
                if value < 24 {
                    Err(CanonicalCborError::NonPreferredArgument)
                } else {
                    Ok(value)
                }
            }
            25 => {
                let value = u64::from(u16::from_be_bytes(self.read_array()?));
                if u8::try_from(value).is_ok() {
                    Err(CanonicalCborError::NonPreferredArgument)
                } else {
                    Ok(value)
                }
            }
            26 => {
                let value = u64::from(u32::from_be_bytes(self.read_array()?));
                if u16::try_from(value).is_ok() {
                    Err(CanonicalCborError::NonPreferredArgument)
                } else {
                    Ok(value)
                }
            }
            27 => {
                let value = u64::from_be_bytes(self.read_array()?);
                if u32::try_from(value).is_ok() {
                    Err(CanonicalCborError::NonPreferredArgument)
                } else {
                    Ok(value)
                }
            }
            28..=30 => Err(CanonicalCborError::ReservedAdditionalInformation),
            31 => Err(CanonicalCborError::IndefiniteLength),
            _ => unreachable!("additional information is five bits"),
        }
    }

    fn read_byte(&mut self) -> Result<u8, CanonicalCborError> {
        let value = *self
            .input
            .get(self.position)
            .ok_or(CanonicalCborError::UnexpectedEnd)?;
        self.position += 1;
        Ok(value)
    }

    fn read_exact(&mut self, length: usize) -> Result<&[u8], CanonicalCborError> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(CanonicalCborError::UnexpectedEnd)?;
        let bytes = self
            .input
            .get(self.position..end)
            .ok_or(CanonicalCborError::UnexpectedEnd)?;
        self.position = end;
        Ok(bytes)
    }

    fn read_array<const N: usize>(&mut self) -> Result<[u8; N], CanonicalCborError> {
        self.read_exact(N)?
            .try_into()
            .map_err(|_| CanonicalCborError::UnexpectedEnd)
    }
}
