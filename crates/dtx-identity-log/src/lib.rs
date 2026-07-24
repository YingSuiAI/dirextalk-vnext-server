#![forbid(unsafe_code)]

//! Self-certifying identity and device-log primitives.
//!
//! This crate deliberately owns only canonical bytes, signatures, and the
//! in-memory authorization projection. HTTP admission, storage, recovery UI,
//! and directory discovery are separate boundaries.

use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt,
    str::FromStr,
};

use dtx_domain::{DeviceId, IdentityId};
use dtx_wire::{
    CanonicalEncode, CanonicalValue, Ed25519Signature, ProtocolVersion, SafeUint, Sha256Digest,
    SigningPublicKey, UtcMillis, WireVersion, decode_deterministic_cbor, encode_deterministic_cbor,
};
use ed25519_dalek::{Signature, VerifyingKey};

include!("constants_and_errors.rs");
include!("certificates.rs");
include!("events.rs");
include!("pages.rs");
include!("projection.rs");
include!("decoding.rs");

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
