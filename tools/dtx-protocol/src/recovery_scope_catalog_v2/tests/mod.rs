use ed25519_dalek::{Signature, VerifyingKey};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::path::PathBuf;

include!("fixtures.rs");
include!("schema.rs");
include!("openapi.rs");
include!("vector.rs");
include!("negative.rs");
