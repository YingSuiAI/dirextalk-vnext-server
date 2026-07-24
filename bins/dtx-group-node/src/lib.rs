#![forbid(unsafe_code)]

//! Tenant-affine HTTP boundary for durable group policy and membership intents.
//!
//! This node deliberately stops at a durable `pending_commit` receipt. It does
//! not invent an MLS result: a later Sequencer adapter is the only component
//! allowed to turn that intent into a committed membership fact.

mod sequencer_key;

include!("shared.rs");
include!("router.rs");
include!("lifecycle_handlers.rs");
include!("mls_handlers.rs");
include!("responses.rs");
include!("body_codec.rs");
include!("auth.rs");
include!("domain_codec.rs");
include!("errors.rs");
