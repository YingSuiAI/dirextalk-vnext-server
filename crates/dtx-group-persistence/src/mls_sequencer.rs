//! Durable single-node MLS Commit Sequencer.
//!
//! This module deliberately treats MLS artifacts as opaque. It serializes one
//! commit per conversation head, binds device admission to an approved GM1
//! workflow or an existing identity's active controller, and requires the new
//! device to confirm the signed receipt before becoming routable.

// The source units below are deliberately included into one private module:
// types, transcript crypto, public command APIs, transaction writers, and
// receipt decoding each have a named owner while retaining private helper
// access and the original transaction/error surface.

include!("mls_sequencer/types_a.rs");
include!("mls_sequencer/crypto.rs");
include!("mls_sequencer/types_b.rs");
include!("mls_sequencer/api_submit.rs");
include!("mls_sequencer/api_receipt.rs");
include!("mls_sequencer/tx_submit_v3.rs");
include!("mls_sequencer/tx_submit.rs");
include!("mls_sequencer/authorize.rs");
include!("mls_sequencer/insert_intent.rs");
include!("mls_sequencer/confirm.rs");
include!("mls_sequencer/load.rs");
include!("mls_sequencer/receipt.rs");
include!("mls_sequencer/crypto_helpers.rs");
