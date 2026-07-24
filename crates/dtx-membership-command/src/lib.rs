#![forbid(unsafe_code)]

//! Pure, replay-safe membership-command coordination.
//!
//! This crate deliberately models neither MLS cryptography nor database I/O. It
//! retains the command, receipt, and Sequencer-query invariants that a durable
//! repository must preserve around those external boundaries.

// Semantic units are included into one private module to preserve exact private
// reducer visibility and canonical digest behavior while keeping files reviewable.

include!("membership/header.rs");
include!("membership/book.rs");
include!("membership/codec.rs");
