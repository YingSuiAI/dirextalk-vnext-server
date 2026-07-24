#![forbid(unsafe_code)]

//! Pure group-role authorization aggregate.
//!
//! Callers supply an already verified actor identity. Persistent command receipts,
//! signed device proofs, MLS epoch/head fencing, and storage transactions belong to
//! later integration layers and are deliberately not modeled here.

// Types, mutation methods, and rehydration validation share one private module so
// all canonical policy invariants retain their original access and signatures.

include!("policy/types.rs");
include!("policy/aggregate.rs");
include!("policy/validation.rs");
