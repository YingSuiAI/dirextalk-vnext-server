#![forbid(unsafe_code)]

//! Test-only security and failure-injection fixtures.
//!
//! Production crates must define and own their real ports. This crate provides
//! deterministic fakes and synthetic credentials for contract and recovery
//! tests; it must never be linked into a production binary.

mod agent;
mod aws;
mod canary;
mod deterministic;
mod fault;
mod kms;
mod mtls;

pub use agent::*;
pub use aws::*;
pub use canary::*;
pub use deterministic::*;
pub use fault::*;
pub use kms::*;
pub use mtls::*;
