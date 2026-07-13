#![forbid(unsafe_code)]

//! Multi-connector domain state machines.

mod binding;
mod connector;

pub use binding::*;
pub use connector::*;
