//! Group membership persistence split by semantic ownership.
//!
//! The included units intentionally remain one private Rust module so their
//! transaction helpers and error mapping retain the exact historical API and
//! lock ordering while each handwritten source stays reviewable.
include!("repository/header.rs");
include!("repository/api.rs");
include!("repository/queries.rs");
include!("repository/commands.rs");
include!("repository/load.rs");
include!("repository/persist.rs");
include!("repository/codec.rs");
