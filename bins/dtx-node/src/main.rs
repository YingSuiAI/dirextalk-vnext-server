#![forbid(unsafe_code)]

// Product Core composition is kept in semantic units so optional public
// content cannot leak into the default identity/group/mailbox process.
include!("node/bootstrap.rs");
include!("node/readiness.rs");
include!("node/config.rs");
include!("node/tests.rs");
