#![forbid(unsafe_code)]

//! Hardened remote identity-log resolution shared by federated services.

// Identity projections, verifier workflows, transport hardening, and tests are
// named separately but remain one private module to preserve exact helper access.

include!("federated/types.rs");
include!("federated/verifier.rs");
include!("federated/transport.rs");
include!("federated/tests.rs");
