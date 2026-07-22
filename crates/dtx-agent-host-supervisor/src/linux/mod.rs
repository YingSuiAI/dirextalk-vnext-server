//! Linux Host Supervisor adapters.
//!
//! Production constructors use only fixed absolute layout and executable
//! capabilities. Test-only constructors can prefix that layout with a
//! temporary root and inject a command runner.

#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

mod bootstrap;
mod command;
mod credential;
mod host_network;
mod journal;
mod layout;
mod process;

#[cfg(target_os = "linux")]
pub use bootstrap::{
    LinuxBootstrapCommand, LinuxMaterial, LinuxMaterialStore, LinuxPlanCapability,
    LinuxPrepareFootprint, derive_trust_digest,
};
#[cfg(target_os = "linux")]
pub use credential::LinuxCredentialArtifact;
#[cfg(target_os = "linux")]
pub use host_network::LinuxHostNetworkBoundary;
#[cfg(target_os = "linux")]
pub use journal::FileJournal;
#[cfg(target_os = "linux")]
pub use process::{
    LinuxProcessController, LinuxReconcileObservation, LinuxReconcileStatus, LinuxResourceLimits,
};
