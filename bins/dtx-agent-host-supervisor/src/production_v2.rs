//! Fixed bootstrap subprocess boundary.  This module deliberately owns no
//! filesystem layout; the following production unit supplies the derived plan
//! path after its no-follow staging proof.

use dtx_agent_host_supervisor::{
    BootstrapMaterialProvider, CatalogRelease, ConfigDigest, ConnectorLifecycleFacts,
    ConnectorLifecycleOperationId, FinalizedMaterialProof, FinalizedReceiptDigest, HandoffDigest,
    HostOperationId, LinuxMaterial, LinuxMaterialStore, LinuxPrepareFootprint,
    LinuxProcessController, MaterialDigest, PlanDigest, PortError, PortErrorKind,
    PrepareMaterialResult, PreparedMaterialProof, PreparedReceiptDigest, ProcessMutationId,
    ProcessObservation, ReleaseDigest, derive_trust_digest,
};
use dtx_connect_registry::AdapterKind;
use dtx_domain::{IdentityId, Revision};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use crate::wire_v2::{
    V2CodecError, V2Header, V2RequestFrame, decode_digest, reject_duplicate_json_keys,
};

const BASE64URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

pub fn digest_only(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

/// Fully owned request material after the secret handoff has been validated.
/// It intentionally exposes neither formatting traits nor secret accessors.
pub struct ValidatedBootstrapRequest {
    pub(crate) frame: V2RequestFrame,
}

// Handoff owns RawValue secrets.  It must never be serializable, printable,
// or expose accessors that could copy those values into ordinary memory.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Handoff<'a> {
    schema: &'a str,
    schema_version: u8,
    state: &'a str,
    operation_id: &'a str,
    manifest_digest: &'a str,
    target: &'a str,
    tenant_id: &'a str,
    host_id: &'a str,
    instance_id: &'a str,
    enrollment_request_id: &'a str,
    enrollment_intent_id: &'a str,
    generation: u64,
    spec_revision: u64,
    expires_at_millis: u64,
    enrollment_token: &'a serde_json::value::RawValue,
    mcp_bearer: &'a serde_json::value::RawValue,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Plan<'a> {
    schema: &'a str,
    schema_version: u8,
    state: &'a str,
    operation_id: &'a str,
    manifest_digest: &'a str,
    target: &'a str,
    connector_artifact: Artifact<'a>,
    host: PlanHost<'a>,
    connector: PlanConnector<'a>,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Artifact<'a> {
    version: &'a str,
    digest: &'a str,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_field_names, reason = "JSON contract names are exact")]
struct PlanHost<'a> {
    tenant_id: &'a str,
    host_id: &'a str,
    owner_id: &'a str,
    host_credential_id: &'a str,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PlanConnector<'a> {
    instance_id: &'a str,
    adapter_kind: &'a str,
    handoff_digest: &'a str,
    display_name: &'a str,
    generation: u64,
    spec_revision: u64,
    enrollment_request_id: &'a str,
    enrollment_intent_id: &'a str,
    installation_id: &'a str,
    agent_device_id: &'a str,
    binding_id: &'a str,
    expires_at_millis: u64,
    server_origin: &'a str,
    trust: Trust<'a>,
    runtime_profile: &'a str,
    remote_mcp: RemoteMcp<'a>,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Trust<'a> {
    enrollment_url: &'a str,
    enrollment_server_name: &'a str,
    enrollment_root_ca_sha256: &'a str,
    control_url: &'a str,
    control_server_name: &'a str,
    control_server_root_ca_sha256: &'a str,
    connector_issuer_root_ca_sha256: &'a str,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RemoteMcp<'a> {
    mcp_server_name: &'a str,
    mcp_url: &'a str,
    mcp_node_id: &'a str,
    max_concurrent_runs: u64,
    offline_policy: &'a str,
}

impl ValidatedBootstrapRequest {
    /// This is intentionally a pure boundary: all checks precede a runner,
    /// filesystem operation, or dispatcher side effect.
    pub fn parse(frame: V2RequestFrame) -> Result<Self, V2CodecError> {
        let material = frame
            .material
            .as_ref()
            .ok_or(V2CodecError::MissingMaterial)?;
        let plan_raw = material.plan_json();
        reject_duplicate_json_keys(plan_raw)?;
        reject_escaped_nonsecret_json(plan_raw)?;
        let mut plan_decoder = serde_json::Deserializer::from_slice(plan_raw);
        let plan =
            Plan::deserialize(&mut plan_decoder).map_err(|_| V2CodecError::InvalidMaterial)?;
        plan_decoder
            .end()
            .map_err(|_| V2CodecError::InvalidMaterial)?;
        validate_plan(&plan, &frame)?;
        let raw = material.handoff_json();
        reject_duplicate_json_keys(raw)?;
        let mut handoff_decoder = serde_json::Deserializer::from_slice(raw);
        let handoff = Handoff::deserialize(&mut handoff_decoder)
            .map_err(|_| V2CodecError::InvalidMaterial)?;
        handoff_decoder
            .end()
            .map_err(|_| V2CodecError::InvalidMaterial)?;
        if handoff.schema != "dirextalk.connector-bootstrap-handoff"
            || handoff.schema_version != 1
            || handoff.state != "ready"
            || !is_v7(handoff.operation_id)
            || !is_digest(handoff.manifest_digest)
            || !matches!(handoff.target, "linux-amd64" | "linux-arm64")
            || !positive(handoff.generation)
            || !positive(handoff.spec_revision)
            || !positive(handoff.expires_at_millis)
            || [
                handoff.tenant_id,
                handoff.host_id,
                handoff.instance_id,
                handoff.enrollment_request_id,
                handoff.enrollment_intent_id,
            ]
            .iter()
            .any(|id| !is_v7(id))
            || handoff.operation_id != frame.header.lifecycle_operation_id.to_string()
            || handoff.tenant_id != frame.header.tenant_id.to_string()
            || handoff.host_id != frame.header.host_id.to_string()
            || handoff.expires_at_millis != frame.header.expiry_millis
            || handoff.operation_id != plan.operation_id
            || handoff.manifest_digest != plan.manifest_digest
            || handoff.target != plan.target
            || handoff.tenant_id != plan.host.tenant_id
            || handoff.host_id != plan.host.host_id
            || handoff.instance_id != plan.connector.instance_id
            || handoff.enrollment_request_id != plan.connector.enrollment_request_id
            || handoff.enrollment_intent_id != plan.connector.enrollment_intent_id
            || handoff.generation != plan.connector.generation
            || handoff.spec_revision != plan.connector.spec_revision
            || handoff.expires_at_millis != plan.connector.expires_at_millis
            || digest_only(raw) != decode_digest(plan.connector.handoff_digest)?
        {
            return Err(V2CodecError::InvalidMaterial);
        }
        let mut enrollment_token = Zeroizing::new([0; 32]);
        let mut mcp_bearer = Zeroizing::new([0; 32]);
        if !decode_secret(handoff.enrollment_token.get(), &mut enrollment_token)
            || !decode_secret(handoff.mcp_bearer.get(), &mut mcp_bearer)
        {
            return Err(V2CodecError::InvalidMaterial);
        }
        Ok(Self { frame })
    }
}

fn validate_plan(plan: &Plan<'_>, frame: &V2RequestFrame) -> Result<(), V2CodecError> {
    let c = &plan.connector;
    let t = &c.trust;
    let m = &c.remote_mcp;
    let raw = frame
        .material
        .as_ref()
        .ok_or(V2CodecError::MissingMaterial)?
        .plan_json();
    if serde_json::to_vec(plan).map_err(|_| V2CodecError::InvalidMaterial)? != raw {
        return Err(V2CodecError::InvalidMaterial);
    }
    if plan.schema != "dirextalk.connector-bootstrap-plan"
        || plan.schema_version != 1
        || plan.state != "prepared"
        || !is_v7(plan.operation_id)
        || !is_digest(plan.manifest_digest)
        || !matches!(plan.target, "linux-amd64" | "linux-arm64")
        || !is_semver(plan.connector_artifact.version)
        || !is_digest(plan.connector_artifact.digest)
        || [
            plan.host.tenant_id,
            plan.host.host_id,
            plan.host.host_credential_id,
            c.instance_id,
            c.enrollment_request_id,
            c.enrollment_intent_id,
            c.installation_id,
            c.agent_device_id,
            c.binding_id,
        ]
        .iter()
        .any(|id| !is_v7(id))
        || !is_identity_id(plan.host.owner_id)
        || !is_digest(c.handoff_digest)
        || !valid_text(c.display_name, 128)
        || !positive(c.generation)
        || !positive(c.spec_revision)
        || !positive(c.expires_at_millis)
        || !valid_origin(c.server_origin)
        || !matches!(
            c.adapter_kind,
            "codex" | "openclaw_acp" | "eino" | "rig" | "claude_code" | "custom_acp" | "hermes_acp"
        )
        || !matches!(c.runtime_profile, "default" | "safe")
        || !valid_endpoint(t.enrollment_url, t.enrollment_server_name)
        || !is_digest(t.enrollment_root_ca_sha256)
        || !valid_endpoint(t.control_url, t.control_server_name)
        || !is_digest(t.control_server_root_ca_sha256)
        || !is_digest(t.connector_issuer_root_ca_sha256)
        || frame.header.enrollment_ca_sha256.as_deref() != Some(t.enrollment_root_ca_sha256)
        || frame.header.control_ca_sha256.as_deref() != Some(t.control_server_root_ca_sha256)
        || frame.header.issuer_ca_sha256.as_deref() != Some(t.connector_issuer_root_ca_sha256)
        || !valid_mcp_name(m.mcp_server_name)
        || !valid_mcp_url(m.mcp_url)
        || !is_v7(m.mcp_node_id)
        || m.max_concurrent_runs == 0
        || m.max_concurrent_runs > 4096
        || m.offline_policy != "queue"
        || plan.operation_id != frame.header.lifecycle_operation_id.to_string()
        || plan.host.tenant_id != frame.header.tenant_id.to_string()
        || plan.host.host_id != frame.header.host_id.to_string()
        || c.instance_id != frame.header.connector_id.to_string()
        || plan.target
            != match frame.header.platform_target {
                crate::wire_v2::PlatformTarget::LinuxAmd64 => "linux-amd64",
                crate::wire_v2::PlatformTarget::LinuxArm64 => "linux-arm64",
            }
        || c.expires_at_millis != frame.header.expiry_millis
        || c.adapter_kind != adapter_name(frame.header.adapter)
        || plan.connector_artifact.digest != frame.header.approved_release_sha256
        || digest_only(raw) != decode_digest(&frame.header.plan_sha256)?
    {
        return Err(V2CodecError::InvalidMaterial);
    }
    // Go's encoding/json escapes these while serde_json does not.  Refuse
    // them rather than creating a durable digest identity that differs across
    // the two implementations.
    if all_plan_strings(plan)
        .iter()
        .any(|value| value.contains(['<', '>', '&', '\u{2028}', '\u{2029}']))
    {
        return Err(V2CodecError::InvalidMaterial);
    }
    Ok(())
}

fn adapter_name(adapter: crate::wire_v2::AdapterV2) -> &'static str {
    match adapter {
        crate::wire_v2::AdapterV2::Codex => "codex",
        crate::wire_v2::AdapterV2::OpenclawAcp => "openclaw_acp",
        crate::wire_v2::AdapterV2::Eino => "eino",
        crate::wire_v2::AdapterV2::Rig => "rig",
        crate::wire_v2::AdapterV2::ClaudeCode => "claude_code",
        crate::wire_v2::AdapterV2::CustomAcp => "custom_acp",
        crate::wire_v2::AdapterV2::HermesAcp => "hermes_acp",
    }
}

fn adapter_kind(adapter: crate::wire_v2::AdapterV2) -> AdapterKind {
    match adapter {
        crate::wire_v2::AdapterV2::Codex => AdapterKind::Codex,
        crate::wire_v2::AdapterV2::OpenclawAcp => AdapterKind::OpenClawAcp,
        crate::wire_v2::AdapterV2::Eino => AdapterKind::Eino,
        crate::wire_v2::AdapterV2::Rig => AdapterKind::Rig,
        crate::wire_v2::AdapterV2::ClaudeCode => AdapterKind::ClaudeCode,
        crate::wire_v2::AdapterV2::CustomAcp => AdapterKind::CustomAcp,
        crate::wire_v2::AdapterV2::HermesAcp => AdapterKind::HermesAcp,
    }
}

pub(crate) fn lifecycle_facts(
    frame: &V2RequestFrame,
) -> Result<ConnectorLifecycleFacts, V2CodecError> {
    lifecycle_facts_header(&frame.header)
}

pub(crate) fn lifecycle_facts_header(
    header: &V2Header,
) -> Result<ConnectorLifecycleFacts, V2CodecError> {
    let config = header
        .config_sha256
        .as_deref()
        .ok_or(V2CodecError::MissingMaterial)?;
    let enrollment = header
        .enrollment_ca_sha256
        .as_deref()
        .ok_or(V2CodecError::MissingMaterial)?;
    let control = header
        .control_ca_sha256
        .as_deref()
        .ok_or(V2CodecError::MissingMaterial)?;
    let issuer = header
        .issuer_ca_sha256
        .as_deref()
        .ok_or(V2CodecError::MissingMaterial)?;
    let platform = match header.platform_target {
        crate::wire_v2::PlatformTarget::LinuxAmd64 => {
            dtx_agent_host_supervisor::PlatformTarget::LinuxAmd64
        }
        crate::wire_v2::PlatformTarget::LinuxArm64 => {
            dtx_agent_host_supervisor::PlatformTarget::LinuxArm64
        }
    };
    Ok(ConnectorLifecycleFacts::new(
        ConnectorLifecycleOperationId::from_request_id(header.lifecycle_operation_id),
        platform,
        adapter_kind(header.adapter),
        ReleaseDigest::from_bytes(decode_digest(&header.approved_release_sha256)?),
        header.tenant_id,
        header.host_id,
        header.connector_id,
        header.expiry_millis,
        PlanDigest::from_bytes(decode_digest(&header.plan_sha256)?),
        HandoffDigest::from_bytes(decode_digest(&header.handoff_sha256)?),
        ConfigDigest::from_bytes(decode_digest(config)?),
        derive_trust_digest(
            decode_digest(enrollment)?,
            decode_digest(control)?,
            decode_digest(issuer)?,
        ),
        MaterialDigest::from_bytes(decode_digest(&header.lifecycle_material_sha256)?),
    ))
}

/// Bin-local adapter that owns request bytes only until the fixed Connector
/// subprocess has claimed them. It exposes no material outside this module.
pub struct LinuxBootstrapProvider {
    request: ValidatedBootstrapRequest,
    now_millis: u64,
    process: LinuxProcessController,
}

impl LinuxBootstrapProvider {
    pub fn new(request: ValidatedBootstrapRequest, now_millis: u64) -> Self {
        Self {
            request,
            now_millis,
            process: LinuxProcessController::new(),
        }
    }

    fn request_matches(&self, facts: &ConnectorLifecycleFacts) -> Result<(), PortError> {
        (lifecycle_facts(&self.request.frame).ok().as_ref() == Some(facts))
            .then_some(())
            .ok_or_else(|| PortError::new(PortErrorKind::InvalidArtifact))
    }

    /// Re-enters the Connector's exact-claim recovery through the same closed
    /// Host ensure, material, descriptor, and adoption capabilities as
    /// prepare. The Connector owns the durable claim/pending decision and
    /// rejects creation of a new expired claim.
    fn recover_expired_prepare(
        &mut self,
        operation_id: HostOperationId,
        facts: ConnectorLifecycleFacts,
        release: CatalogRelease,
        store: &LinuxMaterialStore,
    ) -> Result<PrepareMaterialResult, PortError> {
        self.complete_prepare(operation_id, facts, release, store)
    }

    fn complete_prepare(
        &mut self,
        operation_id: HostOperationId,
        facts: ConnectorLifecycleFacts,
        release: CatalogRelease,
        store: &LinuxMaterialStore,
    ) -> Result<PrepareMaterialResult, PortError> {
        if self.process.ensure_lifecycle(
            ProcessMutationId::requested(operation_id),
            facts,
            release,
        )? != ProcessObservation::Stopped
        {
            return Err(PortError::new(PortErrorKind::Conflict));
        }
        let material = self
            .request
            .frame
            .material
            .as_ref()
            .ok_or_else(|| PortError::new(PortErrorKind::InvalidArtifact))?;
        let plan = store.stage(
            LinuxMaterial {
                config: material.config_toml(),
                enrollment_root_ca: material.enrollment_ca_pem(),
                control_server_root_ca: material.control_ca_pem(),
                connector_issuer_root_ca: material.issuer_ca_pem(),
                plan: material.plan_json(),
            },
            facts.config_digest(),
            facts.trust_digest(),
            facts.plan_digest(),
        )?;
        let output = store
            .bootstrap_command(release, &plan)?
            .run(false, Zeroizing::new(material.handoff_json().to_vec()))?;
        let receipt = store.read_receipt(false)?;
        if output.as_slice() != receipt.as_slice() {
            return Err(PortError::new(PortErrorKind::InvalidArtifact));
        }
        let proof = bind_prepared_receipt(&self.request.frame, &receipt)
            .map_err(|_| PortError::new(PortErrorKind::InvalidArtifact))?;
        let revision = Revision::new(proof.credential_revision)
            .map_err(|_| PortError::new(PortErrorKind::InvalidArtifact))?;
        let credentials = store.adopted_credential_facts(proof.credential_generation, revision)?;
        self.process.adopt_lifecycle_bootstrap_artifacts(
            ProcessMutationId::requested(operation_id),
            facts,
            credentials.credential_ref,
            credentials.mcp_bearer_ref,
        )?;
        if self.process.observe_lifecycle(facts)? != ProcessObservation::Stopped {
            return Err(PortError::new(PortErrorKind::Conflict));
        }
        Ok(PrepareMaterialResult::Prepared(PreparedMaterialProof {
            facts,
            prepared_receipt: PreparedReceiptDigest::from_bytes(proof.prepared_receipt_sha256),
            credentials,
            observation: ProcessObservation::Stopped,
        }))
    }
}

impl BootstrapMaterialProvider for LinuxBootstrapProvider {
    fn prepare(
        &mut self,
        operation_id: HostOperationId,
        facts: ConnectorLifecycleFacts,
        release: CatalogRelease,
    ) -> Result<PrepareMaterialResult, PortError> {
        self.request_matches(&facts)?;
        let store = LinuxMaterialStore::for_lifecycle(facts, operation_id);
        // Expiry recovery deliberately scans the fixed footprint before even a
        // process observation.  An expired request may never create a fresh
        // claim: absence is terminal, ambiguity is rejected, and a present
        // footprint must prove the Connector's exact durable claim below.
        if facts.expiry_millis() <= self.now_millis {
            match expired_prepare_route(store.inspect_prepare_footprint()?)? {
                ExpiredPrepareRoute::Unclaimed => {
                    return Ok(PrepareMaterialResult::ExpiredUnclaimed);
                }
                ExpiredPrepareRoute::RecoverClaim => {
                    return self.recover_expired_prepare(operation_id, facts, release, &store);
                }
            }
        }
        self.complete_prepare(operation_id, facts, release, &store)
    }

    fn finalize(
        &mut self,
        operation_id: HostOperationId,
        facts: ConnectorLifecycleFacts,
        prepared_receipt: PreparedReceiptDigest,
        release: CatalogRelease,
    ) -> Result<FinalizedMaterialProof, PortError> {
        self.request_matches(&facts)?;
        if self.process.observe_lifecycle(facts)? != ProcessObservation::Running {
            return Err(PortError::new(PortErrorKind::Conflict));
        }
        let material = self
            .request
            .frame
            .material
            .as_ref()
            .ok_or_else(|| PortError::new(PortErrorKind::InvalidArtifact))?;
        let store = LinuxMaterialStore::for_lifecycle(facts, operation_id);
        let plan = store.stage_finalize_plan(
            material.plan_json(),
            facts.config_digest(),
            facts.trust_digest(),
            facts.plan_digest(),
        )?;
        let output = store
            .bootstrap_command(release, &plan)?
            .run(true, Zeroizing::new(material.handoff_json().to_vec()))?;
        let prepared = store.read_receipt(false)?;
        let finalized = store.read_receipt(true)?;
        if output.as_slice() != finalized.as_slice() {
            return Err(PortError::new(PortErrorKind::InvalidArtifact));
        }
        let proof = bind_finalized_receipt(&self.request.frame, &prepared, &finalized)
            .map_err(|_| PortError::new(PortErrorKind::InvalidArtifact))?;
        if PreparedReceiptDigest::from_bytes(digest_only(&prepared)) != prepared_receipt {
            return Err(PortError::new(PortErrorKind::InvalidArtifact));
        }
        let state = bind_prepared_receipt(&self.request.frame, &prepared)
            .map_err(|_| PortError::new(PortErrorKind::InvalidArtifact))?;
        let credentials = store.adopted_credential_facts(
            state.credential_generation,
            Revision::new(state.credential_revision)
                .map_err(|_| PortError::new(PortErrorKind::InvalidArtifact))?,
        )?;
        Ok(FinalizedMaterialProof {
            facts,
            prepared_receipt,
            finalized_receipt: FinalizedReceiptDigest::from_bytes(proof.finalized_receipt_sha256),
            credentials,
            observation: ProcessObservation::Running,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ExpiredPrepareRoute {
    Unclaimed,
    RecoverClaim,
}

fn expired_prepare_route(
    footprint: LinuxPrepareFootprint,
) -> Result<ExpiredPrepareRoute, PortError> {
    match footprint {
        LinuxPrepareFootprint::AllAbsent => Ok(ExpiredPrepareRoute::Unclaimed),
        LinuxPrepareFootprint::Present => Ok(ExpiredPrepareRoute::RecoverClaim),
        LinuxPrepareFootprint::Ambiguous => Err(PortError::new(PortErrorKind::InvalidArtifact)),
    }
}

fn all_plan_strings<'a>(p: &'a Plan<'a>) -> [&'a str; 33] {
    let c = &p.connector;
    let t = &c.trust;
    let m = &c.remote_mcp;
    [
        p.schema,
        p.operation_id,
        p.manifest_digest,
        p.target,
        p.connector_artifact.version,
        p.connector_artifact.digest,
        p.host.tenant_id,
        p.host.host_id,
        p.host.owner_id,
        p.host.host_credential_id,
        c.instance_id,
        c.adapter_kind,
        c.handoff_digest,
        c.display_name,
        c.enrollment_request_id,
        c.enrollment_intent_id,
        c.installation_id,
        c.agent_device_id,
        c.binding_id,
        c.server_origin,
        c.runtime_profile,
        t.enrollment_url,
        t.enrollment_server_name,
        t.enrollment_root_ca_sha256,
        t.control_url,
        t.control_server_name,
        t.control_server_root_ca_sha256,
        t.connector_issuer_root_ca_sha256,
        m.mcp_server_name,
        m.mcp_url,
        m.mcp_node_id,
        m.offline_policy,
        "",
    ]
}

/// Go's `encoding/json` and serde agree on accepted plan text only when the
/// borrowed non-secret projection contains no JSON escapes.  Keep this
/// deliberately fail-closed subset until these fields can be owned as a
/// zero-copy-compatible type without changing the Connector contract.
fn reject_escaped_nonsecret_json(raw: &[u8]) -> Result<(), V2CodecError> {
    if raw.contains(&b'\\') {
        Err(V2CodecError::InvalidMaterial)
    } else {
        Ok(())
    }
}
fn valid_text(v: &str, max: usize) -> bool {
    !v.is_empty() && v.len() <= max
}
fn is_semver(v: &str) -> bool {
    let (without_build, build) = match v.split_once('+') {
        Some((head, tail)) if !tail.contains('+') => (head, Some(tail)),
        Some(_) => return false,
        None => (v, None),
    };
    let (main, prerelease) = match without_build.split_once('-') {
        Some((head, tail)) => (head, Some(tail)),
        None => (without_build, None),
    };
    main.split('.').count() == 3
        && main.split('.').all(|x| {
            !x.is_empty()
                && (x == "0" || (!x.starts_with('0') && x.bytes().all(|b| b.is_ascii_digit())))
        })
        && [prerelease, build].into_iter().flatten().all(|suffix| {
            !suffix.is_empty()
                && suffix.split('.').all(|part| {
                    !part.is_empty()
                        && part
                            .bytes()
                            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                })
        })
}
fn dns(v: &str) -> bool {
    !v.is_empty()
        && v.len() <= 253
        && v.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-')
        && v.split('.').all(|part| {
            !part.is_empty() && part.len() <= 63 && !part.starts_with('-') && !part.ends_with('-')
        })
}
fn https_parts(v: &str) -> Option<(&str, &str)> {
    let rest = v.strip_prefix("https://")?;
    if rest.contains(['@', '#', '?']) {
        return None;
    }
    let slash = rest.find('/');
    let (host, path) = slash.map_or((rest, ""), |index| (&rest[..index], &rest[index..]));
    if host.is_empty() || host.contains(':') || !dns(host) {
        return None;
    }
    Some((host, path))
}
fn valid_origin(v: &str) -> bool {
    matches!(https_parts(v), Some((_, "")))
}
fn valid_endpoint(v: &str, name: &str) -> bool {
    matches!(
        https_endpoint_parts(v),
        Some((host, "" | "/"))
            if host == name && name == name.trim() && dns(name)
    )
}
fn valid_mcp_url(v: &str) -> bool {
    matches!(https_parts(v), Some((_, "/mcp")))
}

fn https_endpoint_parts(v: &str) -> Option<(&str, &str)> {
    let rest = v.strip_prefix("https://")?;
    if rest.contains(['@', '#', '?']) {
        return None;
    }
    let slash = rest.find('/');
    let (authority, path) = slash.map_or((rest, ""), |index| (&rest[..index], &rest[index..]));
    let (host, port) = authority
        .split_once(':')
        .map_or((authority, None), |(host, port)| (host, Some(port)));
    if host.is_empty() || !dns(host) {
        return None;
    }
    if let Some(port) = port {
        if port.is_empty()
            || port == "443"
            || port.starts_with('0')
            || !port.bytes().all(|byte| byte.is_ascii_digit())
            || port.parse::<u16>().ok().is_none()
        {
            return None;
        }
    }
    Some((host, path))
}

fn valid_mcp_name(v: &str) -> bool {
    !v.is_empty()
        && v.len() <= 64
        && (v.as_bytes()[0].is_ascii_lowercase() || v.as_bytes()[0].is_ascii_digit())
        && v.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
}

/// Hashes the exact Go `encoding/json` struct encoding after validation.  The
/// unsupported escape-sensitive codepoints were rejected above, so the two
/// encoders have one accepted representation.
fn canonical_plan_digest(plan: &Plan<'_>) -> Result<[u8; 32], V2CodecError> {
    let encoded = serde_json::to_vec(plan).map_err(|_| V2CodecError::InvalidMaterial)?;
    Ok(digest_only(&encoded))
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PreparedReceipt<'a> {
    schema: &'a str,
    schema_version: u8,
    state: &'a str,
    plan_digest: &'a str,
    operation_id: &'a str,
    manifest_digest: &'a str,
    target: &'a str,
    connector_artifact_version: &'a str,
    connector_artifact_digest: &'a str,
    tenant_id: &'a str,
    host_id: &'a str,
    owner_id: &'a str,
    host_credential_id: &'a str,
    instance_id: &'a str,
    adapter_kind: &'a str,
    handoff_digest: &'a str,
    generation: u64,
    spec_revision: u64,
    enrollment_request_id: &'a str,
    enrollment_intent_id: &'a str,
    installation_id: &'a str,
    agent_device_id: &'a str,
    binding_id: &'a str,
    credential_id: &'a str,
    credential_generation: u64,
    credential_revision: u64,
    leaf_fingerprint_sha256: &'a str,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct FinalizedReceipt<'a> {
    schema: &'a str,
    schema_version: u8,
    state: &'a str,
    prepared_receipt_sha256: &'a str,
}

/// Sanitized identity proof; it intentionally contains no secret or raw receipt bytes.
pub struct PreparedReceiptProof {
    pub prepared_receipt_sha256: [u8; 32],
    pub credential_generation: u64,
    pub credential_revision: u64,
}

fn bind_prepared_receipt(
    frame: &V2RequestFrame,
    receipt: &[u8],
) -> Result<PreparedReceiptProof, V2CodecError> {
    reject_duplicate_json_keys(receipt)?;
    let mut decoder = serde_json::Deserializer::from_slice(receipt);
    let r =
        PreparedReceipt::deserialize(&mut decoder).map_err(|_| V2CodecError::InvalidMaterial)?;
    decoder.end().map_err(|_| V2CodecError::InvalidMaterial)?;
    // Connector persists the exact encoding/json struct result; accepting an
    // equivalent JSON spelling would create a second receipt identity.
    if serde_json::to_vec(&r).map_err(|_| V2CodecError::InvalidMaterial)? != receipt {
        return Err(V2CodecError::InvalidMaterial);
    }
    // Reconstruct plan to ensure both parse and canonical digest are bound.
    let raw = frame
        .material
        .as_ref()
        .ok_or(V2CodecError::MissingMaterial)?
        .plan_json();
    reject_escaped_nonsecret_json(raw)?;
    let mut d = serde_json::Deserializer::from_slice(raw);
    let plan = Plan::deserialize(&mut d).map_err(|_| V2CodecError::InvalidMaterial)?;
    d.end().map_err(|_| V2CodecError::InvalidMaterial)?;
    validate_plan(&plan, frame)?;
    let pd = canonical_plan_digest(&plan)?;
    if r.schema != "dirextalk.connector-bootstrap-receipt"
        || r.schema_version != 1
        || r.state != "prepared"
        || decode_digest(r.plan_digest)? != pd
        || r.operation_id != plan.operation_id
        || r.manifest_digest != plan.manifest_digest
        || r.target != plan.target
        || r.connector_artifact_version != plan.connector_artifact.version
        || r.connector_artifact_digest != plan.connector_artifact.digest
        || r.tenant_id != plan.host.tenant_id
        || r.host_id != plan.host.host_id
        || r.owner_id != plan.host.owner_id
        || r.host_credential_id != plan.host.host_credential_id
        || r.instance_id != plan.connector.instance_id
        || r.adapter_kind != plan.connector.adapter_kind
        || r.handoff_digest != plan.connector.handoff_digest
        || r.generation != plan.connector.generation
        || r.spec_revision != plan.connector.spec_revision
        || r.enrollment_request_id != plan.connector.enrollment_request_id
        || r.enrollment_intent_id != plan.connector.enrollment_intent_id
        || r.installation_id != plan.connector.installation_id
        || r.agent_device_id != plan.connector.agent_device_id
        || r.binding_id != plan.connector.binding_id
        || !is_v7(r.credential_id)
        || !positive(r.credential_generation)
        || !positive(r.credential_revision)
        || r.credential_generation != plan.connector.generation
        || r.credential_revision != plan.connector.spec_revision
        || !is_digest(r.leaf_fingerprint_sha256)
    {
        return Err(V2CodecError::InvalidMaterial);
    }
    Ok(PreparedReceiptProof {
        prepared_receipt_sha256: digest_only(receipt),
        credential_generation: r.credential_generation,
        credential_revision: r.credential_revision,
    })
}

pub struct FinalizedReceiptProof {
    pub finalized_receipt_sha256: [u8; 32],
}

fn bind_finalized_receipt(
    frame: &V2RequestFrame,
    prepared: &[u8],
    finalized: &[u8],
) -> Result<FinalizedReceiptProof, V2CodecError> {
    let _ = bind_prepared_receipt(frame, prepared)?;
    if frame
        .header
        .prepared_receipt_sha256
        .as_deref()
        .and_then(|value| decode_digest(value).ok())
        != Some(digest_only(prepared))
    {
        return Err(V2CodecError::InvalidMaterial);
    }
    reject_duplicate_json_keys(finalized)?;
    let mut d = serde_json::Deserializer::from_slice(finalized);
    let r = FinalizedReceipt::deserialize(&mut d).map_err(|_| V2CodecError::InvalidMaterial)?;
    d.end().map_err(|_| V2CodecError::InvalidMaterial)?;
    if serde_json::to_vec(&r).map_err(|_| V2CodecError::InvalidMaterial)? != finalized {
        return Err(V2CodecError::InvalidMaterial);
    }
    if r.schema != "dirextalk.connector-bootstrap-finalized-receipt"
        || r.schema_version != 1
        || r.state != "finalized"
        || decode_digest(r.prepared_receipt_sha256)? != digest_only(prepared)
    {
        return Err(V2CodecError::InvalidMaterial);
    }
    Ok(FinalizedReceiptProof {
        finalized_receipt_sha256: digest_only(finalized),
    })
}

fn positive(value: u64) -> bool {
    value > 0 && value <= 9_007_199_254_740_991
}
fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || matches!(b, b'a'..=b'f'))
}
fn is_v7(value: &str) -> bool {
    let b = value.as_bytes();
    b.len() == 36
        && b[14] == b'7'
        && matches!(b[19], b'8'..=b'b')
        && [8, 13, 18, 23].iter().all(|&i| b[i] == b'-')
        && b.iter().enumerate().all(|(i, c)| {
            matches!(i, 8 | 13 | 18 | 23) || c.is_ascii_digit() || matches!(c, b'a'..=b'f')
        })
}

fn is_identity_id(value: &str) -> bool {
    value.parse::<IdentityId>().is_ok()
}

fn decode_secret(raw: &str, output: &mut [u8; 32]) -> bool {
    output.fill(0);
    // RawValue includes the JSON quotes. A canonical secret has no escapes.
    let bytes = raw.as_bytes();
    if bytes.len() != 45 || bytes[0] != b'"' || bytes[44] != b'"' {
        return false;
    }
    let mut decoded = Zeroizing::new([0_u8; 32]);
    for group in 0..10 {
        let mut value = 0_u32;
        for byte in &bytes[1 + group * 4..=(group + 1) * 4] {
            let Some(index) = BASE64URL.iter().position(|candidate| candidate == byte) else {
                return false;
            };
            value = (value << 6) | u32::try_from(index).expect("base64 index fits");
        }
        let packed = value.to_be_bytes();
        decoded[group * 3..group * 3 + 3].copy_from_slice(&packed[1..]);
    }
    let mut tail = 0_u16;
    for byte in &bytes[41..44] {
        let Some(index) = BASE64URL.iter().position(|candidate| candidate == byte) else {
            return false;
        };
        tail = (tail << 6) | u16::try_from(index).expect("base64 index fits");
    }
    // A 32-byte RawURL value has 43 sextets: only the final two low bits are
    // unused.  The canonical re-encoding below is kept as a second boundary.
    if tail & 0x03 != 0 {
        return false;
    }
    let tail_bytes = (tail >> 2).to_be_bytes();
    decoded[30..].copy_from_slice(&tail_bytes);
    // Re-encode without allocating a secret String; this rejects non-zero
    // unused bits and any otherwise equivalent spelling.
    let mut canonical = Zeroizing::new([0_u8; 43]);
    for group in 0..10 {
        let value = (u32::from(decoded[group * 3]) << 16)
            | (u32::from(decoded[group * 3 + 1]) << 8)
            | u32::from(decoded[group * 3 + 2]);
        for offset in 0..4 {
            canonical[group * 4 + offset] =
                BASE64URL[((value >> (18 - offset * 6)) & 0x3f) as usize];
        }
    }
    let value = (u32::from(decoded[30]) << 16) | (u32::from(decoded[31]) << 8);
    for offset in 0..3 {
        canonical[40 + offset] = BASE64URL[((value >> (18 - offset * 6)) & 0x3f) as usize];
    }
    if canonical.as_slice() != &bytes[1..44] {
        return false;
    }
    output.copy_from_slice(decoded.as_slice());
    true
}

#[cfg(test)]
mod tests {
    use std::fmt::Write as _;

    use super::*;
    use crate::wire_v2::{
        AdapterV2, BootstrapMaterialV1, PROTOCOL_V2, PlatformTarget, V2Header, V2Operation,
    };
    use dtx_domain::{ConnectorId, HostId, RequestId, TenantId};

    const TENANT: &str = "0197f1f0-0000-7000-8000-000000000001";
    const HOST: &str = "0197f1f0-0000-7000-8000-000000000002";
    const OWNER_ID: &str = "dtxi1eci4tbb6kk5wk4vwv5ckekifwqtxy7bdd5vbmd7vac45r5xwu4la";
    const CONNECTOR: &str = "0197f1f0-0000-7000-8000-000000000003";
    const OPERATION: &str = "0197f1f0-0000-7000-8000-000000000005";
    const OTHER: &str = "0197f1f0-0000-7000-8000-000000000006";
    // Captured from an independent standard-library Go encoding/json program
    // using the Connector e731849 field order/types; neither value is derived
    // from serde at test runtime.
    const GO_PLAN_CANONICAL_JSON: &[u8] = br#"{"schema":"dirextalk.connector-bootstrap-plan","schema_version":1,"state":"prepared","operation_id":"0197f1f0-0000-7000-8000-000000000005","manifest_digest":"05b3abf2579a5eb66403cd78be557fd860633a1fe2103c7642030defe32c657f","target":"linux-amd64","connector_artifact":{"version":"1.2.3-alpha.1+build-1","digest":"a4d451ec23463726f72c43d64c710968f6b602cd653b4de8adee1b556240a829"},"host":{"tenant_id":"0197f1f0-0000-7000-8000-000000000001","host_id":"0197f1f0-0000-7000-8000-000000000002","owner_id":"dtxi1eci4tbb6kk5wk4vwv5ckekifwqtxy7bdd5vbmd7vac45r5xwu4la","host_credential_id":"0197f1f0-0000-7000-8000-000000000009"},"connector":{"instance_id":"0197f1f0-0000-7000-8000-000000000003","adapter_kind":"codex","handoff_digest":"c21ed50aa964770b16d098c18f1845d4fd75a0eccda9c3cd791d9a86840902d3","display_name":"Connector","generation":1,"spec_revision":1,"enrollment_request_id":"0197f1f0-0000-7000-8000-000000000006","enrollment_intent_id":"0197f1f0-0000-7000-8000-000000000007","installation_id":"0197f1f0-0000-7000-8000-00000000000a","agent_device_id":"0197f1f0-0000-7000-8000-00000000000b","binding_id":"0197f1f0-0000-7000-8000-00000000000c","expires_at_millis":4000000000,"server_origin":"https://server.example","trust":{"enrollment_url":"https://enroll.example/","enrollment_server_name":"enroll.example","enrollment_root_ca_sha256":"2791bd4394efbf10623f3cd301dc57f37ff18ff2a806b2c013403e85bc62c530","control_url":"https://control.example","control_server_name":"control.example","control_server_root_ca_sha256":"0fcd568a5cb9bdb4677b69354b11ee415af8f784519cff3da49a26f84eaee7f2","connector_issuer_root_ca_sha256":"535c6f8eb511f5d966a1b0725df92ebf27514faba945cbbd698e23ac72c41757"},"runtime_profile":"safe","remote_mcp":{"mcp_server_name":"mcp_1","mcp_url":"https://mcp.example/mcp","mcp_node_id":"0197f1f0-0000-7000-8000-00000000000d","max_concurrent_runs":1,"offline_policy":"queue"}}}"#;
    const GO_PLAN_CANONICAL_SHA256: &str =
        "792b519bcd3f7a489a1ce57d2cf9a0948565e267935568ad70b8537abff1071e";
    const SHARED_CANONICAL_PLAN: &str =
        include_str!("../../../test-vectors/connector-bootstrap-v1/canonical-plan.json");
    const SHARED_INVALID_FIELDS: &str =
        include_str!("../../../test-vectors/connector-bootstrap-v1/invalid-fields.json");
    const CREDENTIAL_ID: &str = "0197f1f0-0000-7000-8000-000000000010";

    fn hex(bytes: &[u8]) -> String {
        let mut value = String::with_capacity(64);
        for byte in Sha256::digest(bytes) {
            let _ = write!(value, "{byte:02x}");
        }
        value
    }
    fn uuid<T: std::str::FromStr>(value: &str) -> T {
        value.parse().ok().expect("uuidv7")
    }
    fn fixture() -> V2RequestFrame {
        let handoff = format!(
            r#"{{"schema":"dirextalk.connector-bootstrap-handoff","schema_version":1,"state":"ready","operation_id":"{OPERATION}","manifest_digest":"{}","target":"linux-amd64","tenant_id":"{TENANT}","host_id":"{HOST}","instance_id":"{CONNECTOR}","enrollment_request_id":"{OTHER}","enrollment_intent_id":"0197f1f0-0000-7000-8000-000000000007","generation":1,"spec_revision":1,"expires_at_millis":4000000000,"enrollment_token":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","mcp_bearer":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}}"#,
            hex(b"manifest")
        );
        let enrollment = hex(b"enrollment");
        let control = hex(b"control");
        let issuer = hex(b"issuer");
        let plan = format!(
            r#"{{"schema":"dirextalk.connector-bootstrap-plan","schema_version":1,"state":"prepared","operation_id":"{OPERATION}","manifest_digest":"{}","target":"linux-amd64","connector_artifact":{{"version":"1.2.3-alpha.1+build-1","digest":"{}"}},"host":{{"tenant_id":"{TENANT}","host_id":"{HOST}","owner_id":"{OWNER_ID}","host_credential_id":"0197f1f0-0000-7000-8000-000000000009"}},"connector":{{"instance_id":"{CONNECTOR}","adapter_kind":"codex","handoff_digest":"{}","display_name":"Connector","generation":1,"spec_revision":1,"enrollment_request_id":"{OTHER}","enrollment_intent_id":"0197f1f0-0000-7000-8000-000000000007","installation_id":"0197f1f0-0000-7000-8000-00000000000a","agent_device_id":"0197f1f0-0000-7000-8000-00000000000b","binding_id":"0197f1f0-0000-7000-8000-00000000000c","expires_at_millis":4000000000,"server_origin":"https://server.example","trust":{{"enrollment_url":"https://enroll.example/","enrollment_server_name":"enroll.example","enrollment_root_ca_sha256":"{enrollment}","control_url":"https://control.example","control_server_name":"control.example","control_server_root_ca_sha256":"{control}","connector_issuer_root_ca_sha256":"{issuer}"}},"runtime_profile":"safe","remote_mcp":{{"mcp_server_name":"mcp_1","mcp_url":"https://mcp.example/mcp","mcp_node_id":"0197f1f0-0000-7000-8000-00000000000d","max_concurrent_runs":1,"offline_policy":"queue"}}}}}}"#,
            hex(b"manifest"),
            hex(b"release"),
            hex(handoff.as_bytes())
        );
        let material = BootstrapMaterialV1::new(
            b"config".to_vec(),
            b"enrollment".to_vec(),
            b"control".to_vec(),
            b"issuer".to_vec(),
            plan.into_bytes(),
            handoff.into_bytes(),
        );
        let payload = material.encode().expect("material");
        let header = V2Header {
            protocol: PROTOCOL_V2.into(),
            tenant_id: uuid::<TenantId>(TENANT),
            host_id: uuid::<HostId>(HOST),
            host_operation_id: uuid::<RequestId>("0197f1f0-0000-7000-8000-000000000004"),
            expected_desired_revision: 1,
            expected_observed_revision: Some(1),
            connector_id: uuid::<ConnectorId>(CONNECTOR),
            adapter: AdapterV2::Codex,
            approved_release_sha256: hex(b"release"),
            lifecycle_operation_id: uuid::<RequestId>(OPERATION),
            platform_target: PlatformTarget::executing().expect("linux"),
            expiry_millis: 4_000_000_000,
            plan_sha256: hex(material.plan_json()),
            handoff_sha256: hex(material.handoff_json()),
            config_sha256: Some(hex(material.config_toml())),
            enrollment_ca_sha256: Some(enrollment),
            control_ca_sha256: Some(control),
            issuer_ca_sha256: Some(issuer),
            lifecycle_material_sha256: hex(&payload),
            payload_sha256: hex(&payload),
            prepared_receipt_sha256: None,
            operation: V2Operation::PrepareConnectorMaterial,
        };
        V2RequestFrame {
            header,
            material: Some(material),
        }
    }

    fn prepared_receipt(
        frame: &V2RequestFrame,
        credential_generation: u64,
        credential_revision: u64,
    ) -> Vec<u8> {
        format!(
            r#"{{"schema":"dirextalk.connector-bootstrap-receipt","schema_version":1,"state":"prepared","plan_digest":"{GO_PLAN_CANONICAL_SHA256}","operation_id":"{OPERATION}","manifest_digest":"{}","target":"linux-amd64","connector_artifact_version":"1.2.3-alpha.1+build-1","connector_artifact_digest":"{}","tenant_id":"{TENANT}","host_id":"{HOST}","owner_id":"{OWNER_ID}","host_credential_id":"0197f1f0-0000-7000-8000-000000000009","instance_id":"{CONNECTOR}","adapter_kind":"codex","handoff_digest":"{}","generation":1,"spec_revision":1,"enrollment_request_id":"{OTHER}","enrollment_intent_id":"0197f1f0-0000-7000-8000-000000000007","installation_id":"0197f1f0-0000-7000-8000-00000000000a","agent_device_id":"0197f1f0-0000-7000-8000-00000000000b","binding_id":"0197f1f0-0000-7000-8000-00000000000c","credential_id":"{CREDENTIAL_ID}","credential_generation":{credential_generation},"credential_revision":{credential_revision},"leaf_fingerprint_sha256":"{}"}}"#,
            hex(b"manifest"),
            hex(b"release"),
            hex(frame.material.as_ref().expect("material").handoff_json()),
            hex(b"leaf"),
        )
        .into_bytes()
    }

    fn replace_once(raw: &[u8], from: &str, to: &str) -> Vec<u8> {
        String::from_utf8(raw.to_vec())
            .expect("fixture is utf8")
            .replacen(from, to, 1)
            .into_bytes()
    }

    fn with_plan(mut frame: V2RequestFrame, plan: Vec<u8>) -> V2RequestFrame {
        let material = frame.material.take().expect("material");
        let material = BootstrapMaterialV1::new(
            material.config_toml().to_vec(),
            material.enrollment_ca_pem().to_vec(),
            material.control_ca_pem().to_vec(),
            material.issuer_ca_pem().to_vec(),
            plan,
            material.handoff_json().to_vec(),
        );
        frame.header.plan_sha256 = hex(material.plan_json());
        frame.material = Some(material);
        frame
    }

    fn fixture_with_explicit_trust_ports() -> V2RequestFrame {
        let frame = fixture();
        let plan = frame.material.as_ref().expect("material").plan_json();
        let plan = replace_once(
            plan,
            "https://enroll.example/",
            "https://enroll.example:8443/",
        );
        let plan = replace_once(
            &plan,
            "https://control.example",
            "https://control.example:9443",
        );
        with_plan(frame, plan)
    }

    #[test]
    fn secret_decoder_accepts_all_canonical_tail_classes_and_rejects_unused_bits() {
        for last in [0_u8, 1, 2, 3] {
            let mut value = [0_u8; 32];
            value[31] = last;
            let mut encoded = [b'A'; 43];
            for group in 0..10 {
                let word = (u32::from(value[group * 3]) << 16)
                    | (u32::from(value[group * 3 + 1]) << 8)
                    | u32::from(value[group * 3 + 2]);
                for offset in 0..4 {
                    encoded[group * 4 + offset] =
                        BASE64URL[((word >> (18 - offset * 6)) & 63) as usize];
                }
            }
            let word = (u32::from(value[30]) << 16) | (u32::from(value[31]) << 8);
            for offset in 0..3 {
                encoded[40 + offset] = BASE64URL[((word >> (18 - offset * 6)) & 63) as usize];
            }
            let raw = format!("\"{}\"", std::str::from_utf8(&encoded).expect("ascii"));
            let mut output = [9; 32];
            assert!(decode_secret(&raw, &mut output));
            assert_eq!(output, value);
            let mut noncanonical = encoded;
            noncanonical[42] = BASE64URL[(BASE64URL
                .iter()
                .position(|v| *v == noncanonical[42])
                .expect("alphabet")
                | 1)
                & 63];
            let raw = format!("\"{}\"", std::str::from_utf8(&noncanonical).expect("ascii"));
            assert!(!decode_secret(&raw, &mut output));
            assert_eq!(output, [0; 32]);
        }
    }

    #[test]
    fn connector_fixture_parses_and_header_trust_is_bound() {
        assert!(ValidatedBootstrapRequest::parse(fixture()).is_ok());
        assert!(ValidatedBootstrapRequest::parse(fixture_with_explicit_trust_ports()).is_ok());
        let mut bad = fixture();
        bad.header.control_ca_sha256 = Some(hex(b"wrong"));
        assert!(ValidatedBootstrapRequest::parse(bad).is_err());
    }

    #[test]
    fn owner_id_requires_canonical_identity_id() {
        assert!(is_identity_id(OWNER_ID));
        for legacy in [
            "0197f1f0-0000-7000-8000-000000000008",
            "dtxi1eci4tbb6kk5wk4vwv5ckekifwqtxy7bdd5vbmd7vac45r5xwu4lb",
            "dtxi1ECI4TBB6KK5WK4VWV5CKEKIFWQTXY7BDD5VBMD7VAC45R5XWU4LA",
        ] {
            assert!(!is_identity_id(legacy));
            let frame = fixture();
            let plan = replace_once(
                frame.material.as_ref().expect("material").plan_json(),
                OWNER_ID,
                legacy,
            );
            assert!(ValidatedBootstrapRequest::parse(with_plan(frame, plan)).is_err());
        }
    }

    #[test]
    fn canonical_plan_matches_independent_go_encoding_json_fixture() {
        let frame = fixture();
        let raw = frame.material.as_ref().expect("material").plan_json();
        assert_eq!(raw, GO_PLAN_CANONICAL_JSON);
        assert_eq!(raw, SHARED_CANONICAL_PLAN.trim_end().as_bytes());
        let mut decoder = serde_json::Deserializer::from_slice(raw);
        let plan = Plan::deserialize(&mut decoder).expect("plan");
        decoder.end().expect("one plan value");
        assert_eq!(
            serde_json::to_vec(&plan).expect("serde plan"),
            GO_PLAN_CANONICAL_JSON
        );
        assert_eq!(
            canonical_plan_digest(&plan).expect("digest"),
            decode_digest(GO_PLAN_CANONICAL_SHA256).expect("hex")
        );
    }

    #[test]
    fn shared_negative_fields_are_rejected_by_host_v2() {
        let invalid: serde_json::Value =
            serde_json::from_str(SHARED_INVALID_FIELDS).expect("shared invalid fields");
        for (from, field) in [
            ("safe", "runtime_profile"),
            ("https://server.example", "server_origin"),
            ("1.2.3-alpha.1+build-1", "version"),
        ] {
            let frame = fixture();
            let plan = replace_once(
                frame.material.as_ref().expect("material").plan_json(),
                from,
                invalid[field].as_str().expect("invalid string"),
            );
            assert!(ValidatedBootstrapRequest::parse(with_plan(frame, plan)).is_err());
        }
    }

    #[test]
    fn prepared_and_finalized_receipts_bind_canonical_connector_proofs() {
        let frame = fixture();
        let prepared = prepared_receipt(&frame, 1, 1);
        let proof = bind_prepared_receipt(&frame, &prepared).expect("prepared receipt");
        assert_eq!(proof.prepared_receipt_sha256, digest_only(&prepared));
        assert_eq!(proof.credential_generation, 1);
        assert_eq!(proof.credential_revision, 1);

        let mut finalize_frame = fixture();
        finalize_frame.header.prepared_receipt_sha256 = Some(hex(&prepared));
        let finalized = format!(
            r#"{{"schema":"dirextalk.connector-bootstrap-finalized-receipt","schema_version":1,"state":"finalized","prepared_receipt_sha256":"{}"}}"#,
            hex(&prepared)
        )
        .into_bytes();
        let final_proof = bind_finalized_receipt(&finalize_frame, &prepared, &finalized)
            .expect("finalized receipt");
        assert_eq!(
            final_proof.finalized_receipt_sha256,
            digest_only(&finalized)
        );
    }

    #[test]
    fn receipts_reject_whitespace_reordering_unknown_duplicates_and_mismatches() {
        let frame = fixture();
        let prepared = prepared_receipt(&frame, 1, 1);
        for (index, invalid) in [
            [b" ".as_slice(), prepared.as_slice()].concat(),
            [prepared.as_slice(), b" "].concat(),
            replace_once(
                &prepared,
                "\"schema_version\":1,\"state\":\"prepared\"",
                "\"state\":\"prepared\",\"schema_version\":1",
            ),
            replace_once(&prepared, "\"}", ",\"unknown\":true}"),
            replace_once(
                &prepared,
                "\"state\":\"prepared\"",
                "\"state\":\"prepared\",\"state\":\"prepared\"",
            ),
            replace_once(&prepared, GO_PLAN_CANONICAL_SHA256, &hex(b"other")),
            replace_once(
                &prepared,
                "\"credential_id\":\"0197f1f0-0000-7000-8000-000000000010\"",
                "\"credential_id\":\"bad\"",
            ),
            replace_once(&prepared, &hex(b"leaf"), "bad"),
            replace_once(
                &prepared,
                "\"credential_generation\":1",
                "\"credential_generation\":0",
            ),
            replace_once(
                &prepared,
                "\"credential_revision\":1",
                "\"credential_revision\":0",
            ),
            replace_once(
                &prepared,
                "\"target\":\"linux-amd64\"",
                "\"target\":\"linux-arm64\"",
            ),
        ]
        .into_iter()
        .enumerate()
        {
            assert!(
                bind_prepared_receipt(&frame, &invalid).is_err(),
                "invalid receipt case {index}"
            );
        }
        let mut finalize_frame = fixture();
        finalize_frame.header.prepared_receipt_sha256 = Some(hex(b"wrong"));
        let finalized = format!(
            r#"{{"schema":"dirextalk.connector-bootstrap-finalized-receipt","schema_version":1,"state":"finalized","prepared_receipt_sha256":"{}"}}"#,
            hex(&prepared)
        )
        .into_bytes();
        assert!(bind_finalized_receipt(&finalize_frame, &prepared, &finalized).is_err());
        let bad_finalized = replace_once(&finalized, &hex(&prepared), &hex(b"wrong"));
        let mut good_frame = fixture();
        good_frame.header.prepared_receipt_sha256 = Some(hex(&prepared));
        assert!(bind_finalized_receipt(&good_frame, &prepared, &bad_finalized).is_err());
    }

    #[test]
    fn connector_url_and_semver_validators_match_closed_shapes() {
        for (url, name) in [
            ("https://host:1", "host"),
            ("https://host:8443/", "host"),
            ("https://host:9443", "host"),
            ("https://host:9444/", "host"),
            ("https://host:65535", "host"),
        ] {
            assert!(valid_endpoint(url, name), "{url}");
        }
        for invalid in [
            "https://host/",
            "https://u@host",
            "https://host:443",
            "https://host?q",
            "https://host#x",
        ] {
            assert!(!valid_origin(invalid));
        }
        for invalid in [
            "https://host//",
            "https://u@host/",
            "https://host:443/",
            "https://host/?q",
            "https://host/#x",
        ] {
            assert!(!valid_endpoint(invalid, "host"));
        }
        for invalid in [
            "https://host:443",
            "https://host:0",
            "https://host:01",
            "https://host:0001",
            "https://host:65536",
            "https://host:9443x",
            "https://other:9443",
        ] {
            assert!(!valid_endpoint(invalid, "host"), "{invalid}");
        }
        for invalid in [
            "https://host/mcp/",
            "https://host//mcp",
            "https://host/%6dcp",
            "https://host/mcp?q",
        ] {
            assert!(!valid_mcp_url(invalid));
        }
        for invalid in ["1.2.3-", "1.2.3-a..b", "1.2.3+", "1.2.3+a+b", "01.2.3"] {
            assert!(!is_semver(invalid));
        }
    }

    #[test]
    fn expired_prepare_footprint_policy_is_effect_free_before_claim_recovery() {
        assert_eq!(
            expired_prepare_route(LinuxPrepareFootprint::AllAbsent),
            Ok(ExpiredPrepareRoute::Unclaimed)
        );
        assert_eq!(
            expired_prepare_route(LinuxPrepareFootprint::Present),
            Ok(ExpiredPrepareRoute::RecoverClaim)
        );
        assert_eq!(
            expired_prepare_route(LinuxPrepareFootprint::Ambiguous),
            Err(PortError::new(PortErrorKind::InvalidArtifact))
        );
    }

    #[test]
    fn expired_present_pending_claim_before_receipt_reenters_connector_recovery() {
        // The footprint gate intentionally has no receipt or process input:
        // the Connector's fixed bootstrap verb is the only authority that can
        // distinguish its durable pending claim from a completed claim.
        assert_eq!(
            expired_prepare_route(LinuxPrepareFootprint::Present),
            Ok(ExpiredPrepareRoute::RecoverClaim)
        );
    }

    #[test]
    fn expired_present_receipt_after_host_reboot_reenters_connector_recovery() {
        // A reboot can make the Host unit Absent after the Connector writes a
        // receipt. Present still follows the exact recovery capability, which
        // re-ensures the fixed stopped unit before adoption.
        assert_eq!(
            expired_prepare_route(LinuxPrepareFootprint::Present),
            Ok(ExpiredPrepareRoute::RecoverClaim)
        );
    }

    #[test]
    fn fixture_rejects_duplicate_unknown_trailing_and_escaped_nonsecret_json() {
        let mut duplicate = fixture();
        duplicate.material = Some(BootstrapMaterialV1::new(
            b"config".to_vec(),
            b"enrollment".to_vec(),
            b"control".to_vec(),
            b"issuer".to_vec(),
            b"{\"schema\":\"x\",\"schema\":\"x\"}".to_vec(),
            b"{}".to_vec(),
        ));
        assert!(ValidatedBootstrapRequest::parse(duplicate).is_err());
        let mut unknown = fixture();
        let material = unknown.material.take().expect("material");
        let mut raw = material.plan_json().to_vec();
        raw.pop();
        raw.extend_from_slice(b",\"unknown\":true}");
        unknown.material = Some(BootstrapMaterialV1::new(
            material.config_toml().to_vec(),
            material.enrollment_ca_pem().to_vec(),
            material.control_ca_pem().to_vec(),
            material.issuer_ca_pem().to_vec(),
            raw,
            material.handoff_json().to_vec(),
        ));
        assert!(ValidatedBootstrapRequest::parse(unknown).is_err());
        let mut escaped = fixture();
        let material = escaped.material.take().expect("material");
        let raw = String::from_utf8(material.plan_json().to_vec())
            .expect("utf8")
            .replacen("Connector", "\\u0043onnector", 1)
            .into_bytes();
        escaped.material = Some(BootstrapMaterialV1::new(
            material.config_toml().to_vec(),
            material.enrollment_ca_pem().to_vec(),
            material.control_ca_pem().to_vec(),
            material.issuer_ca_pem().to_vec(),
            raw,
            material.handoff_json().to_vec(),
        ));
        assert!(ValidatedBootstrapRequest::parse(escaped).is_err());
        let mut trailing = fixture();
        let material = trailing.material.take().expect("material");
        trailing.material = Some(BootstrapMaterialV1::new(
            material.config_toml().to_vec(),
            material.enrollment_ca_pem().to_vec(),
            material.control_ca_pem().to_vec(),
            material.issuer_ca_pem().to_vec(),
            material.plan_json().to_vec(),
            [material.handoff_json(), b" x"].concat(),
        ));
        assert!(ValidatedBootstrapRequest::parse(trailing).is_err());

        let frame = fixture();
        let noncanonical = [
            b" ".as_slice(),
            frame.material.as_ref().expect("material").plan_json(),
        ]
        .concat();
        assert!(ValidatedBootstrapRequest::parse(with_plan(frame, noncanonical)).is_err());
    }

    #[test]
    fn recursive_plan_handoff_and_display_restrictions_fail_closed() {
        for (needle, replacement) in [
            (
                "\"display_name\":\"Connector\"",
                "\"display_name\":\"Connector\",\"display_name\":\"Connector\"",
            ),
            (
                "\"enrollment_url\":\"https://enroll.example/\"",
                "\"enrollment_url\":\"https://enroll.example/\",\"enrollment_url\":\"https://enroll.example/\"",
            ),
            (
                "\"mcp_url\":\"https://mcp.example/mcp\"",
                "\"mcp_url\":\"https://mcp.example/mcp\",\"mcp_url\":\"https://mcp.example/mcp\"",
            ),
        ] {
            let frame = fixture();
            let raw = replace_once(
                frame.material.as_ref().expect("material").plan_json(),
                needle,
                replacement,
            );
            assert!(ValidatedBootstrapRequest::parse(with_plan(frame, raw)).is_err());
        }
        let mut handoff_frame = fixture();
        let material = handoff_frame.material.take().expect("material");
        let handoff = replace_once(
            material.handoff_json(),
            "\"state\":\"ready\"",
            "\"state\":\"ready\",\"state\":\"ready\"",
        );
        handoff_frame.material = Some(BootstrapMaterialV1::new(
            material.config_toml().to_vec(),
            material.enrollment_ca_pem().to_vec(),
            material.control_ca_pem().to_vec(),
            material.issuer_ca_pem().to_vec(),
            material.plan_json().to_vec(),
            handoff,
        ));
        assert!(ValidatedBootstrapRequest::parse(handoff_frame).is_err());

        for marker in ['<', '>', '&', '\u{2028}', '\u{2029}'] {
            let frame = fixture();
            let replacement = format!("\"display_name\":\"{marker}\"");
            let raw = replace_once(
                frame.material.as_ref().expect("material").plan_json(),
                "\"display_name\":\"Connector\"",
                &replacement,
            );
            assert!(ValidatedBootstrapRequest::parse(with_plan(frame, raw)).is_err());
        }
    }

    #[test]
    fn header_binds_target_adapter_release_identity_lifecycle_expiry_and_cas() {
        let cases = [
            "target",
            "adapter",
            "release",
            "tenant",
            "host",
            "connector",
            "lifecycle",
            "expiry",
            "enrollment_ca",
            "control_ca",
            "issuer_ca",
        ];
        for case in cases {
            let mut frame = fixture();
            match case {
                "target" => {
                    frame.header.platform_target = match PlatformTarget::executing() {
                        Some(PlatformTarget::LinuxAmd64) => PlatformTarget::LinuxArm64,
                        Some(PlatformTarget::LinuxArm64) => PlatformTarget::LinuxAmd64,
                        None => unreachable!("fixture target is supported"),
                    }
                }
                "adapter" => frame.header.adapter = AdapterV2::Eino,
                "release" => frame.header.approved_release_sha256 = hex(b"other-release"),
                "tenant" => {
                    frame.header.tenant_id =
                        uuid::<TenantId>("0197f1f0-0000-7000-8000-000000000014");
                }
                "host" => {
                    frame.header.host_id = uuid::<HostId>("0197f1f0-0000-7000-8000-000000000015");
                }
                "connector" => {
                    frame.header.connector_id =
                        uuid::<ConnectorId>("0197f1f0-0000-7000-8000-000000000016");
                }
                "lifecycle" => {
                    frame.header.lifecycle_operation_id =
                        uuid::<RequestId>("0197f1f0-0000-7000-8000-000000000017");
                }
                "expiry" => frame.header.expiry_millis += 1,
                "enrollment_ca" => {
                    frame.header.enrollment_ca_sha256 = Some(hex(b"other-enrollment"));
                }
                "control_ca" => frame.header.control_ca_sha256 = Some(hex(b"other-control")),
                "issuer_ca" => frame.header.issuer_ca_sha256 = Some(hex(b"other-issuer")),
                _ => unreachable!(),
            }
            assert!(ValidatedBootstrapRequest::parse(frame).is_err());
        }
    }
}
