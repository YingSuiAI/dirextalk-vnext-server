#!/usr/bin/env python3
"""Deterministic contract tests for the 0.1.1 -> 0.1.4 production update path."""

from __future__ import annotations

import importlib.machinery
import inspect
import json
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MODULE = importlib.machinery.SourceFileLoader(
    "install_vnext_contract", str(ROOT / "scripts/production-stack/host/install-vnext")
).load_module()
PROVISION = importlib.machinery.SourceFileLoader(
    "provision_vnext_renderer", str(ROOT / "scripts/production-stack/host/provision-vnext")
).load_module()


def facts(version: str) -> dict[str, object]:
    image = "dirextalk/vnet-server@sha256:" + "a" * 64
    return {
        "target": "linux-amd64",
        "domain": "node.example.invalid",
        "version": version,
        "source_commit": "b" * 40,
        "bundle_sha256": "c" * 64,
        "manifest_sha256": "d" * 64,
        "server_image": image,
        "migrator_image": image,
    }


def main() -> None:
    # Recovery embeds, rather than imports, the provisioned-host renderer.  Any
    # drift in compose, owner allowlist, or Caddy/TLS semantics is a failure.
    source = (ROOT / "docker/production/docker-compose.yml").read_text()
    assert MODULE.transform_compose(source) == PROVISION.transform_compose(source)
    assert MODULE.owner_routes() == PROVISION.owner_routes()
    assert MODULE.caddyfile("node.example.invalid") == PROVISION.caddyfile("node.example.invalid")
    # Strictly-forward admission accepts the frozen release transition and
    # rejects replay, downgrade, and malformed ordering.
    assert MODULE.strictly_forward("0.1.1", "0.1.4")
    assert MODULE.admitted_cross_version("0.1.1", "0.1.4")
    assert not MODULE.admitted_cross_version("0.1.2", "0.1.4")
    assert not MODULE.strictly_forward("0.1.4", "0.1.1")
    assert not MODULE.strictly_forward("0.1.1", "0.1.1")

    prior = facts("0.1.1")
    request = facts("0.1.4")
    request["previous_receipt_sha256"] = "e" * 64
    receipt, raw = MODULE.make_receipt(request, "installed", request["previous_receipt_sha256"])
    assert MODULE.validate_receipt(raw) == receipt
    assert MODULE.request_matches_receipt(request, receipt)

    # Fault-inject a crash after receipt history publication but before
    # current.json promotion, then recover the authenticated candidate.
    original_root = MODULE.RECEIPT_ROOT
    original_current = MODULE.CURRENT_RECEIPT
    original_read = MODULE.read_secure
    original_atomic = MODULE.atomic_write
    original_fchown = MODULE.os.fchown
    try:
        with tempfile.TemporaryDirectory() as directory:
            MODULE.RECEIPT_ROOT = Path(directory)
            MODULE.CURRENT_RECEIPT = MODULE.RECEIPT_ROOT / "current.json"
            MODULE.os.fchown = lambda _descriptor, _uid, _gid: None
            def crash_before_current(path: Path, value: bytes) -> None:
                if path == MODULE.CURRENT_RECEIPT:
                    raise OSError("injected current receipt promotion crash")
                original_atomic(path, value)

            MODULE.atomic_write = crash_before_current
            try:
                MODULE.publish_receipt(request, "installed", request["previous_receipt_sha256"])
            except OSError:
                pass
            else:
                raise AssertionError("receipt promotion crash injection unexpectedly succeeded")
            history_files = list(MODULE.RECEIPT_ROOT.glob("*.json"))
            assert len(history_files) == 1
            history = history_files[0]
            published = MODULE.validate_receipt(history.read_bytes())
            assert not MODULE.CURRENT_RECEIPT.exists()
            MODULE.read_secure = lambda path, _mode, _limit: Path(path).read_bytes()
            recovered = MODULE.find_candidate_receipt(request)
            assert recovered is not None and recovered[0]["receipt_sha256"] == published["receipt_sha256"]
            original_atomic(MODULE.CURRENT_RECEIPT, recovered[1])
            assert MODULE.validate_receipt(MODULE.CURRENT_RECEIPT.read_bytes()) == published
    finally:
        MODULE.RECEIPT_ROOT = original_root
        MODULE.CURRENT_RECEIPT = original_current
        MODULE.read_secure = original_read
        MODULE.atomic_write = original_atomic
        MODULE.os.fchown = original_fchown

    # A crash after publishing the candidate receipt is a no-op on replay;
    # a chained rolled-back receipt remains a recoverable prior shape.
    rolled_back, rolled_back_raw = MODULE.make_receipt(
        prior, "rolled_back", request["previous_receipt_sha256"]
    )
    assert MODULE.validate_receipt(rolled_back_raw)["state"] == "rolled_back"
    assert rolled_back["previous_receipt_sha256"] == request["previous_receipt_sha256"]

    # Execute code-only rollback against a temporary canonical environment.
    # Prior readiness is a mandatory second subprocess; failure propagates and
    # therefore cannot publish a rolled_back receipt.
    original_config = MODULE.PRODUCTION_CONFIG_ROOT
    original_env = MODULE.PRODUCTION_ENV
    original_compose = MODULE.PRODUCTION_COMPOSE
    original_install_root = MODULE.PRODUCTION_INSTALL_ROOT
    original_current_env = MODULE.CURRENT_ENV
    original_run = MODULE.subprocess.run
    original_read = MODULE.read_secure
    original_fchown = MODULE.os.fchown
    original_secure_metadata = MODULE.secure_metadata
    try:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            release = base / "release"
            config = base / "config"
            install_root = base / "lib"
            current_env = base / "current.env"
            for path in (
                release / "docker/production",
                release / "tools",
                release / "scripts/production-stack",
                config,
                install_root,
            ):
                path.mkdir(parents=True, exist_ok=True)
            (release / "docker/production/Caddyfile").write_text("prior caddy\n")
            (release / "docker/production/docker-compose.yml").write_text("services: {}\n")
            (release / "tools/validate-production-images.py").write_text("# prior validator\n")
            verifier = release / MODULE.VERIFY_PATH
            verifier.write_text("#!/usr/bin/env bash\nexit 0\n")
            candidate_env = "\n".join(
                (
                    "DTX_SERVER_IMAGE=dirextalk/vnet-server@sha256:" + "f" * 64,
                    "DTX_MIGRATOR_IMAGE=dirextalk/vnet-server@sha256:" + "e" * 64,
                    "DTX_RELEASE_VERSION=0.1.4",
                    "DTX_SECRET_ROOT=/preserved/secrets",
                    "DTX_TLS_ROOT=/preserved/tls",
                    "",
                )
            )
            (config / "production.env").write_text(candidate_env)
            MODULE.PRODUCTION_CONFIG_ROOT = config
            MODULE.PRODUCTION_ENV = config / "production.env"
            MODULE.PRODUCTION_COMPOSE = config / "production-compose.yml"
            MODULE.PRODUCTION_INSTALL_ROOT = install_root
            MODULE.CURRENT_ENV = current_env
            MODULE.os.fchown = lambda _descriptor, _uid, _gid: None
            MODULE.read_secure = lambda path, _mode, _limit: Path(path).read_bytes()
            calls: list[list[str]] = []

            def successful_run(command: list[str], **_kwargs: object) -> None:
                calls.append(command)

            MODULE.subprocess.run = successful_run
            prior_manifest = {
                **prior,
                "server_image": "dirextalk/vnet-server@sha256:" + "1" * 64,
                "migrator_image": "dirextalk/vnet-server@sha256:" + "2" * 64,
            }
            MODULE.install_code_only_rollback(release, prior_manifest)
            assert len(calls) == 2
            assert "--no-deps" in calls[0]
            assert calls[1] == [str(verifier)]
            restored = MODULE.PRODUCTION_ENV.read_text()
            assert "DTX_RELEASE_VERSION=0.1.1" in restored
            assert "DTX_SECRET_ROOT=/preserved/secrets" in restored
            assert "DTX_TLS_ROOT=/preserved/tls" in restored
            assert MODULE.CURRENT_ENV.read_text() == restored

            def failed_probe(command: list[str], **_kwargs: object) -> None:
                if command == [str(verifier)]:
                    raise subprocess.CalledProcessError(1, command)

            MODULE.subprocess.run = failed_probe
            try:
                MODULE.install_code_only_rollback(release, prior_manifest)
            except subprocess.CalledProcessError:
                pass
            else:
                raise AssertionError("failed prior readiness was accepted")
    finally:
        MODULE.PRODUCTION_CONFIG_ROOT = original_config
        MODULE.PRODUCTION_ENV = original_env
        MODULE.PRODUCTION_COMPOSE = original_compose
        MODULE.PRODUCTION_INSTALL_ROOT = original_install_root
        MODULE.CURRENT_ENV = original_current_env
        MODULE.subprocess.run = original_run
        MODULE.read_secure = original_read
        MODULE.os.fchown = original_fchown

    # Candidate activation changes only the three authenticated runtime
    # identity fields.  It cannot overwrite tenant/operator settings, and its
    # resulting attestation is canonical and rejects forged receipt facts.
    original_env = MODULE.PRODUCTION_ENV
    original_compose = MODULE.PRODUCTION_COMPOSE
    original_config = MODULE.PRODUCTION_CONFIG_ROOT
    original_current_env = MODULE.CURRENT_ENV
    original_attestation = MODULE.RUNTIME_ATTESTATION
    original_read = MODULE.read_secure
    original_fchown = MODULE.os.fchown
    original_render = MODULE.provisioned_host_material
    try:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            release = base / ("c" * 64)
            config = base / "config"
            (release / "docker/production").mkdir(parents=True)
            config.mkdir()
            compose = "services: {}\n"
            caddy = "example.invalid { respond 200 }\n"
            (release / "docker/production/docker-compose.yml").write_text(compose)
            (release / "docker/production/Caddyfile").write_text(caddy)
            env = "\n".join((
                "DTX_SERVER_IMAGE=dirextalk/vnet-server@sha256:" + "1" * 64,
                "DTX_MIGRATOR_IMAGE=dirextalk/vnet-server@sha256:" + "2" * 64,
                "DTX_RELEASE_VERSION=0.1.1",
                "DTX_TENANT_OPERATOR_FIELD=preserve-me",
                "",
            ))
            (config / "production.env").write_text(env)
            (config / "production-compose.yml").write_text(compose)
            (config / "Caddyfile").write_text(caddy)
            current_env = base / "current.env"
            candidate_manifest = {
                **request,
                "server_image": "dirextalk/vnet-server@sha256:" + "3" * 64,
                "migrator_image": "dirextalk/vnet-server@sha256:" + "4" * 64,
                "version": "0.1.4",
            }
            MODULE.PRODUCTION_CONFIG_ROOT = config
            MODULE.PRODUCTION_ENV = config / "production.env"
            MODULE.PRODUCTION_COMPOSE = config / "production-compose.yml"
            MODULE.CURRENT_ENV = current_env
            MODULE.RUNTIME_ATTESTATION = base / "runtime-attestation.json"
            MODULE.os.fchown = lambda _descriptor, _uid, _gid: None
            MODULE.read_secure = lambda path, _mode, _limit: Path(path).read_bytes()
            MODULE.provisioned_host_material = lambda _release, _domain: (compose.encode(), caddy.encode())
            selected = MODULE.replace_runtime_identity(candidate_manifest)
            current_env.write_bytes(selected)
            assert b"DTX_TENANT_OPERATOR_FIELD=preserve-me" in selected
            assert b"DTX_RELEASE_VERSION=0.1.4" in selected
            value, raw = MODULE.runtime_attestation(release, candidate_manifest, "node.example.invalid")
            receipt, _receipt_raw = MODULE.make_receipt(candidate_manifest, "installed", "e" * 64)
            assert MODULE.validate_runtime_attestation(raw, receipt) == value
            forged = dict(receipt)
            forged["version"] = "0.1.1"
            try:
                MODULE.validate_runtime_attestation(raw, forged)
            except MODULE.ContractError:
                pass
            else:
                raise AssertionError("forged/mixed receipt was accepted by runtime attestation")
    finally:
        MODULE.PRODUCTION_ENV = original_env
        MODULE.PRODUCTION_COMPOSE = original_compose
        MODULE.PRODUCTION_CONFIG_ROOT = original_config
        MODULE.CURRENT_ENV = original_current_env
        MODULE.RUNTIME_ATTESTATION = original_attestation
        MODULE.read_secure = original_read
        MODULE.os.fchown = original_fchown
        MODULE.provisioned_host_material = original_render

    # The emergency basename accepts only the exact chained receipt shape and
    # reaches activation only after the old-runtime proof.  A forged chain has
    # no side effects.
    original_receipt_root = MODULE.RECEIPT_ROOT
    original_current_reader = MODULE.read_current_receipt
    original_load = MODULE.load_retained_release
    original_compatible = MODULE.compatible
    original_attested = MODULE.runtime_is_attested
    original_prove_false = MODULE.prove_known_false_runtime
    original_activate = MODULE.activate_candidate
    original_attest_runtime = MODULE.attest_runtime
    original_runtime_attestation = MODULE.RUNTIME_ATTESTATION
    original_read = MODULE.read_secure
    try:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            MODULE.RECEIPT_ROOT = base
            old, old_raw = MODULE.make_receipt(prior, "installed", None)
            candidate_request = dict(request)
            candidate_request["previous_receipt_sha256"] = old["receipt_sha256"]
            candidate, candidate_raw = MODULE.make_receipt(
                candidate_request, "installed", old["receipt_sha256"]
            )
            (base / f"{old['receipt_sha256']}.json").write_bytes(old_raw)
            (base / f"{candidate['receipt_sha256']}.json").write_bytes(candidate_raw)
            candidate_release, prior_release = base / "candidate", base / "prior"
            candidate_release.mkdir(); prior_release.mkdir()
            MODULE.read_current_receipt = lambda: (candidate, candidate_raw)
            MODULE.read_secure = lambda path, _mode, _limit: Path(path).read_bytes()
            MODULE.load_retained_release = lambda receipt: (
                (candidate_release, request) if receipt["version"] == "0.1.4" else (prior_release, prior)
            )
            MODULE.compatible = lambda _release: True
            calls: list[str] = []
            attested = iter((False, True))
            MODULE.runtime_is_attested = lambda *_args: next(attested)
            MODULE.prove_known_false_runtime = lambda *_args: calls.append("old-proof")
            MODULE.activate_candidate = lambda *_args: calls.append("activate")
            MODULE.recover_false_runtime_once()
            assert calls == ["old-proof", "activate"]
            forged = dict(candidate); forged["previous_receipt_sha256"] = "f" * 64
            MODULE.read_current_receipt = lambda: (forged, candidate_raw)
            calls.clear()
            try:
                MODULE.recover_false_runtime_once()
            except (MODULE.ContractError, FileNotFoundError):
                pass
            else:
                raise AssertionError("forged recovery chain was accepted")
            assert not calls
            # The attester sees the same false/old runtime as a proof failure;
            # it never falls through to recovery or alters its old attestation.
            MODULE.read_current_receipt = lambda: (candidate, candidate_raw)
            preserved = base / "runtime-attestation.json"
            preserved.write_text("old-proof\n")
            MODULE.RUNTIME_ATTESTATION = preserved
            MODULE.attest_runtime = lambda *_args: (_ for _ in ()).throw(MODULE.ContractError("old runtime"))
            try:
                MODULE.attest_candidate_runtime_once()
            except MODULE.ContractError:
                pass
            else:
                raise AssertionError("false old runtime was attested")
            assert preserved.read_text() == "old-proof\n" and calls == []
    finally:
        MODULE.RECEIPT_ROOT = original_receipt_root
        MODULE.read_current_receipt = original_current_reader
        MODULE.load_retained_release = original_load
        MODULE.compatible = original_compatible
        MODULE.runtime_is_attested = original_attested
        MODULE.prove_known_false_runtime = original_prove_false
        MODULE.activate_candidate = original_activate
        MODULE.attest_runtime = original_attest_runtime
        MODULE.RUNTIME_ATTESTATION = original_runtime_attestation
        MODULE.read_secure = original_read

    # r3 recovery accepts both authenticated old-runtime shapes, then invokes
    # the existing activation boundary without changing either receipt byte.
    original_receipt_root = MODULE.RECEIPT_ROOT
    original_current_reader = MODULE.read_current_receipt
    original_load = MODULE.load_retained_release
    original_compatible = MODULE.compatible
    original_marker = MODULE.R3_TRANSITION_MARKER
    original_state_root = MODULE.STATE_ROOT
    original_runtime_attestation = MODULE.RUNTIME_ATTESTATION
    original_attested_r3 = MODULE.runtime_is_attested_r3
    original_prove_partial = MODULE.prove_partial_migration_runtime
    original_activate = MODULE.activate_candidate
    original_read = MODULE.read_secure
    original_fchown = MODULE.os.fchown
    try:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            MODULE.RECEIPT_ROOT = base
            MODULE.STATE_ROOT = base
            MODULE.R3_TRANSITION_MARKER = base / "r3-transition.json"
            old, old_raw = MODULE.make_receipt(prior, "installed", None)
            candidate_request = dict(request)
            candidate_request["previous_receipt_sha256"] = old["receipt_sha256"]
            candidate, candidate_raw = MODULE.make_receipt(candidate_request, "installed", old["receipt_sha256"])
            (base / f"{old['receipt_sha256']}.json").write_bytes(old_raw)
            (base / f"{candidate['receipt_sha256']}.json").write_bytes(candidate_raw)
            candidate_release, prior_release = base / "candidate", base / "prior"
            candidate_release.mkdir(); prior_release.mkdir()
            MODULE.read_current_receipt = lambda: (candidate, candidate_raw)
            MODULE.read_secure = lambda path, _mode, _limit: Path(path).read_bytes()
            MODULE.os.fchown = lambda _descriptor, _uid, _gid: None
            MODULE.secure_metadata = lambda *_args: None
            MODULE.load_retained_release = lambda receipt: (
                (candidate_release, request) if receipt["version"] == "0.1.4" else (prior_release, prior)
            )
            MODULE.compatible = lambda _release: True
            attest_states = iter((False, True))
            MODULE.runtime_is_attested_r3 = lambda *_args: next(attest_states)
            calls: list[object] = []
            MODULE.prove_partial_migration_runtime = lambda *_args: calls.append(_args[-1])
            MODULE.activate_candidate = lambda *_args: calls.append("activate")
            MODULE.recover_partial_migration_once()
            assert calls == [MODULE.ProofMode.ORIGINAL, "activate"]

            attest_states = iter((False, True, True))
            calls.clear()
            def partial_proof(*args: object) -> None:
                calls.append(args[-1])
                if args[-1] is MODULE.ProofMode.ORIGINAL:
                    raise MODULE.ContractError("original state not present")
            MODULE.prove_partial_migration_runtime = partial_proof
            MODULE.recover_partial_migration_once()
            assert calls == [MODULE.ProofMode.ORIGINAL, MODULE.ProofMode.MIGRATED_OLD, "activate"]
            assert (base / f"{old['receipt_sha256']}.json").read_bytes() == old_raw
            assert (base / f"{candidate['receipt_sha256']}.json").read_bytes() == candidate_raw

            # The marker is written before activation and survives an injected
            # crash; a retry replays activation only after an exact marker-bound
            # candidate proof, then removes it. Invalid markers fail closed.
            MODULE.runtime_is_attested_r3 = lambda *_args: False
            MODULE.prove_partial_migration_runtime = lambda *_args: None
            def crash_activate(*_args: object) -> None:
                calls.append("crash-activate")
                raise MODULE.ContractError("injected activation crash")
            MODULE.activate_candidate = crash_activate
            try:
                MODULE.recover_partial_migration_once()
            except MODULE.ContractError:
                pass
            else:
                raise AssertionError("activation crash unexpectedly succeeded")
            assert MODULE.R3_TRANSITION_MARKER.exists()
            MODULE.R3_TRANSITION_MARKER.write_bytes(b"malformed\n")
            try:
                MODULE.recover_partial_migration_once()
            except MODULE.ContractError:
                pass
            else:
                raise AssertionError("malformed transition marker was accepted")
            MODULE.R3_TRANSITION_MARKER.write_bytes(MODULE.make_r3_transition_marker(candidate, old))
            MODULE.runtime_is_attested_r3 = lambda *_args: True
            MODULE.activate_candidate = lambda *_args: calls.append("unexpected-activation")
            MODULE.recover_partial_migration_once()
            assert not MODULE.R3_TRANSITION_MARKER.exists()
            MODULE.begin_r3_transition(candidate, old)
            try:
                MODULE.attest_candidate_runtime_once_r3()
            except MODULE.ContractError:
                pass
            else:
                raise AssertionError("r3 attester ignored an activating marker")
            MODULE.clear_r3_transition(candidate, old)

            # A valid legacy r2 candidate proof is converted in-place to r3;
            # stale/malformed legacy bytes are not admitted as old-runtime proof.
            MODULE.RUNTIME_ATTESTATION = base / "runtime-attestation.json"
            MODULE.RUNTIME_ATTESTATION.write_bytes(b"legacy-r2")
            attest_states = iter((False, True))
            MODULE.runtime_is_attested_r3 = lambda *_args: next(attest_states)
            MODULE.runtime_is_attested = lambda *_args: True
            MODULE.attest_runtime_r3 = lambda *_args: MODULE.RUNTIME_ATTESTATION.write_bytes(b"r3")
            MODULE.recover_partial_migration_once()
            assert not MODULE.R3_TRANSITION_MARKER.exists()

            MODULE.begin_r3_transition(candidate, old)
            marker_before = MODULE.R3_TRANSITION_MARKER.read_bytes()
            for entry_point in (
                MODULE.install_once,
                MODULE.recover_false_runtime_once,
                MODULE.attest_candidate_runtime_once,
            ):
                try:
                    entry_point()
                except MODULE.ContractError:
                    pass
                else:
                    raise AssertionError("legacy entry point ignored an active r3 marker")
                assert MODULE.R3_TRANSITION_MARKER.read_bytes() == marker_before
            MODULE.clear_r3_transition(candidate, old)
    finally:
        MODULE.RECEIPT_ROOT = original_receipt_root
        MODULE.read_current_receipt = original_current_reader
        MODULE.load_retained_release = original_load
        MODULE.compatible = original_compatible
        MODULE.R3_TRANSITION_MARKER = original_marker
        MODULE.STATE_ROOT = original_state_root
        MODULE.RUNTIME_ATTESTATION = original_runtime_attestation
        MODULE.runtime_is_attested_r3 = original_attested_r3
        MODULE.prove_partial_migration_runtime = original_prove_partial
        MODULE.activate_candidate = original_activate
        MODULE.read_secure = original_read
        MODULE.os.fchown = original_fchown
        MODULE.secure_metadata = original_secure_metadata

    # Docker Compose versions emit either one array or NDJSON. Both forms are
    # bounded and deterministic; malformed, mixed, duplicate, or non-object
    # records fail without echoing the raw output.
    service_records = [
        {"Service": name, "Image": request["server_image"]}
        for name in ("dtx-node", "realtime-gateway", "agent-control")
    ]
    expected_images = {record["Service"]: record["Image"] for record in service_records}
    array_output = json.dumps(service_records, separators=(",", ":")).encode()
    ndjson_output = b"\n".join(
        json.dumps(record, separators=(",", ":")).encode() for record in service_records
    ) + b"\n"
    assert MODULE.parse_compose_ps_images(array_output) == expected_images
    assert MODULE.parse_compose_ps_images(ndjson_output) == expected_images
    assert MODULE.parse_compose_ps_images(
        json.dumps(service_records[0], separators=(",", ":")).encode()
    ) == {"dtx-node": request["server_image"]}

    def reject_compose_output(raw: bytes) -> None:
        try:
            MODULE.parse_compose_ps_images(raw)
        except MODULE.ContractError as error:
            assert "LEAK-MARKER" not in str(error)
            return
        raise AssertionError("invalid Compose ps output was accepted")

    reject_compose_output(b"")
    reject_compose_output(b'{"Service":"dtx-node","Image":"LEAK-MARKER"}\n{')
    reject_compose_output(
        json.dumps(service_records[0]).encode() + b"\n" + json.dumps(service_records).encode()
    )
    reject_compose_output(json.dumps([service_records[0], service_records[0]]).encode())
    reject_compose_output(json.dumps([1]).encode())
    reject_compose_output(json.dumps([{"Service": 1, "Image": "image"}]).encode())
    reject_compose_output(b"x" * (MODULE.MAX_COMPOSE_PS_BYTES + 1))

    # Proof commands remain direct, fixed argv. The incident proof requires the
    # old binary to be absent; candidate proof requires it executable.
    original_run = MODULE.subprocess.run
    try:
        calls: list[list[str]] = []
        class Result:
            def __init__(self, stdout: bytes) -> None: self.stdout = stdout
        def proof_run(command: list[str], **_kwargs: object) -> Result:
            calls.append(command)
            return Result(ndjson_output if command[-2:] == ["--format", "json"] else b"ok\n")
        MODULE.subprocess.run = proof_run
        MODULE.prove_live_runtime(request, True)
        assert calls[1][-3:] == ["test", "-x", "/usr/local/bin/dtx-identity-provision"]
        assert "sh" not in calls[2] and calls[2][-9:-1] == [
            "-v", "ON_ERROR_STOP=1", "-U", "dtx_admin", "-d", "dtx_node", "-At", "-c",
        ]
        assert "202607230056" in calls[2][-1] and "202607230058" in calls[2][-1]
        calls.clear(); MODULE.prove_live_runtime(prior, False)
        assert calls[1][-4:] == ["test", "!", "-e", "/usr/local/bin/dtx-identity-provision"]
    finally:
        MODULE.subprocess.run = original_run

    # r3 uses explicit proof modes and authenticates the full SQLx shape. The
    # original and migrated-old modes require an absent provision binary;
    # candidate-ready requires it executable and the exact 58-row state.
    original_run = MODULE.subprocess.run
    try:
        class R3Result:
            def __init__(self, stdout: bytes) -> None: self.stdout = stdout

        def exercise_r3(mode, migration_output: bytes, image: str | None = None, binary_present: bool = False):
            calls: list[list[str]] = []
            records = [
                {"Service": name, "Image": image or request["server_image"]}
                for name in ("dtx-node", "realtime-gateway", "agent-control")
            ]
            output = json.dumps(records, separators=(",", ":")).encode()

            def run(command: list[str], **_kwargs: object) -> R3Result:
                calls.append(command)
                if command[-2:] == ["--format", "json"]:
                    return R3Result(output)
                if command[:2] == ["docker", "run"] and binary_present:
                    raise subprocess.CalledProcessError(1, command)
                if command[-3:] == ["test", "-x", "/usr/local/bin/dtx-identity-provision"] and not binary_present:
                    raise subprocess.CalledProcessError(1, command)
                return R3Result(migration_output)

            MODULE.subprocess.run = run
            MODULE.prove_live_runtime(request, mode)
            return calls

        for mode, output, present in (
            (MODULE.ProofMode.ORIGINAL, b"55|55|0|0\n", False),
            (MODULE.ProofMode.MIGRATED_OLD, b"58|58|3|3\n", False),
            (MODULE.ProofMode.CANDIDATE_READY, b"58|58|3|3\n", True),
        ):
            calls = exercise_r3(mode, output, binary_present=present)
            if present:
                assert calls[1][-3:] == ["test", "-x", "/usr/local/bin/dtx-identity-provision"]
            else:
                assert calls[1] == [
                    "docker", "run", "--rm", "--pull", "never", "--network", "none", "--read-only",
                    "--entrypoint", "/usr/bin/test", request["server_image"], "!", "-e",
                    "/usr/local/bin/dtx-identity-provision",
                ]
        for invalid in (b"54|54|0|0\n", b"56|55|0|0\n", b"58|58|2|2\n", b"58|58|3|2\n", b"59|59|3|3\n"):
            try:
                exercise_r3(MODULE.ProofMode.MIGRATED_OLD, invalid)
            except MODULE.ContractError:
                pass
            else:
                raise AssertionError(f"invalid r3 migration shape was accepted: {invalid!r}")
        try:
            exercise_r3(MODULE.ProofMode.MIGRATED_OLD, b"58|58|3|3\n", image="dirextalk/vnet-server@sha256:" + "f" * 64)
        except MODULE.ContractError:
            pass
        else:
            raise AssertionError("r3 image drift was accepted")
        try:
            exercise_r3(MODULE.ProofMode.MIGRATED_OLD, b"58|58|3|3\n", binary_present=True)
        except subprocess.CalledProcessError:
            pass
        else:
            raise AssertionError("r3 provision binary presence was accepted")
        for malformed in (b"", b"{}", b'{"schema":"unexpected"}\n'):
            try:
                MODULE.validate_runtime_attestation(malformed, receipt)
            except MODULE.ContractError:
                pass
            else:
                raise AssertionError("malformed r3 attestation was accepted")
        original_read_attestation = MODULE.read_secure
        MODULE.read_secure = lambda *_args: (_ for _ in ()).throw(MODULE.ContractError("missing"))
        try:
            MODULE.runtime_is_attested_r3(Path("/missing"), request, receipt)
        except MODULE.ContractError:
            pass
        else:
            raise AssertionError("missing r3 attestation was accepted")
        finally:
            MODULE.read_secure = original_read_attestation
    finally:
        MODULE.subprocess.run = original_run

    # The migration-state digest is authenticated and therefore replay-tamper
    # resistant, just like the configured/runtime digests.
    body = {
        "schema": MODULE.RUNTIME_ATTESTATION_SCHEMA, "schema_version": 1,
        "bundle_sha256": receipt["bundle_sha256"], "version": receipt["version"],
        "server_image": receipt["server_image"], "migrator_image": receipt["migrator_image"],
        "production_env_sha256": "0" * 64, "compose_sha256": "0" * 64,
        "caddy_sha256": "0" * 64, "running_services_sha256": "0" * 64,
        "client_binding_binary_sha256": "0" * 64, "migration_proof_sha256": "0" * 64,
    }
    value = dict(body); value["attestation_sha256"] = MODULE.digest(MODULE.canonical(body))
    tampered = dict(value); tampered["migration_proof_sha256"] = "f" * 64
    try: MODULE.validate_runtime_attestation(MODULE.canonical(tampered), receipt)
    except MODULE.ContractError: pass
    else: raise AssertionError("migration-proof attestation tamper was accepted")

    # Keep first-install/replay control flow isolated from runtime activation,
    # and leave update.sh as the sole failed-update rollback authority.
    install_source = inspect.getsource(MODULE.install_once)
    assert "if current is None:\n                # Only a first install" in install_source
    assert "else:\n                activate_candidate" in install_source
    assert "install_code_only_rollback" not in install_source
    assert "if current[\"previous_receipt_sha256\"] is not None:" in install_source

    # An absent current receipt may only recover a true initial receipt. A
    # chained historical candidate cannot be promoted without its predecessor.
    original_atomic = MODULE.atomic_write
    original_current_path = MODULE.CURRENT_RECEIPT
    try:
        writes: list[tuple[Path, bytes]] = []
        MODULE.CURRENT_RECEIPT = Path("/receipt/current.json")
        MODULE.atomic_write = lambda path, raw: writes.append((path, raw))
        fresh, fresh_raw = MODULE.make_receipt(prior, "installed", None)
        MODULE.promote_initial_recovered_receipt(fresh, fresh_raw)
        assert writes == [(MODULE.CURRENT_RECEIPT, fresh_raw)]
        chained = dict(fresh); chained["previous_receipt_sha256"] = "e" * 64
        writes.clear()
        try: MODULE.promote_initial_recovered_receipt(chained, fresh_raw)
        except MODULE.ContractError: pass
        else: raise AssertionError("chained historical receipt was promoted as initial")
        assert not writes
    finally:
        MODULE.atomic_write = original_atomic
        MODULE.CURRENT_RECEIPT = original_current_path

    # Unknown staged names fail before directory creation, locking, or upload
    # handling. This keeps the one-artifact basename dispatch fail-closed.
    original_argv = MODULE.sys.argv
    original_euid = MODULE.os.geteuid
    original_ensure = MODULE.ensure_root_directory
    try:
        MODULE.os.geteuid = lambda: 0
        MODULE.ensure_root_directory = lambda *_args: (_ for _ in ()).throw(AssertionError("filesystem mutation"))
        for basename in (
            "recover-vnext-011-to-014",
            "attest-vnext-011-to-014",
            "not-install-vnext",
        ):
            MODULE.sys.argv = [f"/tmp/{basename}"]
            assert MODULE.main() == 1
    finally:
        MODULE.sys.argv = original_argv
        MODULE.os.geteuid = original_euid
        MODULE.ensure_root_directory = original_ensure

    print("production cross-version crash/replay/receipt/rollback checks passed")


if __name__ == "__main__":
    main()
