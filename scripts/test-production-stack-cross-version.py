#!/usr/bin/env python3
"""Deterministic contract tests for the 0.1.1 -> 0.1.4 production update path."""

from __future__ import annotations

import importlib.machinery
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MODULE = importlib.machinery.SourceFileLoader(
    "install_vnext_contract", str(ROOT / "scripts/production-stack/host/install-vnext")
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

    print("production cross-version crash/replay/receipt/rollback checks passed")


if __name__ == "__main__":
    main()
