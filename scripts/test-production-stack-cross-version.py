#!/usr/bin/env python3
"""Deterministic contract tests for the 0.1.1 -> 0.1.4 production update path."""

from __future__ import annotations

import importlib.machinery
import inspect
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

    # Crash recovery: a candidate receipt may already be authenticated in the
    # history directory while current.json still points at the prior release.
    original_root = MODULE.RECEIPT_ROOT
    original_read = MODULE.read_secure
    try:
        with tempfile.TemporaryDirectory() as directory:
            MODULE.RECEIPT_ROOT = Path(directory)
            history = MODULE.RECEIPT_ROOT / f"{receipt['receipt_sha256']}.json"
            history.write_bytes(raw)
            MODULE.read_secure = lambda path, _mode, _limit: Path(path).read_bytes()
            recovered = MODULE.find_candidate_receipt(request)
            assert recovered is not None and recovered[0]["receipt_sha256"] == receipt["receipt_sha256"]
    finally:
        MODULE.RECEIPT_ROOT = original_root
        MODULE.read_secure = original_read

    # A crash after publishing the candidate receipt is a no-op on replay;
    # a chained rolled-back receipt remains a recoverable prior shape.
    rolled_back, rolled_back_raw = MODULE.make_receipt(
        prior, "rolled_back", request["previous_receipt_sha256"]
    )
    assert MODULE.validate_receipt(rolled_back_raw)["state"] == "rolled_back"
    assert rolled_back["previous_receipt_sha256"] == request["previous_receipt_sha256"]

    source = inspect.getsource(MODULE.install_code_only_rollback)
    assert "--no-deps" in source
    assert "migrate" in source and "down" in source
    assert "invoke_fixed_installer" not in source
    assert "--volumes" not in source and "down -v" not in source

    update = (ROOT / "scripts/production-stack/update.sh").read_text()
    assert "candidate_version" in update and "strictly forward" in update
    assert "--no-deps dtx-node realtime-gateway agent-control caddy" in update
    assert "down -v" not in update and "down --volumes" not in update
    print("production cross-version crash/replay/receipt/rollback checks passed")


if __name__ == "__main__":
    main()
