#!/usr/bin/env python3
"""Negative contract tests for the immutable stack bundle and host helpers."""

from __future__ import annotations

import importlib.machinery
import importlib.util
import sys
import tarfile
import tempfile
from pathlib import Path

REPOSITORY = Path(__file__).resolve().parent.parent
sys.dont_write_bytecode = True


def load_module(name: str, path: Path):  # type: ignore[no-untyped-def]
    loader = importlib.machinery.SourceFileLoader(name, str(path))
    specification = importlib.util.spec_from_loader(name, loader)
    if specification is None:
        raise RuntimeError(f"could not load test module: {path}")
    module = importlib.util.module_from_spec(specification)
    sys.modules[name] = module
    loader.exec_module(module)
    return module


def must_reject(action, label: str) -> None:  # type: ignore[no-untyped-def]
    try:
        action()
    except (RuntimeError, ValueError):
        return
    raise AssertionError(f"negative contract was accepted: {label}")


def main() -> int:
    builder = load_module("vnext_stack_bundle", REPOSITORY / "tools/vnext-stack-bundle.py")
    installer = load_module(
        "vnext_host_installer",
        REPOSITORY / "scripts/production-stack/host/install-vnext",
    )
    reader = load_module(
        "vnext_receipt_reader",
        REPOSITORY / "scripts/production-stack/host/read-vnext-receipt",
    )
    release = load_module("production_release", REPOSITORY / "tools/production-release.py")
    image = "dirextalk/vnet-server@sha256:" + "1" * 64
    migrator_image = "dirextalk/vnet-server@sha256:" + "2" * 64
    with tempfile.TemporaryDirectory() as temporary:
        atomic_path = Path(temporary) / "atomic-receipt.json"
        original_fchown = installer.os.fchown
        installer.os.fchown = lambda _descriptor, _uid, _gid: None
        try:
            installer.atomic_write(atomic_path, b"first\n")
            installer.atomic_write(atomic_path, b"second\n")
        finally:
            installer.os.fchown = original_fchown
        assert atomic_path.read_bytes() == b"second\n"
        assert atomic_path.stat().st_mode & 0o777 == 0o600

        bundle = Path(temporary) / "dirextalk-vnext.bundle"
        builder.build(REPOSITORY, bundle, "1.2.3", "a" * 40, image, migrator_image)
        bundle_raw = bundle.read_bytes()
        manifest, manifest_raw, _, _ = installer.validate_bundle(bundle_raw)
        request = {
            "schema": installer.REQUEST_SCHEMA,
            "schema_version": 1,
            "target": "linux-amd64",
            "domain": "x6-api.example.com",
            "version": "1.2.3",
            "source_commit": "a" * 40,
            "bundle_sha256": installer.digest(bundle_raw),
            "manifest_sha256": installer.digest(manifest_raw),
            "server_image": image,
            "migrator_image": migrator_image,
            "previous_receipt_sha256": None,
        }
        request_raw = installer.canonical(request)
        validated_request = installer.validate_request(request_raw)
        installer.request_matches_bundle(validated_request, manifest, manifest_raw)
        _, receipt_raw = installer.make_receipt(validated_request, "installed", None)
        installer.validate_receipt(receipt_raw)
        reader.validate(receipt_raw)

        mutable = dict(request)
        mutable["server_image"] = "dirextalk/vnet-server:latest"
        mutable["migrator_image"] = "dirextalk/vnet-server:latest"
        must_reject(
            lambda: installer.validate_request(installer.canonical(mutable)),
            "mutable latest request",
        )
        installer.validate_request(installer.canonical(request))
        incomplete = dict(request)
        del incomplete["manifest_sha256"]
        must_reject(
            lambda: installer.validate_request(installer.canonical(incomplete)),
            "incomplete request",
        )
        must_reject(
            lambda: installer.validate_request(request_raw.replace(b"\n", b" \n")),
            "noncanonical request",
        )
        corrupted_receipt = receipt_raw.replace(b'"state":"installed"', b'"state":"rolled_back"')
        must_reject(lambda: installer.validate_receipt(corrupted_receipt), "corrupt receipt hash")
        must_reject(lambda: reader.validate(corrupted_receipt), "reader corrupt receipt hash")

        malicious = Path(temporary) / "malicious.bundle"
        with tarfile.open(malicious, "w", format=tarfile.USTAR_FORMAT) as archive:
            info = tarfile.TarInfo(f"{installer.ARCHIVE_ROOT}/escape")
            info.type = tarfile.SYMTYPE
            info.linkname = "../../etc/passwd"
            archive.addfile(info)
        must_reject(
            lambda: installer.validate_bundle(malicious.read_bytes()),
            "archive symlink",
        )

        special = Path(temporary) / "special.bundle"
        with tarfile.open(special, "w", format=tarfile.USTAR_FORMAT) as archive:
            info = tarfile.TarInfo(f"{installer.ARCHIVE_ROOT}/device")
            info.type = tarfile.CHRTYPE
            archive.addfile(info)
        must_reject(
            lambda: installer.validate_bundle(special.read_bytes()),
            "archive special file",
        )

        release_input, input_raw = release.load_input(
            REPOSITORY / "docker/release/production-release.json", REPOSITORY
        )
        facts = release.make_facts(
            release_input,
            input_raw,
            "a" * 40,
            "sha256:" + "1" * 64,
            "sha256:" + "2" * 64,
            "sha256:" + "1" * 64,
        )
        facts_path = Path(temporary) / "release-facts.json"
        facts_path.write_bytes(release.canonical(facts))
        assert builder.load_release_facts(facts_path) == (
            "0.1.0",
            "a" * 40,
            image,
            migrator_image,
        )
    print("vNext stack bundle/host negative contract checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
