#!/usr/bin/env python3
"""Fail closed on secret-shaped files in a runtime image export or directory.

The scanner reports only the artifact path and rule name, never file contents.
"""
from __future__ import annotations

import argparse
import io
import re
import tarfile
import tempfile
from pathlib import Path

NAME_RULE = re.compile(r"(?:^|/)(?:rootkey\.csv|.*(?:private|secret|credential|token).*(?:\.pem|\.key|\.json|\.txt)?|.*\.key)$", re.I)
CONTENT_RULES = [
    re.compile(rb"-----BEGIN (?:RSA |EC |)?PRIVATE KEY-----"),
    re.compile(rb"AKIA[0-9A-Z]{16}"),
]


def suspicious(name: str, content: bytes) -> str | None:
    if NAME_RULE.search(name):
        return "sensitive-name"
    if any(rule.search(content) for rule in CONTENT_RULES):
        return "sensitive-content"
    return None


def scan_directory(root: Path) -> list[tuple[str, str]]:
    findings: list[tuple[str, str]] = []
    for path in root.rglob("*"):
        if path.is_file() and not path.is_symlink():
            rule = suspicious(path.relative_to(root).as_posix(), path.read_bytes())
            if rule:
                findings.append((path.relative_to(root).as_posix(), rule))
    return findings


def scan_tar(path: Path) -> list[tuple[str, str]]:
    findings: list[tuple[str, str]] = []
    with tarfile.open(path, "r:*") as archive:
        for member in archive:
            if not member.isfile():
                continue
            stream = archive.extractfile(member)
            content = b"" if stream is None else stream.read()
            rule = suspicious(member.name, content)
            if rule:
                findings.append((member.name, rule))
    return findings


def self_test() -> int:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        (root / "usr/bin").mkdir(parents=True)
        (root / "usr/bin/dtx-node").write_bytes(b"runtime binary")
        if scan_directory(root):
            return 1
        (root / "private-key.pem").write_bytes(b"-----BEGIN PRIVATE KEY-----\nsynthetic\n")
        if not scan_directory(root):
            return 1
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--root", type=Path)
    group.add_argument("--tar", type=Path)
    group.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        return self_test()
    findings = scan_directory(args.root) if args.root else scan_tar(args.tar)
    for name, rule in findings:
        print(f"runtime secret-artifact gate: {rule} at {name}")
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
