#!/usr/bin/env python3
"""Fail closed on secret-shaped files in an exported runtime image/rootfs.

Use ``--root PATH`` for an exact exported rootfs directory or ``--tar PATH``
for an exact tar archive.  The scanner reports only artifact paths and rule
names; it never prints file contents or matched secret values.
"""
from __future__ import annotations

import argparse
import io
import re
import tarfile
import tempfile
from pathlib import Path
from pathlib import PurePosixPath

NAME_RULE = re.compile(
    r"(?:^|/)(?:"
    r"rootkey\.csv|"
    r".*(?:private|secret|credential|token|authorization|enrollment|"
    r"client[-_.]?binding|connector[-_.]?(?:bearer|handoff|config|log)|"
    r"mcp[-_.]?bearer|handoff).*|"
    r".*\.(?:key|pem|bearer|handoff|token|secret|credentials?|env|log)"
    r")$",
    re.I,
)
CONTENT_RULES = [
    re.compile(rb"-----BEGIN (?:RSA |EC |)?PRIVATE KEY-----"),
    re.compile(rb"(?:AKIA|ASIA)[0-9A-Z]{16}"),
    re.compile(rb"(?i)aws[_-]?(?:access[_-]?key[_-]?id|secret[_-]?access[_-]?key)\s*[\"']?\s*[=:]\s*[\"']?[^\s,}\"']+"),
    re.compile(rb"(?i)(?:x[-_]dirextalk[-_]client[-_]binding[-_]authorization|client[-_]?binding[-_]?authorization|enrollment[_-]?token|binding[_-]?authorization)\s*[\"']?\s*[=:]\s*[\"']?[^\s,}\"']+"),
    re.compile(rb"(?i)(?:connector[-_ ]?(?:bearer|handoff|config|log)|mcp[-_]?bearer|connector[-_]?enrollment)\s*[\"']?\s*[=:]\s*[\"']?[^\s,}\"']+"),
    re.compile(rb"(?i)\bdtxi1[a-z0-9]{20,}\b"),
]


def suspicious(name: str, content: bytes) -> str | None:
    if NAME_RULE.search(name):
        return "sensitive-name"
    if any(rule.search(content) for rule in CONTENT_RULES):
        return "sensitive-content"
    return None


def scan_directory(root: Path) -> list[tuple[str, str]]:
    if root.is_symlink() or not root.is_dir():
        raise ValueError("root export must be a regular directory")
    findings: list[tuple[str, str]] = []
    try:
        paths = list(root.rglob("*"))
    except OSError as error:
        raise ValueError("root export cannot be enumerated") from error
    for path in paths:
        if path.is_symlink():
            continue
        if path.is_file():
            try:
                content = path.read_bytes()
            except OSError as error:
                raise ValueError("root export contains an unreadable file") from error
            relative = path.relative_to(root).as_posix()
            rule = suspicious(relative, content)
            if rule:
                findings.append((relative, rule))
    return findings


def scan_tar(path: Path) -> list[tuple[str, str]]:
    if path.is_symlink() or not path.is_file():
        raise ValueError("tar export must be a regular file")
    findings: list[tuple[str, str]] = []
    try:
        with tarfile.open(path, "r:*") as archive:
            seen: set[str] = set()
            for member in archive:
                name = member.name.rstrip("/")
                relative = PurePosixPath(name)
                if not name or relative.is_absolute() or ".." in relative.parts or name in seen:
                    raise ValueError("tar export contains an unsafe member")
                seen.add(name)
                if member.isdir():
                    continue
                if member.issym() or member.islnk():
                    target = PurePosixPath(member.linkname)
                    if ".." in target.parts or not member.linkname:
                        raise ValueError("tar export contains an unsafe link")
                    continue
                if not member.isfile():
                    raise ValueError("tar export contains an unsupported member")
                stream = archive.extractfile(member)
                if stream is None:
                    raise ValueError("tar export contains an unreadable file")
                content = stream.read()
                rule = suspicious(name, content)
                if rule:
                    findings.append((name, rule))
    except (OSError, tarfile.TarError) as error:
        raise ValueError("tar export cannot be read") from error
    return findings


def self_test() -> int:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        (root / "usr/bin").mkdir(parents=True)
        (root / "usr/bin/dtx-node").write_bytes(b"runtime binary")
        if scan_directory(root):
            return 1
        fixtures = {
            "blob-a": b"-----BEGIN PRIVATE KEY-----\nsynthetic\n",
            "blob-b": b'{"aws_secret_access_key":"synthetic-secret"}',
            "blob-c": b'{"client_binding_authorization":"synthetic"}',
            "blob-d": b'{"connector_bearer":"synthetic"}',
            "blob-e": b"dtxi1eci4tbb6kk5wk4vwv5ckekifwqtxy7bdd5vbmd7vac45r5xwu4la",
        }
        for name, content in fixtures.items():
            target = root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content)
        findings = scan_directory(root)
        if len(findings) < len(fixtures):
            return 1
        archive_path = root / "runtime.tar"
        with tarfile.open(archive_path, "w") as archive:
            for name, content in fixtures.items():
                info = tarfile.TarInfo(name)
                info.size = len(content)
                archive.addfile(info, io.BytesIO(content))
            safe_link = tarfile.TarInfo("safe-link")
            safe_link.type = tarfile.SYMTYPE
            safe_link.linkname = "blob-a"
            archive.addfile(safe_link)
            absolute_link = tarfile.TarInfo("absolute-link")
            absolute_link.type = tarfile.SYMTYPE
            absolute_link.linkname = "/usr/bin/dtx-node"
            archive.addfile(absolute_link)
            safe_hardlink = tarfile.TarInfo("safe-hardlink")
            safe_hardlink.type = tarfile.LNKTYPE
            safe_hardlink.linkname = "blob-a"
            archive.addfile(safe_hardlink)
        if len(scan_tar(archive_path)) < len(fixtures):
            return 1
        unsafe_path = root / "unsafe.tar"
        with tarfile.open(unsafe_path, "w") as archive:
            info = tarfile.TarInfo("unsafe-link")
            info.type = tarfile.SYMTYPE
            info.linkname = "../../etc/passwd"
            archive.addfile(info)
        try:
            scan_tar(unsafe_path)
        except ValueError:
            pass
        else:
            return 1
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Scan an exact exported runtime rootfs directory or tar archive without printing secret values.",
        epilog="Examples: check-runtime-secret-artifacts.py --root ./rootfs; check-runtime-secret-artifacts.py --tar ./runtime.tar",
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--root", type=Path)
    group.add_argument("--tar", type=Path)
    group.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        return self_test()
    try:
        findings = scan_directory(args.root) if args.root else scan_tar(args.tar)
    except (OSError, ValueError):
        print("runtime secret-artifact gate: rejected unreadable or unsupported export")
        return 2
    for name, rule in findings:
        print(f"runtime secret-artifact gate: {rule} at {name}")
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
