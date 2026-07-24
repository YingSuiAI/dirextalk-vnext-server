#!/usr/bin/env python3
"""Validate the closed production image repository/digest contract."""

from __future__ import annotations

import re
import sys
from ipaddress import ip_address, ip_network
from pathlib import Path

DIGEST = r"sha256:[0-9a-f]{64}"
PATTERNS = {
    "DTX_SERVER_IMAGE": re.compile(rf"dirextalk/vnet-server@{DIGEST}"),
    "DTX_MIGRATOR_IMAGE": re.compile(rf"dirextalk/vnet-server@{DIGEST}"),
    "DTX_POSTGRES_IMAGE": re.compile(rf"postgres@{DIGEST}"),
    "DTX_CADDY_IMAGE": re.compile(rf"caddy@{DIGEST}"),
    "DTX_PROBE_IMAGE": re.compile(rf"curlimages/curl@{DIGEST}"),
}


def parse(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise ValueError(f"line {number} is not KEY=VALUE")
        key, value = line.split("=", 1)
        if key in values:
            raise ValueError(f"duplicate key: {key}")
        values[key] = value
    return values


def validate(values: dict[str, str]) -> None:
    for key, pattern in PATTERNS.items():
        value = values.get(key)
        if value is None or pattern.fullmatch(value) is None:
            raise ValueError(f"{key} is not an approved repository@digest reference")
        if "latest" in value:
            raise ValueError(f"{key} may not execute a discovery tag")
    try:
        bind = ip_address(values["DTX_AGENT_CONTROL_BIND"])
    except (KeyError, ValueError) as error:
        raise ValueError("DTX_AGENT_CONTROL_BIND must be an IPv4 address") from error
    private_v4 = (
        ip_network("10.0.0.0/8"),
        ip_network("172.16.0.0/12"),
        ip_network("192.168.0.0/16"),
    )
    if bind.version != 4 or not any(bind in network for network in private_v4):
        raise ValueError("DTX_AGENT_CONTROL_BIND must be an RFC1918 host/VPC address")


def self_test() -> None:
    digest = "sha256:" + "1" * 64
    valid = {
        "DTX_SERVER_IMAGE": f"dirextalk/vnet-server@{digest}",
        "DTX_MIGRATOR_IMAGE": f"dirextalk/vnet-server@{digest}",
        "DTX_POSTGRES_IMAGE": f"postgres@{digest}",
        "DTX_CADDY_IMAGE": f"caddy@{digest}",
        "DTX_PROBE_IMAGE": f"curlimages/curl@{digest}",
        "DTX_AGENT_CONTROL_BIND": "10.0.0.6",
    }
    validate(valid)
    negatives = [
        ("DTX_SERVER_IMAGE", f"other/server@{digest}"),
        ("DTX_SERVER_IMAGE", f"dirextalk/vnet-server:latest@{digest}"),
        ("DTX_MIGRATOR_IMAGE", "dirextalk/vnet-server:immutable"),
        ("DTX_POSTGRES_IMAGE", f"other/postgres@{digest}"),
        ("DTX_CADDY_IMAGE", "caddy:latest"),
        ("DTX_PROBE_IMAGE", f"busybox@{digest}"),
        ("DTX_AGENT_CONTROL_BIND", "0.0.0.0"),
        ("DTX_AGENT_CONTROL_BIND", "127.0.0.1"),
    ]
    for key, bad in negatives:
        candidate = dict(valid)
        candidate[key] = bad
        try:
            validate(candidate)
        except ValueError:
            continue
        raise AssertionError(f"negative image reference accepted: {key}={bad}")


def main(argv: list[str]) -> int:
    if argv == ["--self-test"]:
        self_test()
        return 0
    if len(argv) != 1:
        print("usage: validate-production-images.py <environment-file>", file=sys.stderr)
        return 2
    try:
        validate(parse(Path(argv[0])))
    except (OSError, UnicodeError, ValueError) as error:
        print(f"production image validation failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
