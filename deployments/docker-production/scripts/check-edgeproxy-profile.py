#!/usr/bin/env python3
"""Validate production-only EdgeProxy routing guardrails from JSON on stdin."""

from __future__ import annotations

import argparse
import ipaddress
import json
import sys
from urllib.parse import urlparse


def parse_bool(value: str) -> bool:
    normalized = value.strip().lower()
    if normalized == "true":
        return True
    if normalized == "false":
        return False
    raise argparse.ArgumentTypeError("expected true or false")


def is_demo_or_local_host(raw: str) -> bool:
    host = raw.strip().lower().rstrip(".")
    if not host:
        return True
    if host in {"localhost", "localhost.localdomain", "127.0.0.1", "::1", "example.com", "example.net", "example.org", "example.invalid"}:
        return True
    return host.endswith((".local", ".test", ".invalid", ".example.com", ".example.net", ".example.org"))


def is_loopback_hostname(raw: str) -> bool:
    host = raw.strip().lower()
    if host in {"localhost", "localhost.localdomain"}:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--require-https", type=parse_bool, required=True)
    parser.add_argument("--allow-insecure", type=parse_bool, required=True)
    parser.add_argument("--require-real-hosts", type=parse_bool, required=True)
    parser.add_argument("--reject-loopback", type=parse_bool, required=True)
    args = parser.parse_args()

    try:
        cfg = json.load(sys.stdin)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        print(f"invalid EdgeProxy JSON: {exc}", file=sys.stderr)
        return 2

    problems: list[str] = []
    real_hosts: list[str] = []

    for route in cfg.get("routes", []):
        route_name = str(route.get("name") or "<unnamed>")
        for raw_host in route.get("hosts", []):
            host = str(raw_host)
            if not is_demo_or_local_host(host):
                real_hosts.append(host)

        for upstream in route.get("upstreams", []):
            raw_url = str(upstream.get("url") or "").strip()
            parsed = urlparse(raw_url)
            hostname = (parsed.hostname or "").strip()
            if args.reject_loopback and is_loopback_hostname(hostname):
                problems.append(f"{route_name}: loopback Origin {raw_url}")
            if args.require_https and parsed.scheme.lower() != "https":
                problems.append(f"{route_name}: Origin must use https: {raw_url}")
            if not args.allow_insecure and bool(upstream.get("insecure_skip_verify", False)):
                problems.append(
                    f"{route_name}: insecure_skip_verify must remain false for production Origin {raw_url}"
                )

    if args.require_real_hosts and not real_hosts:
        problems.append(
            "no non-demo route host is configured; replace .test/.local/localhost hosts "
            "with the real production hostname"
        )

    if problems:
        print("production EdgeProxy profile rejected: " + "; ".join(problems), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
