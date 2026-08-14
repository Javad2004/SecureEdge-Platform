#!/usr/bin/env python3
"""Validate production-only EdgeProxy routing guardrails from JSON on stdin."""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import sys
from urllib.parse import urlparse


def parse_bool(value: str) -> bool:
    normalized = value.strip().lower()
    if normalized == "true":
        return True
    if normalized == "false":
        return False
    raise argparse.ArgumentTypeError("expected true or false")


def canonical_host(raw: str) -> str:
    return raw.strip().lower().rstrip(".")


def is_demo_or_local_host(raw: str) -> bool:
    host = canonical_host(raw)
    if not host:
        return True
    if host in {
        "localhost",
        "localhost.localdomain",
        "127.0.0.1",
        "::1",
        "example.com",
        "example.net",
        "example.org",
        "example.invalid",
    }:
        return True
    return host.endswith((".localhost", ".local", ".test", ".invalid", ".example.com", ".example.net", ".example.org"))


def invalid_origin_address(raw: str) -> str | None:
    """Return a rejection reason for addresses that cannot be real Origins."""
    host = canonical_host(raw)
    if not host:
        return "missing hostname"
    if is_demo_or_local_host(host):
        return f"placeholder/local hostname {raw!r}"
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        if len(host) > 253:
            return f"hostname is too long: {raw!r}"
        labels = host.split(".")
        if any(
            not label
            or len(label) > 63
            or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label)
            for label in labels
        ):
            return f"invalid DNS hostname {raw!r}"
        return None
    if ip.is_loopback:
        return f"loopback address {ip}"
    if ip.is_unspecified:
        return f"unspecified address {ip}"
    if ip.is_multicast:
        return f"multicast address {ip}"
    if ip.is_link_local:
        return f"link-local address {ip}"
    return None


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

    routes = cfg.get("routes", [])
    if not isinstance(routes, list):
        print("production EdgeProxy profile rejected: routes must be an array", file=sys.stderr)
        return 1

    for route in routes:
        if not isinstance(route, dict):
            problems.append("route entry must be an object")
            continue
        route_name = str(route.get("name") or "<unnamed>")
        hosts = route.get("hosts", [])
        if not isinstance(hosts, list):
            problems.append(f"{route_name}: hosts must be an array")
            hosts = []
        for raw_host in hosts:
            host = str(raw_host)
            if not is_demo_or_local_host(host):
                real_hosts.append(host)

        upstreams = route.get("upstreams", [])
        if not isinstance(upstreams, list):
            problems.append(f"{route_name}: upstreams must be an array")
            continue
        for upstream in upstreams:
            if not isinstance(upstream, dict):
                problems.append(f"{route_name}: upstream entry must be an object")
                continue
            raw_url = str(upstream.get("url") or "").strip()
            try:
                parsed = urlparse(raw_url)
                # Accessing .port forces malformed/non-numeric/out-of-range ports
                # to raise ValueError instead of being silently accepted here.
                _ = parsed.port
            except ValueError as exc:
                problems.append(f"{route_name}: invalid Origin URL {raw_url!r}: {exc}")
                continue

            scheme = parsed.scheme.lower()
            hostname = parsed.hostname or ""
            if scheme not in {"http", "https"} or not hostname:
                problems.append(f"{route_name}: invalid Origin URL {raw_url!r}")
                continue
            if parsed.username is not None or parsed.password is not None:
                problems.append(f"{route_name}: Origin URL must not contain credentials: {raw_url}")
            if parsed.fragment:
                problems.append(f"{route_name}: Origin URL must not contain a fragment: {raw_url}")

            address_problem = invalid_origin_address(hostname)
            if address_problem is not None:
                # reject_loopback is retained as an explicit CLI contract for
                # callers, but production placeholders/unspecified/multicast
                # endpoints are never useful and are always rejected.
                if args.reject_loopback or "loopback" not in address_problem:
                    problems.append(f"{route_name}: invalid production Origin {raw_url}: {address_problem}")

            if args.require_https and scheme != "https":
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
