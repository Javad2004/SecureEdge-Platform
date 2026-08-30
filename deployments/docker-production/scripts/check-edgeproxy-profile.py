#!/usr/bin/env python3
"""Validate production-only EdgeProxy routing guardrails from JSON on stdin."""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import sys
from urllib.parse import urlparse


PRIVATE_VPN_NETWORKS = tuple(
    ipaddress.ip_network(raw)
    for raw in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "100.64.0.0/10",
        "fc00::/7",
    )
)


def is_private_vpn_address(address) -> bool:
    return any(address in network for network in PRIVATE_VPN_NETWORKS if address.version == network.version)


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
    # A literal Origin address must either be globally routable or belong to a
    # deployment-usable private/VPN range. Python 3.13 intentionally reports
    # documentation and benchmarking networks as non-global/private; accepting
    # those here would make production preflight approve an endpoint that cannot
    # be a real Origin.
    if not ip.is_global and not is_private_vpn_address(ip):
        return f"non-routable special-use address {ip}"
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
                port = parsed.port
            except ValueError as exc:
                problems.append(f"{route_name}: invalid Origin URL {raw_url!r}: {exc}")
                continue
            if parsed.netloc.endswith(":"):
                problems.append(f"{route_name}: Origin URL has ':' without a port: {raw_url}")
            if port == 0:
                problems.append(f"{route_name}: Origin URL port must be between 1 and 65535: {raw_url}")

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
