#!/usr/bin/env python3
"""Validate standalone-production service endpoint URLs."""

from __future__ import annotations

import argparse
import ipaddress
import re
import socket
from urllib.parse import urlparse


PLACEHOLDER_EXACT = {
    "localhost",
    "localhost.localdomain",
    "example.com",
    "example.net",
    "example.org",
    "example.invalid",
}
PLACEHOLDER_SUFFIXES = (
    ".localhost",
    ".local",
    ".test",
    ".invalid",
    ".example.com",
    ".example.net",
    ".example.org",
)


def canonical_dns_host(raw: str) -> str:
    host = raw.strip().lower().rstrip(".")
    try:
        return host.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError(f"invalid IDNA hostname {raw!r}: {exc}") from exc


def validate_dns_hostname(raw: str) -> str:
    host = canonical_dns_host(raw)
    if not host:
        raise ValueError("missing hostname")
    if len(host) > 253:
        raise ValueError(f"hostname is too long: {raw!r}")
    labels = host.split(".")
    if any(
        not label
        or len(label) > 63
        or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label)
        for label in labels
    ):
        raise ValueError(f"invalid DNS hostname {raw!r}")
    return host


def is_placeholder(host: str) -> bool:
    return host in PLACEHOLDER_EXACT or host.endswith(PLACEHOLDER_SUFFIXES)


def reject_nonroutable_ip(key: str, address) -> None:
    if address.is_loopback:
        raise ValueError(f"{key} points at container-local loopback address: {address}")
    if address.is_unspecified:
        raise ValueError(f"{key} points at an unspecified address: {address}")
    if address.is_multicast:
        raise ValueError(f"{key} points at a multicast address: {address}")
    if address.is_link_local:
        raise ValueError(f"{key} points at a link-local address: {address}")


def unsafe_private_admin(address) -> bool:
    return address.is_global or address.is_reserved


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--key", required=True)
    parser.add_argument("--value", required=True)
    parser.add_argument("--required-scheme", choices=("http", "https"), default="")
    parser.add_argument("--scope", choices=("any", "private"), default="any")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    raw = args.value.strip()
    if raw != args.value or any(ch.isspace() for ch in raw):
        raise SystemExit(f"{args.key} must not contain surrounding/embedded whitespace: {args.value!r}")

    try:
        parsed = urlparse(raw)
        port = parsed.port
    except ValueError as exc:
        raise SystemExit(f"{args.key} is not a valid URL: {exc}")

    if not parsed.scheme or not parsed.hostname:
        raise SystemExit(f"{args.key} must include scheme and hostname: {raw}")
    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"}:
        raise SystemExit(f"{args.key} must use http or https: {raw}")
    if args.required_scheme and scheme != args.required_scheme:
        raise SystemExit(f"{args.key} must use {args.required_scheme}: {raw}")
    if parsed.username is not None or parsed.password is not None:
        raise SystemExit(f"{args.key} must not embed credentials")
    if parsed.path not in ("", "/") or parsed.params or parsed.query or parsed.fragment:
        raise SystemExit(f"{args.key} must be an endpoint origin without path/query/fragment: {raw}")
    if parsed.netloc.endswith(":"):
        raise SystemExit(f"{args.key} has an explicit ':' without a port: {raw}")
    if port is not None and port == 0:
        raise SystemExit(f"{args.key} port must be between 1 and 65535: {raw}")

    raw_host = parsed.hostname
    try:
        address = ipaddress.ip_address(raw_host.rstrip("."))
    except ValueError:
        try:
            host = validate_dns_hostname(raw_host)
        except ValueError as exc:
            raise SystemExit(f"{args.key}: {exc}")
        if is_placeholder(host):
            raise SystemExit(f"{args.key} still contains a local/placeholder hostname: {host}")
        addresses = None
    else:
        try:
            reject_nonroutable_ip(args.key, address)
        except ValueError as exc:
            raise SystemExit(str(exc))
        host = str(address)
        addresses = {address}

    if args.scope == "private":
        if addresses is None:
            try:
                infos = socket.getaddrinfo(host, port or (443 if scheme == "https" else 80), type=socket.SOCK_STREAM)
            except socket.gaierror as exc:
                raise SystemExit(
                    f"{args.key} hostname must resolve during preflight for private/VPN HTTP validation: {host}: {exc}"
                )
            addresses = set()
            for info in infos:
                try:
                    resolved = ipaddress.ip_address(info[4][0])
                except ValueError:
                    continue
                try:
                    reject_nonroutable_ip(args.key, resolved)
                except ValueError as exc:
                    raise SystemExit(str(exc))
                addresses.add(resolved)
            if not addresses:
                raise SystemExit(f"{args.key} hostname resolved to no usable IP addresses: {host}")

        unsafe = sorted(str(address) for address in addresses if unsafe_private_admin(address))
        if unsafe:
            raise SystemExit(
                f"{args.key} HTTP Admin endpoint must stay on private/VPN addressing; unsafe address(es): {', '.join(unsafe)}"
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
