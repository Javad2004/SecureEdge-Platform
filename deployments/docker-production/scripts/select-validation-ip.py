#!/usr/bin/env python3
"""Select a free temporary IPv4 address for a one-off Compose validation container."""

from __future__ import annotations

import argparse
import ipaddress
import json
import sys
from typing import Any


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--subnet", required=True)
    parser.add_argument("--gateway", required=True)
    parser.add_argument("--reserved-ip", required=True)
    return parser.parse_args()


def container_addresses(payload: Any) -> set[ipaddress.IPv4Address]:
    addresses: set[ipaddress.IPv4Address] = set()
    if not isinstance(payload, list):
        return addresses
    for network in payload:
        if not isinstance(network, dict):
            continue
        containers = network.get("Containers")
        if not isinstance(containers, dict):
            continue
        for container in containers.values():
            if not isinstance(container, dict):
                continue
            raw = str(container.get("IPv4Address", "")).split("/", 1)[0].strip()
            if not raw:
                continue
            try:
                address = ipaddress.ip_address(raw)
            except ValueError:
                continue
            if isinstance(address, ipaddress.IPv4Address):
                addresses.add(address)
    return addresses


def main() -> int:
    args = parse_args()
    subnet = ipaddress.ip_network(args.subnet, strict=True)
    gateway = ipaddress.ip_address(args.gateway)
    reserved_ip = ipaddress.ip_address(args.reserved_ip)
    if not isinstance(subnet, ipaddress.IPv4Network):
        raise SystemExit("validation network must be IPv4")
    if not isinstance(gateway, ipaddress.IPv4Address) or gateway not in subnet:
        raise SystemExit(f"gateway {gateway} is outside {subnet}")
    if not isinstance(reserved_ip, ipaddress.IPv4Address) or reserved_ip not in subnet:
        raise SystemExit(f"reserved SecurityEdge address {reserved_ip} is outside {subnet}")

    raw = sys.stdin.read().strip()
    if raw:
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise SystemExit(f"invalid Docker network inspection JSON: {exc}") from exc
    else:
        payload = []

    occupied = container_addresses(payload)
    occupied.update({gateway, reserved_ip, subnet.network_address, subnet.broadcast_address})

    # Prefer high addresses so ordinary Docker dynamic allocation, which tends
    # to start near the beginning of the pool, is unlikely to race this
    # short-lived validation container. Scan at most the complete subnet; this
    # helper is used only after doctor.sh has accepted the production network.
    first = int(subnet.network_address) + 1
    last = int(subnet.broadcast_address) - 1
    for value in range(last, first - 1, -1):
        candidate = ipaddress.IPv4Address(value)
        if candidate not in occupied:
            print(candidate)
            return 0
    raise SystemExit(f"no free temporary IPv4 address is available in {subnet}")


if __name__ == "__main__":
    raise SystemExit(main())
