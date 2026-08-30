#!/usr/bin/env python3
"""Validate an Admin Bearer credential from stdin using the Go runtime contract."""

from __future__ import annotations

import argparse
import sys
import unicodedata

MAX_BEARER_CREDENTIAL_BYTES = 8192
RESERVED_SECRET_MARKER = "[REDACTED]"

# Go strings.TrimSpace uses unicode.IsSpace. Python str.strip()/isspace() also
# treats the C0 information separators U+001C..U+001F as whitespace, while Go
# does not. Keep the exact Go White_Space set here so production preflight and
# application normalization cannot disagree on a secret at the boundary.
GO_TRIM_SPACE = frozenset(
    "\t\n\v\f\r "
    "\u0085\u00a0\u1680"
    "\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a"
    "\u2028\u2029\u202f\u205f\u3000"
)


def trim_go_space(value: str) -> str:
    start = 0
    end = len(value)
    while start < end and value[start] in GO_TRIM_SPACE:
        start += 1
    while end > start and value[end - 1] in GO_TRIM_SPACE:
        end -= 1
    return value[start:end]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--label", required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    raw = sys.stdin.buffer.read()
    try:
        value = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise SystemExit(f"{args.label} secret must be valid UTF-8")

    token = trim_go_space(value)
    if not token:
        raise SystemExit(f"{args.label} secret is empty after whitespace normalization")
    if token == RESERVED_SECRET_MARKER:
        raise SystemExit(f"{args.label} secret cannot use the reserved [REDACTED] secret marker")
    if len(token.encode("utf-8")) > MAX_BEARER_CREDENTIAL_BYTES:
        raise SystemExit(f"{args.label} secret cannot exceed 8192 UTF-8 bytes")
    if any(unicodedata.category(ch) == "Cc" or ch.isspace() for ch in token):
        raise SystemExit(f"{args.label} secret cannot contain embedded whitespace or control characters")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
