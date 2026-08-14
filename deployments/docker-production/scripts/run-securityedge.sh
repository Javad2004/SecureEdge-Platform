#!/bin/sh
set -eu

security_secret=${SECURITYEDGE_ADMIN_TOKEN_SECRET_FILE:-/run/secrets/securityedge_admin_token}
edge_secret=${EDGEPROXY_ADMIN_TOKEN_SECRET_FILE:-/run/secrets/edgeproxy_admin_token}

if [ ! -r "$security_secret" ]; then
  echo "securityedge: Dashboard/Admin token secret is not readable: $security_secret" >&2
  exit 78
fi
if [ ! -r "$edge_secret" ]; then
  echo "securityedge: EdgeProxy Admin token secret is not readable: $edge_secret" >&2
  exit 78
fi

SECURITYEDGE_ADMIN_TOKEN=$(cat "$security_secret")
EDGEPROXY_ADMIN_TOKEN=$(cat "$edge_secret")
if [ -z "$SECURITYEDGE_ADMIN_TOKEN" ] || [ -z "$EDGEPROXY_ADMIN_TOKEN" ]; then
  echo "securityedge: one or more required Admin token secrets are empty" >&2
  exit 78
fi
export SECURITYEDGE_ADMIN_TOKEN EDGEPROXY_ADMIN_TOKEN

exec /usr/local/bin/securityedge "$@"
