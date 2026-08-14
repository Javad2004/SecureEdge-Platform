#!/bin/sh
set -eu

secret_file=${EDGEPROXY_ADMIN_TOKEN_SECRET_FILE:-/run/secrets/edgeproxy_admin_token}
if [ ! -r "$secret_file" ]; then
  echo "edgeproxy: Admin token secret is not readable: $secret_file" >&2
  exit 78
fi
EDGEPROXY_ADMIN_TOKEN=$(cat "$secret_file")
if [ -z "$EDGEPROXY_ADMIN_TOKEN" ]; then
  echo "edgeproxy: Admin token secret is empty" >&2
  exit 78
fi
export EDGEPROXY_ADMIN_TOKEN

exec /usr/local/bin/edgeproxy "$@"
