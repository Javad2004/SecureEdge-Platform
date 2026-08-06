#!/usr/bin/env bash
set -Eeuo pipefail

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
DEV="$ROOT/.dev"
BIN="$DEV/bin"
mkdir -p "$BIN"
EDGE_CONFIG=${EDGEPROXY_CONFIG:-$ROOT/apps/edgeproxy/configs/local-dev.json}
SEC_CONFIG=${SECURITYEDGE_CONFIG:-$ROOT/apps/securityedge/configs/local-dev.json}
EDGE_ENV=${EDGEPROXY_ENV_FILE:-$ROOT/apps/edgeproxy/.env}
SEC_ENV=${SECURITYEDGE_ENV_FILE:-$ROOT/apps/securityedge/.env}
POLL_SECONDS=${POLL_SECONDS:-0.5}
DEBOUNCE_SECONDS=${DEBOUNCE_SECONDS:-0.75}
EDGE_PID=""
SEC_PID=""
EDGE_BINARY=""
SEC_BINARY=""
BEFORE=$(mktemp)
AFTER=$(mktemp)
CHANGES=$(mktemp)

log() { printf '[%s] %s\n' "$(date '+%H:%M:%S')" "$*"; }
stop_pid() {
  local pid=${1:-}
  [[ -z "$pid" ]] || ! kill -0 "$pid" 2>/dev/null || {
    kill "$pid" 2>/dev/null || true
    for _ in {1..50}; do kill -0 "$pid" 2>/dev/null || break; sleep 0.1; done
    kill -KILL "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  }
}
cleanup() {
  stop_pid "$SEC_PID"
  stop_pid "$EDGE_PID"
  local paths=("$BEFORE" "$AFTER" "$CHANGES")
  [[ -z "$EDGE_BINARY" ]] || paths+=("$EDGE_BINARY")
  [[ -z "$SEC_BINARY" ]] || paths+=("$SEC_BINARY")
  rm -f -- "${paths[@]}"
}
terminate() {
  trap - INT TERM
  exit 0
}
trap cleanup EXIT
trap terminate INT TERM

build_candidate() {
  local name=$1 app=$2 package=$3 key=$4
  local candidate="$BIN/${key}-$(date +%Y%m%d%H%M%S%N)-$$"
  log "Building $name candidate..." >&2
  if (cd "$app" && go build -trimpath -o "$candidate" "$package"); then
    printf '%s\n' "$candidate"
    return 0
  fi
  rm -f "$candidate"
  log "$name build failed; keeping the last healthy generation." >&2
  return 1
}

start_edge() {
  local binary=$1 args=(-config "$EDGE_CONFIG")
  [[ ! -f "$EDGE_ENV" ]] || args+=(-env "$EDGE_ENV")
  "$binary" "${args[@]}" & EDGE_PID=$!
  sleep 0.75
  if ! kill -0 "$EDGE_PID" 2>/dev/null; then
    wait "$EDGE_PID" 2>/dev/null || true
    EDGE_PID=""
    log "EdgeProxy candidate exited during the startup verification window." >&2
    return 1
  fi
  EDGE_BINARY=$binary
  log "EdgeProxy started with PID $EDGE_PID."
}
start_security() {
  local binary=$1 args=(-config "$SEC_CONFIG")
  [[ ! -f "$SEC_ENV" ]] || args+=(-env "$SEC_ENV")
  "$binary" "${args[@]}" & SEC_PID=$!
  sleep 0.75
  if ! kill -0 "$SEC_PID" 2>/dev/null; then
    wait "$SEC_PID" 2>/dev/null || true
    SEC_PID=""
    log "SecurityEdge candidate exited during the startup verification window." >&2
    return 1
  fi
  SEC_BINARY=$binary
  log "SecurityEdge started with PID $SEC_PID."
}
restart_edge() {
  local candidate old=$EDGE_BINARY
  candidate=$(build_candidate EdgeProxy "$ROOT/apps/edgeproxy" ./cmd/edgeproxy edgeproxy) || return 1
  stop_pid "$EDGE_PID"; EDGE_PID=""
  if start_edge "$candidate"; then
    [[ -z "$old" || "$old" == "$candidate" ]] || rm -f "$old"
    return 0
  fi
  rm -f "$candidate"
  if [[ -n "$old" ]] && start_edge "$old"; then
    log 'Previous EdgeProxy generation restored; watcher remains active.'
    return 0
  fi
  log 'EdgeProxy rollback failed; the watcher will retry on the next poll.' >&2
  return 1
}
restart_security() {
  local candidate old=$SEC_BINARY
  candidate=$(build_candidate SecurityEdge "$ROOT/apps/securityedge" ./cmd/securityedge securityedge) || return 1
  stop_pid "$SEC_PID"; SEC_PID=""
  if start_security "$candidate"; then
    [[ -z "$old" || "$old" == "$candidate" ]] || rm -f "$old"
    return 0
  fi
  rm -f "$candidate"
  if [[ -n "$old" ]] && start_security "$old"; then
    log 'Previous SecurityEdge generation restored; watcher remains active.'
    return 0
  fi
  log 'SecurityEdge rollback failed; the watcher will retry on the next poll.' >&2
  return 1
}

snapshot() {
  find "$ROOT" -type f \
    ! -path '*/.git/*' ! -path '*/.dev/*' ! -path '*/logs/*' ! -path '*/node_modules/*' ! -path '*/vendor/*' \
    ! -name '*.log' ! -name '*.tmp' ! -name '*.bak' ! -name '*.zip' ! -name '*.exe' ! -name '*~' \
    -printf '%P|%T@|%s\n' 2>/dev/null | LC_ALL=C sort
}

diff_snapshots() {
  awk -F'|' '
    NR==FNR { old[$1]=$2 FS $3; next }
    { seen[$1]=1; value=$2 FS $3; if (!($1 in old) || old[$1] != value) print $1 }
    END { for (path in old) if (!(path in seen)) print path }
  ' "$1" "$2" | LC_ALL=C sort -u
}

runtime_path() {
  local path=$1
  [[ "$path" == "${EDGE_CONFIG#$ROOT/}" || "$path" == "${EDGE_ENV#$ROOT/}" ||
     "$path" == "${SEC_CONFIG#$ROOT/}" || "$path" == "${SEC_ENV#$ROOT/}" ]]
}

EDGE_BINARY=$(build_candidate EdgeProxy "$ROOT/apps/edgeproxy" ./cmd/edgeproxy edgeproxy)
SEC_BINARY=$(build_candidate SecurityEdge "$ROOT/apps/securityedge" ./cmd/securityedge securityedge)
start_edge "$EDGE_BINARY"
start_security "$SEC_BINARY"
log 'Development watcher active. Active JSON/.env files use internal hot reload; source and embedded web assets are built as isolated generations before replacement.'
snapshot > "$BEFORE"

while :; do
  sleep "$POLL_SECONDS"
  snapshot > "$AFTER"
  diff_snapshots "$BEFORE" "$AFTER" > "$CHANGES"
  if [[ ! -s "$CHANGES" ]]; then
    if [[ -n "$EDGE_PID" ]] && ! kill -0 "$EDGE_PID" 2>/dev/null; then log 'EdgeProxy exited unexpectedly; rebuilding.'; restart_edge || log 'EdgeProxy restart failed; retrying on the next poll.' >&2; fi
    if [[ -n "$SEC_PID" ]] && ! kill -0 "$SEC_PID" 2>/dev/null; then log 'SecurityEdge exited unexpectedly; rebuilding.'; restart_security || log 'SecurityEdge restart failed; retrying on the next poll.' >&2; fi
    continue
  fi

  sleep "$DEBOUNCE_SECONDS"
  snapshot > "$AFTER"
  diff_snapshots "$BEFORE" "$AFTER" > "$CHANGES"
  cp "$AFTER" "$BEFORE"

  edge=0 security=0
  while IFS= read -r path; do
    [[ -n "$path" ]] || continue
    log "Changed: $path"
    if runtime_path "$path"; then
      log "Transactional runtime watcher will apply: $path"
      continue
    fi
    case "$path" in
      apps/edgeproxy/*) edge=1 ;;
      apps/securityedge/*) security=1 ;;
      integration/*.json|integration/*/*.json|go.work|go.work.sum|scripts/*|deployments/*) edge=1; security=1 ;;
    esac
  done < "$CHANGES"

  (( edge == 0 )) || restart_edge || log 'EdgeProxy restart failed; watcher remains active and will retry.' >&2
  (( security == 0 )) || restart_security || log 'SecurityEdge restart failed; watcher remains active and will retry.' >&2
done
