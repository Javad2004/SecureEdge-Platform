# SecurityEdge

SecurityEdge is the independent Phase 3 and Phase 4 implementation of the shared EdgeProxy bachelor project.

- **Phase 3:** application-layer WAF, protocol validation, hierarchical traffic protection, temporary auto-ban, privacy-preserving security telemetry.
- **Phase 4:** authenticated operations dashboard, policy management, SecurityEdge metrics/logs, and a backend-for-frontend for the EdgeProxy Admin API.

The uploaded EdgeProxy project is not modified. The active deployment is **standalone non-embedded gateway mode**.

## Real three-device topology

```text
Phone / Client
    |
    | DNS: project.test -> 10.36.74.241
    v
Technitium DNS on Proxy device :53
    |
    v
SecurityEdge on Proxy device 0.0.0.0:80
    |
    v
EdgeProxy on the same device 127.0.0.1:8080
    |
    v
Origin device 10.36.74.43:9000
```

Expected management bindings:

```text
EdgeProxy Admin       127.0.0.1:9090
SecurityEdge Admin    127.0.0.1:9191
```

The Origin Windows Firewall allows TCP/9000 only from Proxy IP `10.36.74.241`. The phone can reach only DNS and SecurityEdge public HTTP; it cannot directly reach EdgeProxy, either Admin listener, or Origin.

## Security pipeline

```text
request ID and trusted client-IP resolution
  -> global/per-client concurrency admission
  -> request shape and protocol limits
  -> allowlist / temporary-ban / denylist / method policy
  -> route-wide global token bucket
  -> route+client token bucket
  -> bounded normalized WAF inspection
  -> fail-closed inspection limit policy
  -> anomaly score and block/log/off decision
  -> allowed request forwarded to EdgeProxy
  -> cache, origin health, and reverse proxy logic remain in EdgeProxy
```

## Professional security controls

- 32 built-in deterministic RE2 rules covering SQLi, XSS, traversal, sensitive-file probes, command injection, SSRF, XXE, NoSQLi, LDAP injection, CRLF, template injection, Log4Shell/JNDI, PHP wrappers, null bytes, scanner/exploit markers, open redirect, and cookie injection.
- Validated custom rules with unique IDs, selected targets, score, category, description, and RE2-safe patterns.
- Multi-stage URL decoding, HTML entity decoding, UTF-8 normalization, query decomposition, JSON flattening, form parsing, header inspection, and cookie inspection.
- Bounded body reading and restoration; optional fail-closed behavior when the inspection prefix is exceeded.
- Optional rejection of compressed/encoded bodies and unsupported body content types.
- Per-route block/log/off modes, anomaly thresholds, disabled rules, excluded paths, allowlists, and denylists.
- Hierarchical token buckets: global per-route limits plus per-client/per-route limits.
- Bounded rate-limit state, idle cleanup, global and per-client bursts, and `Retry-After` responses.
- Non-blocking global and per-client concurrency limits.
- Adaptive temporary bans after repeated WAF blocks, rate limits, or overload decisions.
- Trusted-proxy-aware client-IP resolution that prevents untrusted `X-Forwarded-For` spoofing.
- HTTP server, upstream transport, header, path, query, body, and graceful-shutdown limits.
- Privacy-preserving logs: raw request bodies, query values, cookies, authorization headers, suspicious paths, and User-Agent strings are not retained. Suspicious values use SHA-256 fingerprints.
- Bounded in-memory log ring plus optional rotating NDJSON persistence.
- Security metrics schema 2.0, percentile latency, per-route dimensions, rejection reasons, and Prometheus exposition.
- Constant-time bearer-token comparison, admin brute-force lockout, strict JSON decoding, CSP, and audit events.
- Atomic configuration persistence with validation, temporary file sync, rollback staging, and hot reload.
- Build/version metadata and `-version` CLI support.

## Dashboard and Admin API

The dashboard is served from `http://127.0.0.1:9191` and combines:

- SecurityEdge overview, WAF detections, rejected requests, reasons, latency, rule/category counters.
- Global/per-client rate-limit and concurrency state.
- Temporary-ban listing/removal/clear operations.
- Filtered cursor-paginated security events and CSV/NDJSON export.
- Prometheus export.
- Complete default and per-route policy editor.
- EdgeProxy route readiness, origin health, cache entries/bytes/evictions, request/cache/latency metrics, access logs, and cache purge.

The EdgeProxy Admin token stays in the SecurityEdge backend and is never exposed to browser JavaScript.

## Run on the actual network

### Origin device

```powershell
go run ./cmd/origin-demo -listen 0.0.0.0:9000 -name origin-a
```

### Proxy device — EdgeProxy repository

```powershell
go run ./cmd/edgeproxy `
  -config ..\edgeproxy-go-second-member-professional-final\integration\edgeproxy-behind-waf.json `
  -pretty-logs
```

### Proxy device — this repository

```powershell
go run ./cmd/securityedge `
  -config .\configs\securityedge.json `
  -pretty-logs
```

Or:

```powershell
.\scripts\start-security.ps1
```

### Phone

```text
http://project.test
```

The phone's DNS server must be `10.36.74.241`, Private DNS must not bypass Technitium during the test, and the Technitium A records must point `project.test` and `www.project.test` to `10.36.74.241`.

## Secrets

Demo tokens exist only to make the academic network test reproducible. Replace them for presentation or deployment:

```powershell
$env:SECURITYEDGE_ADMIN_TOKEN = .\scripts\generate-admin-token.ps1
$env:EDGEPROXY_ADMIN_TOKEN = "the-token-used-by-edgeproxy"
```

Environment overrides are used in memory and are not written into the JSON file when policies are saved.

## Validation

```powershell
gofmt -w .
go test ./...
go test -race ./...
go vet ./...
node --check .\internal\admin\web\app.js
go build -trimpath ./cmd/securityedge
go run ./cmd/securityedge -config .\configs\securityedge.json -validate
go run ./cmd/securityedge -version
```

Network scripts:

```powershell
.\scripts\check-listeners.ps1
.\scripts\test-current-network.ps1
.\scripts\test-protection.ps1
```
## Scope statement

SecurityEdge provides strong **application-layer DoS/DDoS mitigation** for this project through global/per-client rate limiting, bounded state, admission control, request limits, timeouts, and temporary bans. It does not claim to absorb network-layer volumetric attacks such as SYN floods, UDP floods, DNS floods, or bandwidth saturation; those require operating-system/network firewalling and upstream DDoS infrastructure.

The optional embedded config and patch are retained for future study only and are not used in the current run.
