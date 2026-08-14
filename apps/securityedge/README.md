# SecurityEdge

SecurityEdge is the application-security gateway and operations component of the [SecureEdge Platform](../../README.md). It runs in front of [EdgeProxy](../edgeproxy/README.md), inspects incoming HTTP or HTTPS requests, enforces traffic policies, records security telemetry, and exposes an authenticated dashboard and Admin API.

This README assumes commands are executed from:

```text
apps/securityedge
```

The active deployment mode is **standalone non-embedded gateway mode**. EdgeProxy remains an independently executable application; SecurityEdge does not embed EdgeProxy into its own process.

## Architecture

```text
HTTP/HTTPS client
    │
    │ public request
    ▼
SecurityEdge ingress
    │  optional native TLS termination (TLS 1.2+)
    │  WAF inspection
    │  request-size and protocol controls
    │  per-client and global rate limiting
    │  concurrency admission and temporary bans
    ▼
EdgeProxy loopback data plane
    │  routing, cache, origin selection, retries
    ▼
Application origin
```

SecurityEdge also calls the EdgeProxy Admin API over loopback to obtain routes, origin health, cache metrics, access logs, and readiness information for its operations dashboard.

The gateway path also preserves validated HTTP/1.1 protocol upgrades end-to-end. WebSocket-style traffic passes through the standard SecurityEdge reverse proxy and the EdgeProxy upgrade tunnel while still receiving the initial WAF, routing, admission, and trusted-client checks. WAF inspection applies to the HTTP upgrade handshake; after a successful switch, application-protocol frames are tunneled as opaque bytes rather than reinterpreted as HTTP requests. Once a `101 Switching Protocols` handshake succeeds, the switched connection is treated as a long-lived bidirectional stream rather than a cacheable HTTP response. SecurityEdge clears any HTTP server read/write deadline from its hijacked client connection so handshake timeouts cannot terminate an otherwise healthy long-lived tunnel. SecurityEdge tracks the connection explicitly, records the `101` decision correctly, and closes active upgraded tunnels when its managed generation is retired so a client cannot remain attached to obsolete WAF or routing state; clients should reconnect after an automatic restart.

## Main capabilities

### Web Application Firewall

- deterministic RE2-based rules;
- configurable anomaly scoring;
- `block`, `log`, and `off` policy modes;
- route-specific and default policies;
- path, query, header, cookie, JSON, form, XML, and text-body inspection;
- multi-stage URL and HTML-entity normalization;
- SQL injection, XSS, path traversal, command injection, SSRF, XXE, NoSQL injection, LDAP injection, CRLF injection, template injection, Log4Shell/JNDI, PHP wrapper, sensitive-file, scanner, and reconnaissance detection;
- validated custom rules;
- method, path, query, header, content-type, content-encoding, and body-size limits; repeated header field lines count individually, and all accepted repeated header and raw Cookie fields remain inspectable by the WAF;
- IP allowlists and denylists;
- bounded inspection and fail-closed options.

### Native HTTPS/TLS ingress

- optional native TLS termination on the standalone SecurityEdge gateway listener;
- certificate-chain and private-key paths are configured under `server.tls`;
- TLS-enabled listeners enforce a minimum protocol version of TLS 1.2;
- certificate/key material is loaded before the public listener is committed to a generation;
- TLS enablement, certificate paths, and key paths are restart-required settings handled by the managed graceful-generation supervisor;
- restart preflight revalidates the configured certificate/key pair before draining the healthy generation, including when the TLS file paths themselves did not change;
- embedded mode rejects `server.tls.enabled=true` because it has no independent SecurityEdge listener.

Native TLS is optional. Local-development, LAN-reference, and Compose profiles remain HTTP by default, while the checked-in systemd production profile demonstrates direct HTTPS on port `443`. A trusted external load balancer, CDN, or reverse proxy can still terminate TLS instead when that is the desired deployment boundary.

### HTTP flood and overload protection

- per-client token-bucket rate limits;
- route-wide global rate limits, with global/client rejection counters derived from the limiter decision scope even when bounded bucket capacity is exhausted;
- global and per-client concurrency limits;
- bounded limiter state;
- adaptive temporary bans;
- trusted-proxy-aware client IP resolution and verified propagation to EdgeProxy and the Origin;
- spoof-resistant forwarded-address handling;
- upstream and server timeouts.

SecurityEdge provides application-layer HTTP protection. SYN floods, UDP floods, link saturation, and other volumetric network-layer attacks require firewall, CDN, load-balancer, or provider-side controls.

### Operations and observability

- responsive authenticated dashboard;
- SecurityEdge JSON metrics and Prometheus exposition, including the full scalar outcome/protection counter set and global/client rate-limit attribution;
- WAF and admission-control event browsing;
- recent privacy-safe client traffic telemetry;
- bounded, atomically persisted request-rate and Route/Origin telemetry history;
- dependency monitoring for DNS, SecurityEdge ingress, EdgeProxy data plane, EdgeProxy Admin API, route readiness, and Origin health;
- EdgeProxy metrics, logs, cache purge, transactional configuration, Route/Origin CRUD, and watcher status through an authenticated backend-for-frontend;
- policy editing with validation and atomic persistence;
- temporary-ban management;
- CSV and NDJSON event exports;
- bounded dependency transition history;
- bounded metric labels, with nonstandard or extension HTTP methods aggregated under `OTHER`.

## Configuration profiles

| Configuration | SecurityEdge ingress | TLS | EdgeProxy profile | Purpose |
|---|---:|---|---|---|
| `configs/local-dev.json` | `127.0.0.1:8081` | off | `../../integration/edgeproxy-local-behind-waf.json` | Local integrated development |
| `configs/securityedge.json` | `0.0.0.0:80` | off | `../../integration/edgeproxy-behind-waf.json` | Reference LAN deployment |
| `configs/embedded.json` | no standalone ingress | not applicable | local integration profile | Optional future embedded mode |
| `configs/compose.json` | `0.0.0.0:8081` | off | `../../integration/edgeproxy-compose-behind-waf.json` | Full-platform Docker Compose deployment |
| `deploy/systemd/securityedge.json` | `0.0.0.0:443` | native HTTPS | `/var/lib/edgeproxy/config.json` | Hardened Linux systemd deployment |

The JSON value stored in `edgeproxy.config_path` is resolved relative to the SecurityEdge configuration file, not relative to the shell's current directory. The checked-in values therefore use `../../../integration/...` internally and correctly resolve to the repository-level `integration` directory.

## Environment configuration

SecurityEdge can run without an environment file. For deployment-specific listeners, dependency addresses, DNS checks, and credentials, copy the committed template:

```powershell
Copy-Item ./.env.example ./.env
```

The process automatically loads `apps/securityedge/.env` when launched from the repository root and `.env` when launched from this directory. It does not fall back to a repository-root `.env`, so settings for another tool or application cannot become SecurityEdge configuration accidentally. Select another file with `-env` or `SECURITYEDGE_ENV_FILE`; use `-no-env` for an isolated run that must ignore dotenv files. Relative `SECURITYEDGE_CONFIG` values loaded from `.env` resolve from that file, while CLI and pre-existing process-environment paths remain relative to the current working directory.

Configuration precedence is:

```text
CLI flags > existing process environment > .env > JSON profile > built-in defaults
```

Important variables:

| Variable | Purpose |
|---|---|
| `SECURITYEDGE_CONFIG` | SecurityEdge JSON profile; relative paths are resolved from the loaded `.env` file |
| `SECURITYEDGE_SERVER_LISTEN_ADDR` | Public gateway IP and port |
| `SECURITYEDGE_TLS_ENABLED` | Enable or disable native TLS on the standalone gateway listener |
| `SECURITYEDGE_TLS_CERT_FILE` | Certificate-chain PEM path used by native TLS |
| `SECURITYEDGE_TLS_KEY_FILE` | Private-key PEM path used by native TLS |
| `SECURITYEDGE_ADMIN_LISTEN_ADDR` | Dashboard and Admin API IP and port |
| `SECURITYEDGE_ADMIN_TOKEN` | Dashboard and SecurityEdge Admin API credential |
| `SECURITYEDGE_UPSTREAM_PROXY_URL` | Internal EdgeProxy data-plane URL |
| `SECURITYEDGE_EDGEPROXY_ADMIN_URL` | EdgeProxy Admin API URL |
| `SECURITYEDGE_EDGEPROXY_CONFIG_PATH` | EdgeProxy route-table JSON path, resolved relative to the SecurityEdge JSON file |
| `EDGEPROXY_ADMIN_TOKEN` | Shared backend credential; must match EdgeProxy |
| `SECURITYEDGE_TRUSTED_PROXY_CIDRS` | Comma-separated proxies trusted in front of SecurityEdge |
| `SECURITYEDGE_FORWARDED_FOR_HEADER` | Header accepted only from configured trusted proxies |
| `SECURITYEDGE_DNS_ENABLED` / `SECURITYEDGE_DNS_CRITICAL` | Enable and classify the DNS acceptance probe |
| `SECURITYEDGE_DNS_SERVER` | DNS resolver IP address and port |
| `SECURITYEDGE_DNS_NAMES` | Comma-separated names checked by the DNS probe |
| `SECURITYEDGE_DNS_EXPECTED_ADDRESSES` | Comma-separated expected resolved IP addresses |
| `SECURITYEDGE_LOG_FILE_PATH` | Persistent NDJSON security-log path |
| `SECURITYEDGE_TELEMETRY_HISTORY_FILE` | Optional bounded telemetry-history JSON path |

Empty or missing variables preserve the JSON values. Environment-derived values are runtime-only: dashboard policy updates continue to persist the file-backed configuration without writing secrets or machine-specific endpoint overrides into JSON.

A missing auto-discovered `.env` file is not an error. An explicitly selected file must identify a regular UTF-8 file no larger than 1 MiB. Invalid files are rejected before any values are applied. Double-quoted dotenv values use JSON-compatible escapes in both the Go executable and PowerShell scripts; Go-only escapes such as `\xNN` are rejected. Never commit the real `.env`; commit only `.env.example`. SecurityEdge PowerShell verification, listener, connectivity, and firewall scripts use compatible validated dotenv loading and the same precedence as the service; `test-deployment.ps1` additionally loads the EdgeProxy `.env` so route and Origin overrides are tested exactly as deployed.

## Native HTTPS configuration

Native HTTPS is configured directly on the standalone gateway server:

```json
{
  "server": {
    "mode": "gateway",
    "listen_addr": "0.0.0.0:443",
    "tls": {
      "enabled": true,
      "cert_file": "/etc/securityedge/tls/fullchain.pem",
      "key_file": "/etc/securityedge/tls/privkey.pem"
    }
  }
}
```

`cert_file` must contain a PEM certificate chain appropriate for the public hostname and `key_file` must contain its matching private key. SecurityEdge validates that both paths are present when TLS is enabled and loads the X.509 key pair before accepting the generation. Runtime TLS uses a minimum version of TLS 1.2. Certificate verification remains the client's responsibility; production deployments should use a certificate issued for the hostname clients actually connect to.

Changing `server.tls.enabled`, `cert_file`, or `key_file` through the JSON file, Admin API, Dashboard System form, or `SECURITYEDGE_TLS_*` environment overrides is restart-required. The supervisor validates the candidate certificate and listener before draining the healthy generation. Environment-only TLS changes are applied to the effective runtime without being persisted into the JSON file. Invalid environment revisions restore the previous managed environment.

Certificate **contents** are intentionally not watched independently when the configured path stays the same. After replacing or renewing a PEM file in place, perform a controlled SecurityEdge restart (for systemd, `systemctl restart securityedge.service`) so the new certificate is loaded. A restart-required configuration change also causes the certificate pair to be revalidated.

The SecurityEdge Admin/Dashboard listener is a separate management boundary and remains HTTP in the current design, normally bound to loopback. Protect remote Admin access with SSH/VPN/private-network access or a separately trusted TLS access layer rather than exposing port `9191` publicly.

## Quick start: local integrated development

Run all commands below from `apps/securityedge` in separate terminals.

### 1. Start the demo Origin

```powershell
go run ../edgeproxy/cmd/origin-demo `
  -no-env `
  -listen 127.0.0.1:9000 `
  -name origin-local
```

### 2. Start EdgeProxy

```powershell
go run ../edgeproxy/cmd/edgeproxy `
  -no-env `
  -config ../../integration/edgeproxy-local-behind-waf.json `
  -pretty-logs
```

### 3. Start SecurityEdge

```powershell
go run ./cmd/securityedge `
  -no-env `
  -config ./configs/local-dev.json `
  -pretty-logs
```

### 4. Send requests through SecurityEdge

```powershell
curl.exe -i http://127.0.0.1:8081/api/products
curl.exe -i http://127.0.0.1:8081/api/products
```

Expected cache behavior from EdgeProxy:

```text
first request   X-Cache: MISS
second request  X-Cache: HIT
```

Test a blocked XSS request:

```powershell
curl.exe -i "http://127.0.0.1:8081/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E"
```

Expected status:

```text
403 Forbidden
```

### Local dashboard

```text
URL:    http://127.0.0.1:9191
Token:  dev-security-token
```

## Reference LAN deployment

The supplied LAN profile uses:

```text
SecurityEdge ingress       0.0.0.0:80
EdgeProxy data plane       127.0.0.1:8080
EdgeProxy Admin API        127.0.0.1:9090
SecurityEdge dashboard     127.0.0.1:9191
DNS resolver endpoint      10.36.74.241:53
Origin                     10.36.74.43:9000
Public hostnames           project.test, www.project.test
```

Update the two application `.env` files when the gateway address, Origin address, hostnames, or DNS service changes.

Run from `apps/securityedge`.

Copy and edit both application `.env.example` files first.

### Origin host

```powershell
go run ../edgeproxy/cmd/origin-demo
```

### Gateway host: EdgeProxy

From `apps/edgeproxy`:

```powershell
go run ./cmd/edgeproxy -pretty-logs
```

### Gateway host: SecurityEdge

From `apps/securityedge`:

```powershell
go run ./cmd/securityedge -pretty-logs
```

### Dashboard credentials

```text
SecurityEdge dashboard token   value of SECURITYEDGE_ADMIN_TOKEN
EdgeProxy Admin API token      shared EDGEPROXY_ADMIN_TOKEN value
```

The dashboard token is entered by the operator. The EdgeProxy token is used only by the SecurityEdge backend and is not exposed to browser JavaScript.

## Expected listener exposure

```text
0.0.0.0:80       public SecurityEdge ingress
127.0.0.1:8080   internal EdgeProxy data plane
127.0.0.1:9090   internal EdgeProxy Admin API
127.0.0.1:9191   local SecurityEdge dashboard and Admin API
```

The Origin should permit its application port only from the gateway host. Untrusted clients should not connect directly to EdgeProxy, either Admin API, or the Origin port.

SecurityEdge connects to the configured EdgeProxy data plane directly and does not inherit ambient `HTTP_PROXY` or `HTTPS_PROXY` settings. This prevents internal application traffic from being redirected through an unrelated host-level proxy. An `https://` EdgeProxy data-plane URL is supported for split-host deployments; the outbound transport uses normal certificate verification and explicitly requires TLS 1.2 or newer. The EdgeProxy Admin client follows the same TLS 1.2+ minimum when its configured Admin URL uses HTTPS.

## Dashboard behavior

The authenticated dashboard is also the platform Control Center. In addition to dependency health and security events, operators can:

- create, edit, and delete EdgeProxy routes and Origins;
- edit every Route field through validated forms: host/path matching, prefix handling, scheduler, retry/transport limits, cache privacy/capacity/TTL rules, and health-check policy;
- use a focused per-route cache editor and segment-aware purge controls without editing raw JSON;
- inspect per-route request volume, HTTP client-facing success/error counts, status distributions, cache hit ratio, min/average/max and P50/P95/P99 latency, retries, upstream calls, timeouts, and bytes; `proxy_errors` remains a separate diagnostic cause and is not added again to the HTTP error-request total;
- inspect per-Route physical request volume, independently tracked client cancellations, completed client-facing outcomes, cache/latency/error telemetry, and per-Origin health, active requests, EWMA latency, scheduler selections, response/status counts, client-canceled attempts, failures, retries, timeouts, and health transitions;
- manage SecurityEdge gateway—including native TLS enablement and certificate/key paths—Admin API, EdgeProxy dependency, and WAF settings through dedicated validated System forms;
- manage EdgeProxy data-plane and Admin listeners, TLS, trusted proxies, timeouts, authentication, and log capacity through dedicated validated System forms;
- rotate secrets without exposing existing values to browser JavaScript; blank secret inputs preserve the current redacted value;
- edit and validate raw EdgeProxy and SecurityEdge JSON configurations for advanced multi-section transactions;
- inspect both file watchers, revision counters, last errors, apply modes, and pending automatic restarts;
- switch between accessible light and dark dashboard themes from either the locked login view or the authenticated console.

All browser mutations call the SecurityEdge backend-for-frontend. The SecurityEdge operator token is kept in `sessionStorage`; the EdgeProxy backend credential is never exposed to browser JavaScript. While the console is locked, the Dashboard shell is inert and keyboard focus stays inside the authentication dialog. Successful login, explicit Lock, expired credentials, and authentication lockout clear the credential field; failed authentication never leaves a token in active Dashboard state, authenticated exports re-lock the console on `401` or `429` responses instead of leaving a stale session running, and periodic refreshes preserve that authoritative locked state instead of misreporting credential expiry as an Operations API outage. Editors track unsaved changes and are not overwritten by periodic dashboard refreshes; Route-dependent Policy and Cache editors also resynchronize safely if the Route table changes, and failed operator actions surface an explicit error instead of leaving an unhandled browser rejection. Periodic, manual, and post-mutation refresh requests are serialized and coalesced, so a slow dependency cannot create overlapping refresh generations or allow an older response to overwrite newer state. Browser API requests have a bounded timeout, and event downloads reuse the received Blob instead of allocating a redundant browser-side copy. EdgeProxy-dependent KPIs, Route/Origin runtime health, telemetry tables, and System metrics display explicit unavailable or unknown states when backend telemetry is absent rather than presenting missing measurements as real zero or unhealthy values. Derived percentages and latencies are likewise displayed as unavailable (`—`) when their denominator or sample count is zero; a cache hit ratio with no cache lookups, a latency with no observations, or a success/error rate with no evaluable outcomes is not presented as a measured `0`. Client-canceled EdgeProxy requests remain visible in physical request/cancellation activity but are excluded from completed client-facing status/error, proxy-error, success/error-rate, and response-latency measurements; the Dashboard labels canceled-only Route rates as unavailable rather than as measured zero. SecurityEdge applies the same distinction before a security decision is complete: a client that aborts while its request body is being received is counted in physical `requests` and `canceled_requests`, but is not mislabeled as a WAF block, processing error, rejection, detection, action/reason outcome, or latency sample. Passive recent-traffic telemetry reports these cancellations separately from allowed and rejected requests. Client-canceled EdgeProxy Origin attempts likewise remain visible as physical calls but are excluded from Origin reliability and latency denominators. Runtime-status and metrics availability are evaluated independently, so a healthy metrics response is not hidden by a failed status probe (and a valid status snapshot is not discarded just because metrics are unavailable). Non-2xx EdgeProxy status/metrics responses remain error metadata in the aggregated overview, and metrics payloads without a declared schema remain unavailable; neither case is ingested into telemetry history as successful zero-valued samples. Telemetry-history persistence uses schema `1.5`: schema `1.2` corrected client-facing error semantics, `1.3` added explicit SecurityEdge process identity and request/rejection-rate validity so service restarts and counter resets create gaps rather than synthetic zeros or spikes, `1.4` preserves per-Origin client-cancellation counters, and `1.5` persists SecurityEdge request-cancellation counters so canceled-only samples cannot make latency appear observed after restart. Existing `1.0`/`1.1`/`1.2`/`1.3`/`1.4` files remain readable; legacy `1.0`/`1.1` aggregate EdgeProxy error counts remain explicitly unverified because historical proxy-error overlap cannot be reconstructed safely, and pre-`1.3` SecurityEdge interval-rate validity is treated conservatively as unknown until two contiguous samples from the current process are available. Live metrics snapshots use a short consistency boundary so concurrent request writers remain concurrent with one another while aggregate counters, per-Route counters, dimensions, latency samples, and derived values are captured from one coherent update generation for both JSON and Prometheus consumers. The appearance preference is deliberately separate from credentials: on a browser with no saved choice the dashboard uses the operating-system `prefers-color-scheme` value, and after an operator toggles the theme the explicit `light` or `dark` choice is stored in `localStorage`, synchronized across same-origin tabs, and retained across refreshes and browser restarts. Clearing the site storage removes that preference and returns the next visit to the system default; there is no separate System-theme option in the UI.

The Overview page separates service health from traffic activity.

### Service Health & Dependencies

The health topology contains only dependencies that SecurityEdge can actively inspect:

```text
DNS Resolution → SecurityEdge → EdgeProxy → Routes → Origins
```

The dashboard reports component status, probe latency, HTTP status, last success or failure, consecutive failures, route readiness, Origin health, and transition history. Connectivity availability is calculated from evaluable `healthy`, `degraded`, or `down` checks, but only `healthy` observations increase `successful_checks`: `degraded` remains in the denominator without being mislabeled as either a healthy success or a hard failure, while `unknown` and `not_applicable` observations do not change the denominator at all. Connectivity state is also wall-clock-safe: a cached `generated_at` that lies in the future after a clock rollback, VM snapshot restore, or clock correction is treated as stale immediately instead of suppressing new probes until the local clock catches up. Each `generated_at` is stamped only after every probe in that generation has completed, so a slow dependency check cannot make a newly returned snapshot immediately stale and trigger an unnecessary second probe cycle. Before the refreshed snapshot is published, any remembered last-success/last-failure timestamp or transition-history entry that is now future-dated is removed from the active timeline, so the Dashboard cannot report an outcome that appears to occur after its own generated time. During normal monotonic operation, degraded and non-evaluable observations still interrupt the current healthy/down streak without overwriting valid historical success/failure timestamps, so partial dependency health is visible without creating either a false success streak or a false outage streak. The EdgeProxy metrics dependency is considered healthy only when its authenticated endpoint returns a successful JSON payload with a non-empty declared metrics schema; a schema-less payload is treated as degraded rather than silently counted as a successful observability check. The authenticated Route/Origin status endpoint is also part of observability health: if it is unavailable while the data plane and readiness remain healthy, traffic-path health stays healthy but observability becomes down and the overall service state is reported as degraded rather than falsely healthy. It also samples a bounded operational timeline containing SecurityEdge rejection rates, EdgeProxy request/cache/latency signals, and condensed per-Route/per-Origin counters. The live top-level `requests_per_second` values exposed by the service metrics snapshots are cumulative averages since the corresponding process started; the Dashboard labels the EdgeProxy KPI accordingly and formats low non-zero averages with adaptive precision instead of rounding them to a misleading zero, including extremely low long-uptime rates below `0.0001 req/s`. Percentage KPIs and component availability use the same truthfulness rule at their boundaries: small but non-zero rejection, detection, cache, success, or error percentages gain enough precision to remain visibly non-zero, and values below but very close to `100%` are not rounded up to an exact `100%` measurement. Latency measurements follow the same rule: sampled SecurityEdge, EdgeProxy, Route/Origin, log-duration, scheduler-EWMA, and connectivity latency values retain additional precision when a positive sub-millisecond measurement would otherwise round to `0.00 ms`, while unavailable connectivity latency remains explicitly unavailable rather than being invented as zero. The trend chart instead derives interval rates from adjacent persisted counter samples. Its Y-axis uses an adaptive request-rate scale with headroom rather than forcing a `1 req/s` minimum, and its X-axis follows the persisted sample timestamps instead of array positions. The Dashboard preserves the complete retained sample sequence for latest-interval availability, retained-count, and retained-time-range semantics, while trimming leading/trailing intervals with no available rate only from the plotted viewport; genuine interior telemetry gaps remain disconnected. Canvas X-axis bounds are therefore derived only from rate-bearing display points to avoid artificial whitespace, while the metadata beneath the chart reports the timestamps of the full retained history so a trailing unavailable interval cannot silently shorten the displayed history range. A short, statistically isolated burst is never deleted or smoothed: EdgeProxy request rates and SecurityEdge rejection rates are profiled independently so a sparsely available or naturally higher-magnitude series cannot be mislabeled as an outlier merely because the other series contributes more low-valued samples. When a small number of rates within a series are clearly separated from that series' ordinary positive-rate distribution, the shared linear display range is based on the largest ordinary value across both series, every above-range peak is clamped only for drawing and marked at the top edge, and the UI reports both the number of peaks above scale and the exact observed maximum. Sustained or broadly distributed higher traffic continues to expand the normal Y-axis instead of being treated as an outlier. The Dashboard exposes one concise retained-history range rather than duplicating the plotted viewport as a second visible time card, alongside the current display scale, numeric rate ticks, and an explicit no-history state. Each legend entry reports its latest value and observed-interval coverage so partial series availability is immediately visible without a dense explanatory paragraph. A measured zero remains a real measurement: zero-valued EdgeProxy request rates and SecurityEdge rejection rates are drawn on the `0 req/s` baseline whenever their interval is available, while unavailable intervals remain blank and are never invented as zero. EdgeProxy uses a solid series and SecurityEdge uses a dashed series so coincident zero baselines remain visually distinguishable without shifting either series away from its true Y value; the legend may still summarize a fully observed zero rejection series as `No rejections`. Large timestamp discontinuities relative to the normal persisted-sample cadence also break the plotted line and, when space permits, receive a subtle `No telemetry` label, preventing the chart from visually connecting traffic across an observability outage. These presentation rules keep low-volume, bursty, sparsely available, and partially unavailable histories interpretable in both light and dark themes. Legend values still reflect the latest retained interval rather than carrying an older finite value forward: when the newest sample marks one series unavailable, that series is shown as `Unavailable` even though its earlier historical line remains part of the retained history. EdgeProxy request rates and SecurityEdge request/rejection rates are marked available only when two adjacent samples belong to the same process generation, have monotonic counters, and have a positive time interval. An observability outage, EdgeProxy or SecurityEdge restart, counter reset, or newly observed Route therefore creates an explicit gap instead of a synthetic zero or spike. Existing history schemas `1.0`, `1.1`, `1.2`, `1.3`, and `1.4` remain readable: pre-`1.1` EdgeProxy rate-validity metadata and pre-`1.3` SecurityEdge rate-validity metadata are unknown and are rendered conservatively as gaps until contiguous current-process samples establish a valid interval; `1.0`/`1.1` EdgeProxy aggregate error counts also remain unverified because their historical proxy-error overlap cannot be reconstructed. New files persist corrected error semantics, EdgeProxy and SecurityEdge process/rate-validity metadata, per-Origin client-cancellation counters, and SecurityEdge request-cancellation counters in schema version `1.5`. The current schema also carries explicit availability flags for derived cache ratios, latency percentiles, and Origin success rates so history consumers can distinguish an unobserved measurement from a legitimate numeric zero. History is bounded by both sample count and a 16 MiB serialized in-memory budget; old samples are evicted first, and an individually oversized topology sample retains its aggregate security/EdgeProxy counters while marking Route details as truncated. The history API reports both retained and maximum retained bytes. When `admin.telemetry_history.file_path` is configured, samples are replaced atomically and restored after restart; the persisted document remains capped at 32 MiB, and a corrupt history file is reported as degraded but never prevents service startup. Future-dated samples caused by wall-clock rollback, VM snapshot restore, or clock correction are discarded so they cannot freeze periodic collection; the next valid observation intentionally starts a rate gap instead of deriving a synthetic spike across the clock discontinuity.

The periodic SecurityEdge → EdgeProxy data-plane check uses a reserved operational-probe marker together with `Cache-Control: no-store`. EdgeProxy honors that marker only for the expected `HEAD` probe received directly from loopback or a configured trusted-proxy peer, strips it before contacting the Origin, and excludes the synthetic request from application request/cache/upstream metrics, retained access/origin-attempt logs, scheduler/EWMA state, and Origin health transitions. A data-plane probe is considered Route-matched only when EdgeProxy returns the private `X-SecureEdge-Internal-Probe: matched-v1` acknowledgement; a generic `X-Request-ID` is insufficient because observable `__unmatched__` 404 responses also carry request IDs. The acknowledgement proves routing, but it does not override the final service outcome: a matched probe that returns an HTTP `5xx` is reported as a failed data-plane check, while non-`5xx` application responses such as `404` or `405` may still prove that the configured Route/Origin path is reachable. Origin-supplied copies of the acknowledgement are removed by EdgeProxy, so the response marker remains authoritative. This keeps the Overview cache hit ratio and request-rate history representative of real application traffic even when connectivity checks run every five seconds. SecurityEdge strips any client-supplied copy of the marker from normal gateway traffic, and EdgeProxy treats a matching marker from an untrusted peer as ordinary metered traffic rather than as a probe. Deploy matching SecurityEdge and EdgeProxy binaries together so the reserved probe contract and telemetry semantics remain aligned during upgrades.

`X-SecureEdge-Internal-Probe` is reserved exclusively for this private connectivity contract and is rejected as `server.forwarded_for_header`. Using control-plane metadata as a client-identity source would otherwise create a configuration that validates but cannot be honored consistently after the marker is stripped.

### Recent Client Traffic

This panel is updated by real requests that reach SecurityEdge. It can show:

- last request time;
- privacy-safe client IP metadata;
- HTTP method and sanitized path;
- selected route;
- `ALLOW` or `BLOCK` decision;
- downstream HTTP status;
- response duration;
- EdgeProxy cache result;
- request and unique-client counts within the bounded recent window.

The recent-traffic tracker retains at most 512 request events in memory and keeps that bounded set ordered by normalized observation time rather than tracker insertion order. Concurrent scheduling or delayed request finalization therefore cannot make an older event appear as the latest request or displace a newer retained event. If the wall clock moves backward, retained events that are now future-dated are discarded from the active timeline, together with any future-dated truncation marker, so an old pre-correction request cannot remain the apparent latest request or reappear later when the clock catches up. If more still-in-window events have been evicted because that capacity was reached, the API sets `window_truncated=true`, reports the retention capacity and a conservative `minimum_requests_in_window`, and the Dashboard labels the displayed breakdown as a retained sample instead of presenting it as an exact five-minute total. This keeps memory bounded without silently under-reporting high-volume traffic.

No external acceptance-test reporter is required. No recent traffic is informational and does not make service health degraded or down.

## Authentication and secrets

Use separate strong tokens for the two trust boundaries:

```text
SECURITYEDGE_ADMIN_TOKEN   operator access to the dashboard and SecurityEdge API
EDGEPROXY_ADMIN_TOKEN      SecurityEdge backend access to the EdgeProxy Admin API
```

Generate values with:

```powershell
.\scripts\generate-admin-token.ps1
```

Put the SecurityEdge token only in `apps/securityedge/.env`. Put the exact same EdgeProxy token in both application `.env` files. Existing process variables override dotenv values, which makes the same binaries compatible with service managers and secret stores.

Repeated invalid Admin authentication attempts are rate-limited and can trigger a temporary in-memory lockout according to the selected profile.

## Admin API

The Admin listener provides the dashboard plus these endpoints.

Unauthenticated process endpoints:

```text
GET /healthz
GET /readyz
```

These endpoints intentionally return only generic liveness/readiness state. Dependency URLs, transport errors, route names, and full EdgeProxy readiness payloads are available only through authenticated status and connectivity endpoints.

Authenticated SecurityEdge endpoints:

```text
GET     /api/v1/session
GET     /api/v1/status
GET     /api/v1/info
GET     /api/v1/metrics
GET     /api/v1/metrics/prometheus
GET     /api/v1/logs
DELETE  /api/v1/logs
GET     /api/v1/logs/export
GET     /api/v1/rules
GET     /api/v1/config
PUT     /api/v1/config
GET     /api/v1/server
PUT     /api/v1/server
GET     /api/v1/admin
PUT     /api/v1/admin
GET     /api/v1/edgeproxy-settings
PUT     /api/v1/edgeproxy-settings
GET     /api/v1/waf
PUT     /api/v1/waf
GET     /api/v1/config/watch
GET     /api/v1/policies
PUT     /api/v1/policies/default
PUT     /api/v1/policies/{route}
DELETE  /api/v1/policies/{route}
POST    /api/v1/reload
GET     /api/v1/bans
DELETE  /api/v1/bans/{client}
DELETE  /api/v1/bans
GET     /api/v1/dashboard/overview
GET     /api/v1/dashboard/history?limit=120
GET     /api/v1/traffic/recent
GET     /api/v1/connectivity
POST    /api/v1/connectivity/check
```

`/api/v1/metrics/prometheus` mirrors the scalar counters exposed by the JSON metrics snapshot for both aggregate and per-Route series. In particular, request outcomes remain partitionable in Prometheus (`allowed`, `logged`, `blocked`, rate-limited, overload-rejected, banned, and canceled), and the export includes global/client rate-limit attribution plus body-size, auto-ban, inspection, truncation, detection, and processing-error counters.

`DELETE /api/v1/logs` clears the in-memory event ring, truncates the active NDJSON log, and removes rotated backups. CSV exports neutralize spreadsheet-formula prefixes in user-controlled fields before writing rows. CSV and NDJSON downloads page through the retained ring in bounded batches and stream each batch directly to the client; they do not clone the complete ring or materialize a second serialized payload, and client disconnects stop work promptly. Named log filters accept at most 512 bytes and free-text `q` searches accept at most 2,048 bytes; search normalization is performed once per request rather than once per retained event.

When NDJSON persistence is enabled, SecurityEdge restores the newest retained events from the active file and configured rotated backups during startup. Event sequence numbers continue monotonically across restarts; malformed, crash-truncated, or oversized lines are skipped and counted in the log-store `file_errors` metric instead of preventing startup. Oversized records are discarded only through their terminating newline, so valid events later in the same active or rotated file are still recovered. Restored timestamps, rule IDs, tags, and WAF match details are normalized to the same bounded representation used by live events, so a damaged or manually altered log cannot inflate the in-memory ring through oversized nested fields.

The in-memory Admin event ring accepts a configured `capacity` from `1` through `100000` entries. Persistent security logs are limited to 1 GiB per file and at most 100 rotated backups. Gateway concurrency, rate-limit buckets, automatic-ban tracking, rates, and bursts are capped at 1,000,000; automatic-ban thresholds are capped at 10,000. Security policy collections are bounded as well: at most 2,048 Route policies, 256 custom WAF rules, 4,096 entries in each IP allow/deny list, 4,096 trusted-proxy CIDRs, and a 4 KiB regular-expression pattern per custom rule. Expired bans and stale partial-violation records are removed opportunistically, so bounded tracking capacity is reclaimed even without capacity pressure. SecurityEdge upstream connection pools are also capped at 1,000,000 configured slots per transport setting. Validation stops processing each oversized collection at its published ceiling, so invalid profiles cannot amplify CPU or diagnostic-memory use while they are being rejected. These boundaries prevent structurally valid configuration from requesting unbounded CPU, memory, disk, or rotation work.

### Automatic reload and restart boundaries

SecurityEdge watches three inputs independently: its own JSON configuration, the shared EdgeProxy Route table, and its application `.env`. This separation is intentional:

- a shared EdgeProxy file change reloads only SecurityEdge's Route metadata and policy lookup table;
- a hot-applicable SecurityEdge change updates policies, WAF rules, trusted proxies, route metadata, and EdgeProxy Admin connectivity without interrupting traffic;
- hot-applicable `.env` overrides are validated and applied in place; listener, TLS, transport, Admin listener/auth/log-store, process-wide limiter/ban-store, or configuration-path changes schedule an automatic graceful generation restart;
- invalid JSON, referenced Route-table, or `.env` revisions restore the previous managed environment, keep the last healthy runtime, and are reported through `/api/v1/config/watch`.

`POST /api/v1/reload` remains available for an explicit re-read. `PUT /api/v1/config` validates and atomically persists a complete candidate. Hot changes return `200 OK`; restart-required revisions from either endpoint return `202 Accepted` and are applied automatically by the managed process. Before the active generation is drained, SecurityEdge rebuilds configuration-dependent runtime components, verifies the shared Route table, reopens the security log store, probes the telemetry-history destination, validates enabled TLS certificate/key material, and tests every newly claimed listener. An occupied port or unavailable persistent resource is rejected without persisting the API revision or stopping the healthy generation. New gateway and Admin sockets are bound synchronously, and a partial bind failure closes every socket acquired by that candidate. If startup still loses a post-preflight race, the supervisor restores the latest file-backed configuration known to be healthy in the active generation—including successful WAF, policy, Route-metadata, and dependency hot reloads—restarts that generation, and records the rejected candidate in watcher status.

Dedicated `GET/PUT /api/v1/server`, `GET/PUT /api/v1/admin`, `GET/PUT /api/v1/edgeproxy-settings`, and `GET/PUT /api/v1/waf` endpoints provide section-scoped SecurityEdge configuration management without requiring a complete-document replacement. The PowerShell control client exposes the same operations as `GetServer`, `SetServer`, `GetAdmin`, `SetAdmin`, `GetEdgeProxySettings`, `SetEdgeProxySettings`, `GetWAF`, and `SetWAF`; full-document editing remains available for advanced or multi-section transactions.

Multiple rapid restart requests are coalesced so the newest valid revision wins. The service process remains the same while listeners and long-lived resources move to the new generation.

The restart-required comparison uses the file-backed SecurityEdge configuration independently of runtime/environment endpoint overrides. A change made to EdgeProxy routes from the Dashboard therefore cannot be misclassified as a SecurityEdge process change or cause an unnecessary listener restart.

Rate-limit buckets and automatic-ban tracking are also process-wide stores. Route policies may define different request rates, bursts, violation thresholds, windows, and ban durations, but they must use the same `cleanup_interval`, `idle_ttl`, `max_buckets`, and `max_tracked_clients` capacity settings as `default_policy`. This prevents one route from applying a smaller shared-store capacity to buckets or client records created by another route. The case-insensitive identifier `__unmatched__` is reserved for SecurityEdge's internal unmatched-request telemetry and cannot be used as an EdgeProxy Route name or a SecurityEdge Route-policy key, preventing unmatched traffic from inheriting or merging with a user-defined Route identity.

Dashboard policy updates are prepared before the configuration file is replaced. A validation or reload-preparation failure therefore leaves both the persisted file and the active runtime unchanged. Reload and policy-write transactions are serialized, so concurrent Admin API requests cannot overwrite one another or apply a different revision than the one persisted on disk.

SecurityEdge also overwrites `X-Request-ID`, `X-Security-Action`, and `X-Security-Score` at the final response boundary. Values supplied by EdgeProxy or an Origin cannot impersonate the security decision returned to the client.

Authenticated EdgeProxy backend-for-frontend endpoints:

```text
GET     /api/v1/edgeproxy/status
GET     /api/v1/edgeproxy/metrics
GET     /api/v1/edgeproxy/telemetry
GET     /api/v1/edgeproxy/routes/{route}/telemetry
GET     /api/v1/edgeproxy/routes/{route}/origins/{origin}/telemetry
GET     /api/v1/edgeproxy/logs
DELETE  /api/v1/edgeproxy/logs
POST    /api/v1/edgeproxy/cache/purge
GET     /api/v1/edgeproxy/config
PUT     /api/v1/edgeproxy/config
POST    /api/v1/edgeproxy/config/reload
GET     /api/v1/edgeproxy/config/watch
GET     /api/v1/edgeproxy/server
PUT     /api/v1/edgeproxy/server
GET     /api/v1/edgeproxy/admin
PUT     /api/v1/edgeproxy/admin
GET     /api/v1/edgeproxy/routes
POST    /api/v1/edgeproxy/routes
GET     /api/v1/edgeproxy/routes/{route}
PUT     /api/v1/edgeproxy/routes/{route}
DELETE  /api/v1/edgeproxy/routes/{route}
GET     /api/v1/edgeproxy/routes/{route}/load-balancing
PUT     /api/v1/edgeproxy/routes/{route}/load-balancing
GET     /api/v1/edgeproxy/routes/{route}/proxy
PUT     /api/v1/edgeproxy/routes/{route}/proxy
GET     /api/v1/edgeproxy/routes/{route}/cache
PUT     /api/v1/edgeproxy/routes/{route}/cache
POST    /api/v1/edgeproxy/routes/{route}/cache/purge
GET     /api/v1/edgeproxy/routes/{route}/health-check
PUT     /api/v1/edgeproxy/routes/{route}/health-check
GET     /api/v1/edgeproxy/routes/{route}/origins
POST    /api/v1/edgeproxy/routes/{route}/origins
GET     /api/v1/edgeproxy/routes/{route}/origins/{origin}
PUT     /api/v1/edgeproxy/routes/{route}/origins/{origin}
DELETE  /api/v1/edgeproxy/routes/{route}/origins/{origin}
```

Successful EdgeProxy mutations immediately refresh SecurityEdge's shared Route table and are also observed by the independent file watcher. Deleting a Route removes its matching SecurityEdge policy override transactionally; the policy is restored if the downstream EdgeProxy deletion fails. Replacing the complete EdgeProxy configuration is rejected when it would orphan existing SecurityEdge route-policy overrides.

The cache-purge backend forwards the EdgeProxy `route`, `host`, and `path_prefix` query parameters. A path prefix is segment-aware: `/api` purges `/api` and `/api/...`, but not `/apix`. Invalid or ambiguous path prefixes are rejected with `400 Bad Request`.

Example:

```powershell
$AdminUrl = "http://127.0.0.1:9191"
$Token = "dev-security-token"
$Headers = @{ Authorization = "Bearer $Token" }

Invoke-RestMethod "$AdminUrl/api/v1/dashboard/overview" -Headers $Headers
```

## Operational scripts

Run from `apps/securityedge`.

The two management clients expose the complete Control Plane from PowerShell:

```powershell
.\scripts\manage-edgeproxy.ps1 -Action ListRoutes
.\scripts\manage-edgeproxy.ps1 -Action UpdateRoute -Route demo-app -BodyFile .\route.json
.\scripts\manage-edgeproxy.ps1 -Action Telemetry
.\scripts\manage-security.ps1 -Action Watch
.\scripts\manage-security.ps1 -Action GetServer
.\scripts\manage-security.ps1 -Action SetAdmin -BodyFile .\admin-settings.json
.\scripts\manage-security.ps1 -Action GetEdgeProxySettings
.\scripts\manage-security.ps1 -Action SetWAF -BodyFile .\waf-settings.json
.\scripts\manage-security.ps1 -Action Policies
.\scripts\manage-security.ps1 -Action SetRoutePolicy -Route demo-app -BodyFile .\policy.json
```

They produce structured JSON, load the proper Admin token from the process environment or application `.env`, reject invalid request JSON locally, fail fast on HTTP/API errors, and disable ambient proxy use for local or LAN management traffic.

The scripts auto-load `../.env`; existing process variables take precedence, and explicit parameters remain the highest-priority overrides. Use `-EnvFile` for an external SecurityEdge file or `-NoEnv` for an isolated JSON/default check. The complete deployment test also auto-loads `../../edgeproxy/.env`, with `-EdgeProxyEnvFile` available for an external file. Admin helper URLs preserve explicitly bound hostnames, LAN IPs, and IPv6 addresses; wildcard listeners are contacted through loopback. Protection smoke tests use the first configured DNS name only when DNS probing is enabled, and otherwise use the reachable local ingress listener. Port `0` requires an explicit `-AdminUrl` or `-BaseUrl` because the assigned runtime port is not known from configuration.

Validate listener exposure against the effective ports:

```powershell
.\scripts\check-listeners.ps1
```

Force dependency checks with the effective Admin URL and token:

```powershell
.\scripts\check-connectivity.ps1 -Force
```

Validate the complete LAN deployment, including both application environment files:

```powershell
.\scripts\test-deployment.ps1
```

Run protection tests with the effective public URL and Admin credential:

```powershell
.\scripts\test-protection.ps1
```

Start with validation:

```powershell
.\scripts\start-security.ps1 `
  -Config ./configs/securityedge.json
```

Preview or create Windows Firewall rules for the public SecurityEdge ingress:

```powershell
.\scripts\setup-proxy-firewall.ps1

.\scripts\setup-proxy-firewall.ps1 -Apply
```

The firewall script intentionally does not expose EdgeProxy or Admin ports.

On POSIX systems, `scripts/test-security.sh` and `scripts/test-protection.sh` are explicit-environment smoke tests. They deliberately do not source `.env` as shell code. Export the active Admin credential and override the public and Admin URLs when needed:

```sh
SECURITYEDGE_ADMIN_TOKEN='replace-with-the-active-token' \
BASE_URL='http://project.test:8081' \
ADMIN_URL='http://127.0.0.1:9191' \
bash ./scripts/test-security.sh
```

Both scripts fail before sending requests when no Admin token is supplied and bypass ambient HTTP proxy settings for local verification. For an HTTPS test endpoint with a deliberately self-signed development certificate, set `INSECURE=1`; production verification should leave it unset so certificate validation remains enabled. The PowerShell `test-security.ps1`, `test-protection.ps1`, and `test-deployment.ps1` scripts provide the equivalent opt-in `-Insecure` switch. `test-protection.sh` expects a profile whose rate limiter and automatic-ban behavior are enabled.

## Build and verification

```powershell
go fmt ./...

go vet ./...
go test ./...
go test -race ./...

node --check ./internal/admin/web/theme.js
node --check ./internal/admin/web/app.js
node --check ../../scripts/test-dashboard-browser.mjs
node ../../scripts/test-dashboard-browser.mjs --fixture-root ../..

go build -trimpath -o ./bin/securityedge ./cmd/securityedge
```

Validate configurations:

```powershell
go run ./cmd/securityedge -config ./configs/local-dev.json -validate
go run ./cmd/securityedge -config ./configs/securityedge.json -validate
go run ./cmd/securityedge -config ./configs/embedded.json -validate
go run ./cmd/securityedge -config ./configs/compose.json -validate
```

Makefile targets:

```powershell
make fmt
make test
make race
make vet
make js
make dashboard
make build
make validate
make validate-network
make verify
```

## Linux systemd deployment

Install EdgeProxy first because SecurityEdge reads the authoritative Route table and calls the EdgeProxy Admin API. The supplied unit starts SecurityEdge as a separate unprivileged user, grants only low-port binding capability, and keeps writable configuration, telemetry history, and logs outside read-only `/etc`.

Run these commands as `root` from `apps/securityedge`, or adapt the source paths to your release directory:

```sh
getent group edgeproxy >/dev/null || groupadd --system edgeproxy
groupadd --system securityedge 2>/dev/null || true
id securityedge >/dev/null 2>&1 || \
  useradd --system --gid securityedge --groups edgeproxy \
    --home-dir /var/lib/securityedge --shell /usr/sbin/nologin securityedge
usermod -a -G edgeproxy securityedge

install -o root -g root -m 0755 ./bin/securityedge \
  /usr/local/bin/securityedge
install -o root -g root -m 0644 ./deploy/systemd/securityedge.service \
  /etc/systemd/system/securityedge.service
install -d -o root -g securityedge -m 0750 /etc/securityedge
install -d -o root -g securityedge -m 0750 /etc/securityedge/tls
install -o root -g securityedge -m 0640 \
  ./deploy/systemd/securityedge.env.example \
  /etc/securityedge/securityedge.env
install -d -o securityedge -g securityedge -m 0750 /var/lib/securityedge
install -d -o securityedge -g securityedge -m 0750 /var/log/securityedge
install -o securityedge -g securityedge -m 0640 \
  ./deploy/systemd/securityedge.json \
  /var/lib/securityedge/securityedge.json
```

Replace both placeholder credentials in `/etc/securityedge/securityedge.env`. `EDGEPROXY_ADMIN_TOKEN` must exactly match the value used by EdgeProxy. The checked-in systemd profile enables native HTTPS on port `443`, so install the certificate chain and matching private key before starting the service:

```sh
install -o root -g securityedge -m 0640 /path/to/fullchain.pem /etc/securityedge/tls/fullchain.pem
install -o root -g securityedge -m 0640 /path/to/privkey.pem /etc/securityedge/tls/privkey.pem
```

Use certificate material issued for the hostname clients will use; do not commit private keys to the repository. Confirm the shared Route table is readable but not writable by SecurityEdge, then start the services. Startup validates each effective profile after applying its systemd environment overrides and loads the TLS key pair before binding the public listener:

```sh
chown edgeproxy:edgeproxy /var/lib/edgeproxy/config.json
chmod 0750 /var/lib/edgeproxy
chmod 0640 /var/lib/edgeproxy/config.json

systemctl daemon-reload
systemctl enable --now edgeproxy.service
systemctl enable --now securityedge.service
systemctl status securityedge.service
journalctl -u securityedge.service -f
```

The supplied systemd profile terminates native HTTPS on public port `443` and keeps the Dashboard/Admin API loopback-only at `127.0.0.1:9191`. `CAP_NET_BIND_SERVICE` is retained only so the unprivileged SecurityEdge process can bind the privileged HTTPS port. Change the listener/TLS settings through the Dashboard/API or edit `/var/lib/securityedge/securityedge.json` before startup when a different network boundary is required. Dashboard/API changes persist atomically to that file; security events and bounded telemetry history survive restarts under `/var/log/securityedge` and `/var/lib/securityedge`. After renewing or replacing certificate files in place, restart `securityedge.service` to load the new key pair.

The systemd environment template deliberately contains only `SECURITYEDGE_ADMIN_TOKEN` and the shared `EDGEPROXY_ADMIN_TOKEN`. Gateway, listener, Admin, WAF, DNS, logging, history, and EdgeProxy dependency settings remain file-backed so successful Control Plane updates remain authoritative after reload and restart. Defining their optional `SECURITYEDGE_*` environment overrides intentionally pins those fields. Dashboard/API and direct file reloads reject changes to environment-managed fields with a clear validation error; rotate the two systemd credentials in `/etc/securityedge/securityedge.env` and restart SecurityEdge instead of using the Dashboard token fields.

## Docker

### Build the SecurityEdge image

The Dockerfile copies files from both `apps/securityedge` and the repository-level `integration` directory. Commands in this README start from `apps/securityedge`, so the build context must be the repository root (`../..`):

```powershell
docker build `
  -f ./Dockerfile `
  -t securityedge:latest `
  ../..
```

The image uses `/app/config/securityedge.json`, initialized from `configs/compose.json`. Its container-specific settings are:

```text
SecurityEdge ingress       0.0.0.0:8081
SecurityEdge Admin API     0.0.0.0:9191
EdgeProxy data plane       http://edgeproxy:8080
EdgeProxy Admin API        http://edgeproxy:9090
EdgeProxy route profile    /integration/edgeproxy-compose-behind-waf.json
```

The `/app/config` and `/app/logs` paths are writable volumes owned by the non-root application user. This allows dashboard policy changes to be atomically persisted and allows rotated NDJSON logs to survive container recreation. Real credentials should be injected through `SECURITYEDGE_ADMIN_TOKEN` and `EDGEPROXY_ADMIN_TOKEN`.

The image is designed to participate in a container network with services named `edgeproxy` and `origin`; running it alone will not provide a reachable upstream. The checked-in Compose profile keeps ingress HTTP for a self-contained local demonstration. For an Internet-facing container deployment, either enable SecurityEdge native TLS and mount certificate/key material read-only at the configured paths, or terminate TLS at a trusted load balancer/CDN and configure `trusted_proxy_cidrs` to match that boundary.

### Run the complete platform

From `apps/securityedge`:

```powershell
docker compose `
  -f ../../deployments/docker/compose.yml `
  up --build
```

Optional environment overrides can be loaded with:

```powershell
Copy-Item ../../deployments/docker/.env.example ../../deployments/docker/.env

docker compose `
  --env-file ../../deployments/docker/.env `
  -f ../../deployments/docker/compose.yml `
  up --build
```

The full stack publishes:

```text
SecurityEdge ingress    host TCP port 8081 (all host interfaces)
SecurityEdge dashboard  http://127.0.0.1:9191 (loopback only)
```

Local verification can still use `http://127.0.0.1:8081`; clients on another machine must use the Docker host's reachable address. EdgeProxy and the Origin remain internal to the Docker network, preventing direct host-side bypass of SecurityEdge.

To reset persisted policy configuration and logs:

```powershell
docker compose `
  -f ../../deployments/docker/compose.yml `
  down -v
```

See [../../deployments/docker/README.md](../../deployments/docker/README.md) for service topology, volumes, ports, and credential overrides.

For production Docker operation, including the SecurityEdge-only migration profile and the full private-network platform deployment, use [`../../deployments/docker-production/README.md`](../../deployments/docker-production/README.md). The existing application Docker workflow remains the local/demo path.

## Privacy and log handling

SecurityEdge avoids retaining raw sensitive attack payloads in recent-traffic telemetry. Security events use bounded in-memory storage and optional NDJSON persistence with rotation. Historical telemetry stores only aggregate counters, rates, latency summaries, health outcomes, and Route/Origin names; it never stores request bodies, headers, credentials, or client payloads.

Generated files under `logs/` are runtime artifacts and must not be committed. Keep only `logs/.gitkeep` in source control.

## Embedded mode

`configs/embedded.json` and [`../../integration/edgeproxy-embedded-integration.patch`](../../integration/edgeproxy-embedded-integration.patch) document an optional future mode in which SecurityEdge wraps the EdgeProxy handler in-process.

When that patch is applied, the EdgeProxy command independently discovers both application `.env` files. Set `SECURITYEDGE_CONFIG=configs/embedded.json` in `apps/securityedge/.env`; use `SECURITYEDGE_ENV_FILE` for an external file. EdgeProxy's `-no-env` flag disables both dotenv loaders, and `-validate` validates both configurations in the patched build.

This mode is not required by the current deployment and the patch is not applied to the active EdgeProxy source tree. Because embedded mode has no independent SecurityEdge listener, `server.tls.enabled=true` is rejected there; TLS remains the responsibility of the outer EdgeProxy/server integration. The supported demonstration path remains standalone non-embedded gateway mode.

## Related documentation

- [SecureEdge Platform](../../README.md)
- [EdgeProxy](../edgeproxy/README.md)
- [Platform integration](../../integration/README.md)

## License

See [../../LICENSE](../../LICENSE).
