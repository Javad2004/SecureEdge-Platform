# Platform Scripts

This directory contains repository-wide development and operational helpers. Component-specific verification and Control Plane clients remain under `apps/edgeproxy/scripts/` and `apps/securityedge/scripts/`.

## Automatic development supervisor

Run from the repository root on Windows:

```powershell
.\scripts\dev-watch.ps1 -PrettyLogs
```

Run on Linux:

```bash
bash ./scripts/dev-watch.sh
```

The supervisor watches source code, embedded Dashboard HTML/CSS/JavaScript, workspace files, integration JSON, deployment assets, and platform scripts. Changes are debounced and classified so only the affected service is rebuilt. A uniquely named candidate binary is built before the healthy generation is stopped; a failed build leaves the running service untouched, and a candidate startup failure restores the preceding binary without terminating the watcher. If no healthy generation can be restored, the supervisor remains active and retries on a later poll. Unexpected process exits are rebuilt and restarted automatically.

By default, EdgeProxy runs from `integration/edgeproxy-local-behind-waf.json`, which is the exact Route table referenced by `apps/securityedge/configs/local-dev.json`. Dashboard/API Route and Origin changes, EdgeProxy's internal watcher, and SecurityEdge's shared-table watcher therefore observe one authoritative file rather than two similar local profiles.

The active application JSON and `.env` files are intentionally not handled as source changes. EdgeProxy and SecurityEdge watch those files internally, validate them transactionally, hot-apply safe changes, coalesce restart-required revisions, and preserve the last healthy runtime when a revision is invalid. This avoids duplicate restarts and scheduler resets.

Generated development binaries are stored under ignored `.dev/bin/` and removed when the supervisor exits. The PowerShell watcher requires Windows PowerShell or PowerShell 7. The Linux watcher requires Bash and GNU `find`.

Relative profile and dotenv arguments are resolved from the repository root in both supervisors, even when the command is invoked from another working directory; absolute external paths are preserved.

Optional PowerShell parameters select external profiles, dotenv files, polling/debounce intervals, and pretty logs:

```powershell
.\scripts\dev-watch.ps1 `
  -EdgeProxyConfig integration/edgeproxy-local-behind-waf.json `
  -SecurityEdgeConfig apps/securityedge/configs/local-dev.json `
  -PollMilliseconds 500 `
  -DebounceMilliseconds 750 `
  -PrettyLogs
```

The full container stack is managed through `deployments/docker/compose.yml`.

## Dashboard browser smoke test

The browser smoke test uses an installed Chrome, Edge, or Chromium through the DevTools protocol and has no npm dependency. Against a running SecurityEdge stack:

```powershell
node .\scripts\test-dashboard-browser.mjs `
  --url http://127.0.0.1:9191 `
  --token $env:SECURITYEDGE_ADMIN_TOKEN
```

Live mode is intentionally read-only: it verifies authentication, rendering, populated editors, navigation, and browser runtime behavior without submitting configuration changes to the running deployment. Mutation/form-submission coverage is exercised only in fixture mode, where API writes are intercepted by deterministic browser-side mocks.

For CI, restricted sandboxes, or workstations whose browser policy blocks local HTTP navigation, fixture mode loads the real embedded Dashboard HTML and JavaScript into a real browser, supplies deterministic API responses from the checked-in local profiles, and verifies login/modal focus isolation, credential clearing across lock and authentication failures, expired-export and expired-periodic-refresh re-locking, preservation of the locked connection state after authentication loss, truthful unavailable rendering for missing or invalid EdgeProxy telemetry and for undefined zero-denominator/zero-sample derived metrics, independent EdgeProxy status/metrics availability, non-overlapping client-facing/proxy-error counting, explicit trend gaps across unavailable/restarted/reset EdgeProxy request-rate and SecurityEdge rejection-rate windows, accessible dialog naming, initial rendering, complete Route forms, per-route cache management, preservation of unsaved Policy/Cache edits across refreshes, safe Policy/Cache resynchronization after Route-table changes, operator-facing failure feedback for control-plane actions, navigation, responsive layouts across every Dashboard view (including page-level overflow and clipped-content containment), compact page-header spacing, Security Explorer action/filter composition, Service Health action wrapping, accessible names for all interactive controls, Light/Dark contrast, system-default theme selection, persisted theme bootstrap, cross-tab storage synchronization, storage clearing fallback, and browser runtime errors:

```powershell
node .\scripts\test-dashboard-browser.mjs --fixture-root .
```

Use `--browser <path>` when the browser is not in a standard installation location. Fixture mode complements rather than replaces API and end-to-end tests; live mode remains the final browser-to-service verification for deployment environments.
