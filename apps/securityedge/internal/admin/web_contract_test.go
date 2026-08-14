package admin

import (
	"regexp"
	"strings"
	"testing"
)

func TestDashboardUsesOperationalAndPassiveTrafficLabels(t *testing.T) {
	index, err := webAssets.ReadFile("web/index.html")
	if err != nil {
		t.Fatal(err)
	}
	app, err := webAssets.ReadFile("web/app.js")
	if err != nil {
		t.Fatal(err)
	}
	content := string(index) + "\n" + string(app)

	for _, required := range []string{
		"Service health & dependencies",
		"DNS resolution",
		"dns_resolution",
		"Recent client traffic",
		"Observed ingress activity",
		"recent_client_traffic",
		"Inactivity is informational and does not indicate a service failure",
	} {
		if !strings.Contains(content, required) {
			t.Fatalf("dashboard is missing required operational label %q", required)
		}
	}

	lower := strings.ToLower(content)
	for _, forbidden := range []string{
		strings.Join([]string{"phone", "technitium"}, " & "),
		strings.Join([]string{"technitium", "dns"}, " "),
		strings.Join([]string{"client", "networks"}, " "),
		strings.Join([]string{"external", "acceptance", "test"}, " "),
		strings.Join([]string{"validated", "by", "an", "external"}, " "),
		strings.Join([]string{"first", "member's"}, " "),
		strings.Join([]string{"bachelor's", "project"}, " "),
		"10.36.74.241, 192.168.1.0/24",
	} {
		if strings.Contains(lower, strings.ToLower(forbidden)) {
			t.Fatalf("dashboard contains deployment-specific or unnecessary label %q", forbidden)
		}
	}
}

func TestDashboardAdvancedControlPlaneContract(t *testing.T) {
	index, err := webAssets.ReadFile("web/index.html")
	if err != nil {
		t.Fatal(err)
	}
	app, err := webAssets.ReadFile("web/app.js")
	if err != nil {
		t.Fatal(err)
	}
	html := string(index)
	javascript := string(app)
	for _, required := range []string{
		"route-strip-prefix", "route-request-timeout", "route-cache-enabled", "route-health-enabled",
		"cache-config-form", "cache-route-select", "telemetry-dialog", "telemetry-status-bars",
		"system-security-server-form", "system-security-admin-form", "system-security-edgeproxy-form",
		"system-waf-form", "system-edge-server-form", "system-edge-admin-form",
		`name="tls.enabled"`, `name="tls.cert_file"`, `name="tls.key_file"`,
		"graceful EdgeProxy generation restart", "Data-plane protocol",
		"/cache/purge", "load_balancing", "health_check", "/telemetry",
		"/api/v1/edgeproxy-settings", "/api/v1/waf", "/api/v1/edgeproxy/server", "/api/v1/edgeproxy/admin",
	} {
		if !strings.Contains(html+javascript, required) {
			t.Fatalf("advanced dashboard contract is missing %q", required)
		}
	}

	idPattern := regexp.MustCompile(`\bid="([^"]+)"`)
	seen := map[string]bool{}
	for _, match := range idPattern.FindAllStringSubmatch(html, -1) {
		if seen[match[1]] {
			t.Fatalf("duplicate DOM id %q", match[1])
		}
		seen[match[1]] = true
	}
	lookupPattern := regexp.MustCompile(`\$\('([^']+)'\)`)
	for _, match := range lookupPattern.FindAllStringSubmatch(javascript, -1) {
		if !seen[match[1]] {
			t.Fatalf("JavaScript references missing DOM id %q", match[1])
		}
	}
}

func TestDashboardThemeContract(t *testing.T) {
	index, err := webAssets.ReadFile("web/index.html")
	if err != nil {
		t.Fatal(err)
	}
	theme, err := webAssets.ReadFile("web/theme.js")
	if err != nil {
		t.Fatal(err)
	}
	styles, err := webAssets.ReadFile("web/styles.css")
	if err != nil {
		t.Fatal(err)
	}
	app, err := webAssets.ReadFile("web/app.js")
	if err != nil {
		t.Fatal(err)
	}
	html := string(index)
	javascript := string(theme)
	css := string(styles)

	if strings.Count(html, `data-theme-toggle`) != 2 {
		t.Fatalf("dashboard must expose synchronized theme toggles on the login and authenticated views")
	}
	for _, required := range []string{
		`<meta name="color-scheme" content="light dark">`,
		`<meta name="theme-color" content="#0b1020">`,
		`<script src="/assets/theme.js"></script>`,
		`class="theme-toggle"`,
		`class="theme-icon theme-icon-sun"`,
		`class="theme-icon theme-icon-moon"`,
	} {
		if !strings.Contains(html, required) {
			t.Fatalf("dashboard theme markup contract is missing %q", required)
		}
	}
	if themeIndex, stylesheetIndex := strings.Index(html, `/assets/theme.js`), strings.Index(html, `/assets/styles.css`); themeIndex < 0 || stylesheetIndex < 0 || themeIndex > stylesheetIndex {
		t.Fatal("theme bootstrap must execute before the stylesheet to avoid an incorrect first-paint theme")
	}

	for _, required := range []string{
		`securityedge.ui.theme`,
		`localStorage.getItem(storageKey)`,
		`localStorage.setItem(storageKey, theme)`,
		`matchMedia('(prefers-color-scheme: dark)')`,
		`systemPreference.addEventListener('change'`,
		`window.addEventListener('storage'`,
		`root.dataset.theme = currentTheme`,
		`hasUserPreference = true`,
		`data-theme-toggle`,
		`securityedge:themechange`,
		`return theme === 'light' ? '#f2f6fb' : '#0b1020';`,
	} {
		if !strings.Contains(javascript, required) {
			t.Fatalf("theme persistence/system-default contract is missing %q", required)
		}
	}
	for _, required := range []string{
		`:root {`,
		`color-scheme:dark`,
		`html[data-theme="light"] {`,
		`color-scheme:light`,
		`--bg:#f2f6fb`,
		`--text:#152238`,
		`--muted:#52647c`,
		`--chart-grid:#c8d4e3`,
		`.theme-toggle {`,
		`html[data-theme="light"] .editor-dialog`,
		`html[data-theme="light"] .telemetry-raw`,
		`html[data-theme="light"] .system-config-card[open] > summary`,
		`html[data-theme="light"] .connectivity-panel.status-degraded::before`,
		`html[data-theme="light"] .status-degraded .status-orb span`,
		`html[data-theme="light"] .degraded .node-dot`,
		`html[data-theme="light"] .legend-dot.degraded`,
		`html[data-theme="light"] .traffic-active .activity-dot`,
	} {
		if !strings.Contains(css, required) {
			t.Fatalf("dashboard light-theme stylesheet contract is missing %q", required)
		}
	}
	for _, required := range []string{
		`function cssColor(name, fallback)`,
		`cssColor('--chart-grid'`,
		`cssColor('--chart-requests'`,
		`cssColor('--chart-blocked'`,
		`window.addEventListener('securityedge:themechange'`,
	} {
		if !strings.Contains(string(app), required) {
			t.Fatalf("theme-aware chart contract is missing %q", required)
		}
	}
}

func TestDashboardClientFacingErrorsDoNotDoubleCountProxyCauses(t *testing.T) {
	app, err := webAssets.ReadFile("web/app.js")
	if err != nil {
		t.Fatal(err)
	}
	javascript := string(app)
	if !strings.Contains(javascript, "Number(m.client_errors||0)+Number(m.server_errors||0)") {
		t.Fatal("dashboard must derive client-facing errors from HTTP 4xx/5xx request counters")
	}
	if strings.Contains(javascript, "Number(m.client_errors||0)+Number(m.server_errors||0)+Number(m.proxy_errors||0)") {
		t.Fatal("dashboard must not double-count proxy_errors as additional client-facing requests")
	}
}

func TestDashboardClientCancellationsStayOutOfCompletedOutcomeRates(t *testing.T) {
	app, err := webAssets.ReadFile("web/app.js")
	if err != nil {
		t.Fatal(err)
	}
	javascript := string(app)
	for _, required := range []string{
		"const canceledRequests = Number(m.canceled_requests || 0)",
		"const completedOutcomes = Number(m.success || 0) + errors",
		"completedOutcomes > 0 ? `${pct(m.success_rate)} / ${pct(m.error_rate)}` : '— / —'",
		"canceled · no completed responses",
		"['Requests / canceled',`${fmt(m.requests)} / ${fmt(m.canceled_requests)}`]",
		"Number(m.success || 0) + Number(m.client_errors || 0) + Number(m.server_errors || 0) > 0",
	} {
		if !strings.Contains(javascript, required) {
			t.Fatalf("dashboard client-cancellation telemetry contract is missing %q", required)
		}
	}
}

func TestDashboardSecurityCancellationsStayOutOfDecisionRatesAndLatency(t *testing.T) {
	app, err := webAssets.ReadFile("web/app.js")
	if err != nil {
		t.Fatal(err)
	}
	javascript := string(app)
	for _, required := range []string{
		"function completedSecurityDecisions(total)",
		"const canceled = Math.max(0, Number(total?.canceled_requests || 0))",
		"const securityDecisions = completedSecurityDecisions(total)",
		"canceled · no completed decisions",
		"No completed security decisions",
		"msIf(total.latency?.p95_ms, securityDecisions > 0)",
		"completedSecurityDecisions(total) > 0",
		"${fmt(traffic.rejected)} rejected · ${fmt(traffic.canceled)} canceled",
	} {
		if !strings.Contains(javascript, required) {
			t.Fatalf("dashboard SecurityEdge-cancellation telemetry contract is missing %q", required)
		}
	}
}

func TestDashboardTrendPreservesTelemetryRateGaps(t *testing.T) {
	app, err := webAssets.ReadFile("web/app.js")
	if err != nil {
		t.Fatal(err)
	}
	javascript := string(app)
	for _, required := range []string{
		"point.edgeproxy?.request_rate_available === true",
		"requests: point.edgeproxy?.available === true",
		"filter(Number.isFinite)",
		"if (!Number.isFinite(value)) { segmentStarted = false; return; }",
	} {
		if !strings.Contains(javascript, required) {
			t.Fatalf("dashboard telemetry-gap contract is missing %q", required)
		}
	}
}

func TestDashboardTopbarKeepsPrimaryActionsBesideTitle(t *testing.T) {
	index, err := webAssets.ReadFile("web/index.html")
	if err != nil {
		t.Fatal(err)
	}
	styles, err := webAssets.ReadFile("web/styles.css")
	if err != nil {
		t.Fatal(err)
	}
	html := string(index)
	css := string(styles)

	for _, required := range []string{
		`class="eyebrow topbar-eyebrow"`,
		`class="topbar-row"`,
		`class="topbar-title-group"`,
		`id="last-updated" class="topbar-updated"`,
		`class="topbar-actions"`,
	} {
		if !strings.Contains(html, required) {
			t.Fatalf("dashboard topbar markup contract is missing %q", required)
		}
	}
	for _, required := range []string{
		`.topbar-row {`,
		`.topbar-title-group {`,
		`.topbar-actions {`,
		`.topbar-actions #refresh {`,
		`flex:0 0 auto`,
		`flex-direction:column`,
	} {
		if !strings.Contains(css, required) {
			t.Fatalf("dashboard topbar responsive contract is missing %q", required)
		}
	}
}

func TestDashboardResourceInputsMatchBackendSafetyLimits(t *testing.T) {
	index, err := webAssets.ReadFile("web/index.html")
	if err != nil {
		t.Fatal(err)
	}
	html := string(index)
	for _, required := range []string{
		`id="route-retry-count" type="number" min="0" max="10"`,
		`id="route-max-idle" type="number" min="1" max="1000000"`,
		`id="route-cache-entries" type="number" min="1" max="1000000"`,
		`id="route-cache-mib" type="number" min="1" max="65536"`,
		`id="route-cache-object-mib" type="number" min="0.001" max="1024"`,
		`name="upstream_transport.max_idle_conns" type="number" min="1" max="1000000"`,
		`name="upstream_transport.max_idle_conns_per_host" type="number" min="1" max="1000000"`,
		`name="upstream_transport.max_conns_per_host" type="number" min="0" max="1000000"`,
		`name="requests_per_second" type="number" step="0.1" min="0.1" max="1000000"`,
		`name="violation_threshold" type="number" min="1" max="10000"`,
		`name="max_tracked_clients" type="number" min="1" max="1000000"`,
	} {
		if !strings.Contains(html, required) {
			t.Fatalf("dashboard safety boundary is missing %q", required)
		}
	}
}

func TestDashboardAvoidsInlineStylesUnderStrictCSP(t *testing.T) {
	index, err := webAssets.ReadFile("web/index.html")
	if err != nil {
		t.Fatal(err)
	}
	app, err := webAssets.ReadFile("web/app.js")
	if err != nil {
		t.Fatal(err)
	}
	content := strings.ToLower(string(index) + "\n" + string(app))
	if strings.Contains(content, "style=\"") || strings.Contains(content, "style='") {
		t.Fatal("dashboard contains inline style attributes that are blocked by style-src 'self'")
	}
	if !strings.Contains(string(app), `class="bar-progress"`) {
		t.Fatal("dashboard bar visualization must use the CSP-safe progress element")
	}
}

func TestDashboardCoalescesRefreshesAndTimesOutRequests(t *testing.T) {
	app, err := webAssets.ReadFile("web/app.js")
	if err != nil {
		t.Fatal(err)
	}
	javascript := string(app)
	for _, required := range []string{
		"refreshPromise: null",
		"refreshQueued: false",
		"if (state.refreshPromise)",
		"state.refreshQueued = true",
		"while (state.refreshQueued && state.token)",
		"const requestTimeoutMS = 15000",
		"new AbortController()",
		"Request timed out after",
		"await loadEdgeLogs()",
	} {
		if !strings.Contains(javascript, required) {
			t.Fatalf("dashboard refresh-safety contract is missing %q", required)
		}
	}
	if strings.Contains(javascript, "URL.createObjectURL(new Blob([blob]") {
		t.Fatal("dashboard download creates a redundant second Blob")
	}
}

func TestDashboardPreservesAuthAndTelemetryTruthfulness(t *testing.T) {
	app, err := webAssets.ReadFile("web/app.js")
	if err != nil {
		t.Fatal(err)
	}
	javascript := string(app)
	for _, required := range []string{
		"if (!state.token) continue;",
		"Operations API unavailable",
		"edgeproxy_metrics_status_code",
		"return status >= 200 && status < 300 && typeof metrics?.schema_version === 'string'",
		"upstreamSamples > 0 ? `${ms(edgeTotal.upstream?.latency_ms?.average)} upstream avg` : 'No upstream samples'",
		"edgeStatusAvailable ? `${healthy}/${origins.length}` : '—'",
		"edgeStatusAvailable ? `${routes.filter(route => route.ready).length}/${routes.length} routes ready` : 'EdgeProxy status unavailable'",
		"return key ? routes[key] : null;",
		"routeReadyKnown ? (status.ready ? 'READY' : 'NOT READY') : 'UNKNOWN'",
		"healthKnown ? (live.healthy ? 'healthy' : 'unhealthy') : 'unknown'",
		"EdgeProxy telemetry unavailable.",
		"Runtime health unavailable.",
		"req/s avg since start",
		`trendRateLabel(edgeMetrics.requests_per_second)`,
		"while (numeric > 0 && Number(fixed) === 0 && decimals < 9)",
		"function percentageLabel(percent)",
		"while (decimals < 6 && ((numeric > 0 && rounded === 0) || (numeric < 100 && rounded === 100)))",
		"percentageLabel(component.availability_percent)",
		"pctIf(edgeTotal.cache_hit_ratio, cacheLookups > 0)",
		"function millisecondLabel(value, initialDecimals = 2)",
		"const ms = n => millisecondLabel(n, 2)",
		"millisecondLabel(latency, latency < 10 ? 2 : 1)",
		"msIf(total.latency?.p95_ms, securityDecisions > 0)",
		"const plotBounds = trendTimeBounds(displayTrend)",
		"const retainedBounds = trendTimeBounds(state.trend)",
		"unavailable intervals left blank, never zero-filled.",
		"function trendTemporalGaps(points)",
		"point.security?.rejected_rate_available === true",
		"pctIf(m.cache_hit_ratio, cacheLookups > 0)",
		"Number(component.checks || 0) > 0",
		"fmt(om.canceled)",
		"pctIf(om.success_rate, latencyAvailable)",
		"msIf(live.ewma_latency_ms, Number(live.scheduler_selections || 0) > 0)",
	} {
		if !strings.Contains(javascript, required) {
			t.Fatalf("dashboard authentication/telemetry truthfulness contract is missing %q", required)
		}
	}
}

func TestDashboardVisualControlStylesContract(t *testing.T) {
	styles, err := webAssets.ReadFile("web/styles.css")
	if err != nil {
		t.Fatal(err)
	}
	css := string(styles)
	for _, required := range []string{
		`overflow-x:hidden`,
		`.shell {`,
		`grid-template-columns:250px minmax(0,1fr)`,
		`min-height:100dvh`,
		`.sidebar {`,
		`position:fixed`,
		`inset:0 auto 0 0`,
		`height:100dvh`,
		`overflow-y:auto`,
		`main {`,
		`grid-column:2`,
		`.sidebar-foot {`,
		`flex:0 0 auto`,
		`.table-wrap {`,
		`overflow:auto`,
		`.policy-form input:not([type="checkbox"])`,
		`.editor-form input:not([type="checkbox"])`,
		`.switch-row input[type="checkbox"]`,
		`width:22px!important`,
		`.switch-row.compact {`,
		`height:40px`,
		`.editor-dialog {`,
		`position:fixed`,
		`top:50vh`,
		`left:50vw`,
		`transform:translate(-50%,-50%)`,
		`.wide-dialog .dialog-head {`,
		`padding:18px 18px 17px`,
		`.icon-button::before,.icon-button::after`,
		`place-items:center`,
		`.grid > .panel {`,
		`margin-bottom:0`,
		`.route-grid {`,
		`margin-bottom:18px`,
		`.origin-row {`,
		`.origin-actions,.table-actions {`,
		`.table-actions-heading,.table-actions-cell {`,
		`text-align:right`,
		`.system-config-grid {`,
		`align-items:start`,
		`.system-config-card[open] {`,
		`grid-column:1 / -1`,
		`#reload-config {`,
		`align-self:center`,
		`.system-config-card > summary:focus-visible`,
		`.config-editor-grid .panel-head {`,
		`grid-template-columns:minmax(0,1fr) max-content`,
		`.config-editor-grid .panel-head .top-actions {`,
		`justify-self:end`,
		`min-width:138px`,
		`.telemetry-detail-grid + .subsection {`,
		`padding:16px 18px 18px`,
		`.telemetry-detail-grid + .subsection .bar-list,`,
		`.editor-form > .form-grid + .switch-row {`,
		`margin-top:14px`,
	} {
		if !strings.Contains(css, required) {
			t.Fatalf("dashboard visual-control stylesheet contract is missing %q", required)
		}
	}
}

func TestDashboardOverviewTopologyFitsStandardDesktop(t *testing.T) {
	styles, err := webAssets.ReadFile("web/styles.css")
	if err != nil {
		t.Fatal(err)
	}
	css := string(styles)
	for _, required := range []string{
		`.connectivity-topology {`,
		`gap:8px`,
		`.topology-node {`,
		`min-width:150px`,
		`flex:1 1 168px`,
		`.topology-arrow {`,
		`flex:0 0 18px`,
	} {
		if !strings.Contains(css, required) {
			t.Fatalf("dashboard topology stylesheet contract is missing %q", required)
		}
	}
}

func TestDashboardRouteAndTableActionLayoutContract(t *testing.T) {
	index, err := webAssets.ReadFile("web/index.html")
	if err != nil {
		t.Fatal(err)
	}
	app, err := webAssets.ReadFile("web/app.js")
	if err != nil {
		t.Fatal(err)
	}
	content := string(index) + "\n" + string(app)
	for _, required := range []string{
		`class="origin-identity"`,
		`class="origin-actions"`,
		`class="table-actions"`,
		`class="table-actions-cell"`,
		`class="table-actions-heading"`,
		`<span class="sr-only">Actions</span>`,
	} {
		if !strings.Contains(content, required) {
			t.Fatalf("dashboard route/table action layout contract is missing %q", required)
		}
	}
}

func TestDashboardAccessibilityLabelsContract(t *testing.T) {
	index, err := webAssets.ReadFile("web/index.html")
	if err != nil {
		t.Fatal(err)
	}
	html := string(index)
	for _, required := range []string{
		`id="security-filters" class="filters" aria-label="Security event filters"`,
		`name="q" placeholder="Search" aria-label="Search security events"`,
		`name="action" aria-label="Filter by action"`,
		`name="client_ip" placeholder="Client IP" aria-label="Filter by client IP"`,
		`id="purge-form" class="filters" aria-label="Cache purge controls"`,
		`id="purge-route" required aria-label="Route to purge"`,
		`id="trend-chart" height="240" role="img" aria-label="Recent EdgeProxy request-rate and SecurityEdge rejection-rate trend" aria-describedby="trend-chart-summary"`,
		`id="trend-scale"`,
	} {
		if !strings.Contains(html, required) {
			t.Fatalf("dashboard accessibility contract is missing %q", required)
		}
	}
}

func TestDashboardTrendPresentationContract(t *testing.T) {
	index, err := webAssets.ReadFile("web/index.html")
	if err != nil {
		t.Fatal(err)
	}
	styles, err := webAssets.ReadFile("web/styles.css")
	if err != nil {
		t.Fatal(err)
	}
	app, err := webAssets.ReadFile("web/app.js")
	if err != nil {
		t.Fatal(err)
	}
	content := string(index) + "\n" + string(styles) + "\n" + string(app)
	for _, required := range []string{
		`class="panel trend-panel"`,
		`class="trend-legend" aria-label="Request-rate trend legend"`,
		`id="trend-requests-latest"`,
		`id="trend-blocked-latest"`,
		`id="trend-requests-coverage"`,
		`id="trend-blocked-coverage"`,
		`id="trend-window"`,
		`id="trend-empty" class="trend-empty" hidden`,
		`id="trend-chart-summary" class="trend-chart-summary"`,
		`function normalizeTrendHistory(history)`,
		`function trendDisplayPoints(points)`,
		`function niceTrendMaximum(value)`,
		`function trendQuantile(sortedValues, quantile)`,
		`function trendSeriesScaleProfile(values)`,
		`function trendScaleModel(seriesValues)`,
		`trendScaleModel([requestValues, blockedValues])`,
		`function trendLatestValue(key)`,
		`const value = state.trend[state.trend.length - 1][key];`,
		`function trendTemporalGaps(points)`,
		`function trendGapDurationLabel(milliseconds)`,
		`const blockedZeroOnly = blockedValues.length > 0 && blockedValues.every(value => value === 0);`,
		`No rejections ·`,
		`unavailable intervals left blank, never zero-filled.`,
		`id="trend-scale"`,
		`const scaleDetailText = !values.length`,
		`max ${trendRateLabel(rawMaximum, rawMaximum)} req/s`,
		`function trendTimeBounds(points)`,
		`const plotBounds = trendTimeBounds(displayTrend)`,
		`const retainedBounds = trendTimeBounds(state.trend)`,
		`.trend-chart-wrap`,
		`.trend-swatch.blocked`,
		`.trend-series-copy`,
		`.trend-status-item`,
	} {
		if !strings.Contains(content, required) {
			t.Fatalf("dashboard trend presentation contract is missing %q", required)
		}
	}
	if strings.Contains(string(app), `Math.max(1, ...values)`) {
		t.Fatal("trend chart still forces a 1 req/s minimum scale")
	}
	if strings.Contains(string(app), `for (let index = state.trend.length - 1; index >= 0; index -= 1)`) {
		t.Fatal("trend legend still carries a stale finite rate forward across trailing unavailability")
	}
	if strings.Contains(string(app), `trendMetaCard('trend-viewport'`) {
		t.Fatal("trend UI still renders a duplicate visible chart-viewport time card")
	}
}

func TestDashboardBrandingContract(t *testing.T) {
	index, err := webAssets.ReadFile("web/index.html")
	if err != nil {
		t.Fatal(err)
	}
	styles, err := webAssets.ReadFile("web/styles.css")
	if err != nil {
		t.Fatal(err)
	}
	html := string(index)
	css := string(styles)
	for _, required := range []string{
		`class="login-brand"`,
		`class="brand-mark" aria-hidden="true"><svg class="brand-shield"`,
		`class="brand-mark small" aria-hidden="true"><svg class="brand-shield"`,
		`class="brand-copy"`,
		`class="brand-shield-body"`,
		`class="brand-shield-check"`,
	} {
		if !strings.Contains(html, required) {
			t.Fatalf("dashboard branding markup contract is missing %q", required)
		}
	}
	if strings.Contains(html, `class="brand-mark">SE</div>`) || strings.Contains(html, `class="brand-mark small">SE</div>`) {
		t.Fatal("dashboard brand marks still expose the legacy SE text instead of the shield icon")
	}
	for _, required := range []string{
		`.brand-shield {`,
		`.brand-shield-body {`,
		`.brand-shield-check {`,
		`.login-brand {`,
		`justify-content:center`,
		`white-space:nowrap`,
		`.brand-copy {`,
	} {
		if !strings.Contains(css, required) {
			t.Fatalf("dashboard branding stylesheet contract is missing %q", required)
		}
	}
}

func TestDashboardResponsiveLayoutContract(t *testing.T) {
	styles, err := webAssets.ReadFile("web/styles.css")
	if err != nil {
		t.Fatal(err)
	}
	css := string(styles)
	for _, required := range []string{
		`@media(max-width:960px)`,
		`.route-card {
  min-width:0;`,
		`.route-grid {
    grid-template-columns:minmax(0,1fr)`,
		`scrollbar-width:none`,
		`.sidebar nav::-webkit-scrollbar`,
		`.sidebar nav::after {`,
		`flex:0 0 40px`,
		`.sidebar-foot {
    display:grid;`,
		`grid-template-columns:auto minmax(0,1fr) auto`,
		`.sidebar-foot #connection-label {`,
		`text-overflow:ellipsis`,
	} {
		if !strings.Contains(css, required) {
			t.Fatalf("dashboard responsive stylesheet contract is missing %q", required)
		}
	}
	if strings.Contains(css, `.sidebar-foot {
    display:none`) {
		t.Fatal("compact dashboard hides the connection status and Lock action")
	}
	if strings.Contains(css, "@media(max-width:900px)") || strings.Contains(css, "@media (max-width:900px)") {
		t.Fatal("dashboard still contains the obsolete 900px responsive breakpoint")
	}
	app, err := webAssets.ReadFile("web/app.js")
	if err != nil {
		t.Fatal(err)
	}
	javascript := string(app)
	for _, required := range []string{
		`const active = nav?.querySelector('.nav-item.active')`,
		`const navRect = nav.getBoundingClientRect()`,
		`const activeRect = active.getBoundingClientRect()`,
		`const visibleStart = nav.scrollLeft`,
		`const activeStart = visibleStart + activeRect.left - navRect.left`,
		`const itemBoundaries = [...nav.querySelectorAll('.nav-item')]`,
		`nav.scrollLeft = Math.max(0, Math.min(maxScroll, target))`,
		`window.addEventListener('resize', () => requestAnimationFrame(ensureActiveNavVisible))`,
		`const navResizeObserver = new ResizeObserver(() => requestAnimationFrame(ensureActiveNavVisible))`,
		`navResizeObserver.observe($('nav'))`,
	} {
		if !strings.Contains(javascript, required) {
			t.Fatalf("compact navigation visibility contract is missing %q", required)
		}
	}
}

func TestDashboardAuthenticationModalIsolationContract(t *testing.T) {
	index, err := webAssets.ReadFile("web/index.html")
	if err != nil {
		t.Fatal(err)
	}
	app, err := webAssets.ReadFile("web/app.js")
	if err != nil {
		t.Fatal(err)
	}
	html := string(index)
	javascript := string(app)

	for _, required := range []string{
		`id="login" class="modal visible" role="dialog" aria-modal="true" aria-labelledby="login-title" aria-describedby="login-description"`,
		`id="login-description"`,
		`id="token" type="password" autocomplete="current-password" autocapitalize="none" spellcheck="false" aria-describedby="login-error" autofocus required`,
		`id="app-shell" class="shell" inert`,
		`id="route-dialog" class="editor-dialog wide-dialog" aria-labelledby="route-dialog-title"`,
		`id="origin-dialog" class="editor-dialog" aria-labelledby="origin-dialog-title"`,
		`id="telemetry-dialog" class="editor-dialog wide-dialog" aria-labelledby="telemetry-dialog-title"`,
	} {
		if !strings.Contains(html, required) {
			t.Fatalf("dashboard authentication/dialog accessibility contract is missing %q", required)
		}
	}

	for _, required := range []string{
		`function setConsoleLocked(locked, focusLogin = false)`,
		`shell.inert = locked`,
		`$('token').focus({preventScroll:true})`,
		`$('token').value = ''`,
		`sessionRemove('securityedge_token')`,
		`catch (error) {`,
		`state.token = ''`,
		`if (response.status === 401) {`,
		`if (response.status === 429) {`,
		`else setConsoleLocked(true, true);`,
	} {
		if !strings.Contains(javascript, required) {
			t.Fatalf("dashboard authentication-state contract is missing %q", required)
		}
	}
}

func TestDashboardPreservesControlPlaneEditorState(t *testing.T) {
	app, err := webAssets.ReadFile("web/app.js")
	if err != nil {
		t.Fatal(err)
	}
	javascript := string(app)

	for _, required := range []string{
		"policyDirty: false",
		"cacheEditorDirty: false",
		"if (state.policyDirty) return;",
		"state.policyDirty = true",
		"else { state.selectedPolicy = 'default'; state.policyDirty = false; }",
		"const loadedCacheRoute = cacheSelect.dataset.loaded || '';",
		"const loadedStillExists = routes.some(route => route.name === loadedCacheRoute);",
		"if (!loadedStillExists || loadedCacheRoute !== selectedCacheRoute)",
		"else if (!state.cacheEditorDirty) loadCacheEditor(selectedCacheRoute);",
		"state.cacheEditorDirty = true",
		"state.cacheEditorDirty = false; loadCacheEditor(event.currentTarget.value);",
		"cacheForm.reset();",
		"$('save-cache-config').disabled = !cacheAvailable;",
		"loadPolicies().catch(error => toast(error.message))",
		"const results = await Promise.allSettled(requests);",
		"failures: results.filter(result => result.status === 'rejected')",
		"else toast(result.failures[0]);",
		"catch (error) { toast(error.message); }",
	} {
		if !strings.Contains(javascript, required) {
			t.Fatalf("dashboard control-plane editor resilience contract is missing %q", required)
		}
	}
}
