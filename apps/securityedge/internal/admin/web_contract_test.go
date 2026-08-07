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
