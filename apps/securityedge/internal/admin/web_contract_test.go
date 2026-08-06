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
		"/cache/purge", "load_balancing", "health_check", "/telemetry",
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
