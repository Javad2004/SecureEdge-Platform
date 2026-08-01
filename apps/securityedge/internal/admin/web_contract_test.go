package admin

import (
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
