package admin

import (
	"strings"
	"testing"
)

func TestDashboardUsesRoleBasedArchitectureLabels(t *testing.T) {
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
		"Client networks",
		"DNS resolution",
		"dns_resolution",
		"external acceptance test",
	} {
		if !strings.Contains(content, required) {
			t.Fatalf("dashboard is missing required role-based label %q", required)
		}
	}

	lower := strings.ToLower(content)
	for _, forbidden := range []string{
		"phone & technitium",
		"technitium dns",
		"first member's",
		"bachelor's project",
		"10.36.74.241, 192.168.1.0/24",
	} {
		if strings.Contains(lower, strings.ToLower(forbidden)) {
			t.Fatalf("dashboard contains deployment-specific label %q", forbidden)
		}
	}
}
