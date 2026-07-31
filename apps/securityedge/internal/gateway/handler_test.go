package gateway

import (
	"github.com/bachelor-project/edgeproxy-security/internal/config"
	"github.com/bachelor-project/edgeproxy-security/internal/metrics"
	"github.com/bachelor-project/edgeproxy-security/internal/ratelimit"
	"github.com/bachelor-project/edgeproxy-security/internal/routes"
	"github.com/bachelor-project/edgeproxy-security/internal/securitylog"
	"github.com/bachelor-project/edgeproxy-security/internal/waf"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

type policies struct{ p config.Policy }

func (p policies) Policy(string) config.Policy { return p.p }
func TestBlocksXSSBeforeNext(t *testing.T) {
	called := false
	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true })
	tableFile := t.TempDir() + "/edge.json"
	os.WriteFile(tableFile, []byte(`{"routes":[{"name":"demo-app","hosts":["project.test"],"path_prefix":"/"}]}`), 0600)
	table, _ := routes.Load(tableFile)
	p := config.Default().DefaultPolicy
	p.RateLimit.Enabled = false
	l := ratelimit.New(time.Hour, time.Hour)
	defer l.Close()
	h := New(next, table, policies{p}, waf.NewInspector(), l, metrics.New(), securitylog.New(10), slog.Default())
	req := httptest.NewRequest("GET", "http://project.test/?q=%3Cscript%3Ealert(1)%3C/script%3E", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden || called {
		t.Fatalf("status=%d called=%v", rec.Code, called)
	}
}
