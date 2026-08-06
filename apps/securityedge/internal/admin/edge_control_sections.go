package admin

import (
	"net/http"
)

func (s *Server) edgeTelemetry(w http.ResponseWriter, r *http.Request) {
	s.forward(w, r, http.MethodGet, "/api/v1/telemetry", r.URL.Query())
}

func (s *Server) edgeRouteTelemetry(w http.ResponseWriter, r *http.Request) {
	s.forward(w, r, http.MethodGet, edgeRoutePath(r)+"/telemetry", r.URL.Query())
}

func (s *Server) edgeOriginTelemetry(w http.ResponseWriter, r *http.Request) {
	s.forward(w, r, http.MethodGet, edgeOriginPath(r)+"/telemetry", r.URL.Query())
}

func (s *Server) edgeServerGet(w http.ResponseWriter, r *http.Request) {
	s.forward(w, r, http.MethodGet, "/api/v1/server", r.URL.Query())
}

func (s *Server) edgeServerUpdate(w http.ResponseWriter, r *http.Request) {
	s.forwardBody(w, r, http.MethodPut, "/api/v1/server")
}

func (s *Server) edgeAdminGet(w http.ResponseWriter, r *http.Request) {
	s.forward(w, r, http.MethodGet, "/api/v1/admin", r.URL.Query())
}

func (s *Server) edgeAdminUpdate(w http.ResponseWriter, r *http.Request) {
	s.forwardBody(w, r, http.MethodPut, "/api/v1/admin")
}

func (s *Server) edgeLoadBalancingGet(w http.ResponseWriter, r *http.Request) {
	s.forward(w, r, http.MethodGet, edgeRoutePath(r)+"/load-balancing", r.URL.Query())
}

func (s *Server) edgeLoadBalancingUpdate(w http.ResponseWriter, r *http.Request) {
	s.forwardBody(w, r, http.MethodPut, edgeRoutePath(r)+"/load-balancing")
}

func (s *Server) edgeProxySettingsGet(w http.ResponseWriter, r *http.Request) {
	s.forward(w, r, http.MethodGet, edgeRoutePath(r)+"/proxy", r.URL.Query())
}

func (s *Server) edgeProxySettingsUpdate(w http.ResponseWriter, r *http.Request) {
	s.forwardBody(w, r, http.MethodPut, edgeRoutePath(r)+"/proxy")
}

func (s *Server) edgeRouteCacheGet(w http.ResponseWriter, r *http.Request) {
	s.forward(w, r, http.MethodGet, edgeRoutePath(r)+"/cache", r.URL.Query())
}

func (s *Server) edgeRouteCacheUpdate(w http.ResponseWriter, r *http.Request) {
	s.forwardBody(w, r, http.MethodPut, edgeRoutePath(r)+"/cache")
}

func (s *Server) edgeRouteCachePurge(w http.ResponseWriter, r *http.Request) {
	s.forward(w, r, http.MethodPost, edgeRoutePath(r)+"/cache/purge", r.URL.Query())
}

func (s *Server) edgeHealthCheckGet(w http.ResponseWriter, r *http.Request) {
	s.forward(w, r, http.MethodGet, edgeRoutePath(r)+"/health-check", r.URL.Query())
}

func (s *Server) edgeHealthCheckUpdate(w http.ResponseWriter, r *http.Request) {
	s.forwardBody(w, r, http.MethodPut, edgeRoutePath(r)+"/health-check")
}
