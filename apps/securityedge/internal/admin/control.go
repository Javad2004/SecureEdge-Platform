package admin

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/Javad2004/SecureEdge-Platform/apps/securityedge/internal/config"
)

type configRuntime interface {
	ReplaceConfig(config.Config) error
	RedactedConfig() config.Config
	WatchStatusMap() map[string]any
}

func (s *Server) configurableRuntime(w http.ResponseWriter) (configRuntime, bool) {
	runtime, ok := s.runtime.(configRuntime)
	if !ok {
		writeError(w, http.StatusNotImplemented, "control_plane_unavailable", "runtime configuration control is unavailable")
	}
	return runtime, ok
}

func (s *Server) configGet(w http.ResponseWriter, _ *http.Request) {
	runtime, ok := s.configurableRuntime(w)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, runtime.RedactedConfig())
}

func (s *Server) configReplace(w http.ResponseWriter, r *http.Request) {
	runtime, ok := s.configurableRuntime(w)
	if !ok {
		return
	}
	var candidate config.Config
	if err := s.decodeJSON(r, &candidate); err != nil {
		writeAdminDecodeError(w, err)
		return
	}
	s.applySecurityConfig(w, runtime, candidate, "config_rejected")
}

func (s *Server) securityServerGet(w http.ResponseWriter, _ *http.Request) {
	runtime, ok := s.configurableRuntime(w)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, runtime.RedactedConfig().Server)
}

func (s *Server) securityServerUpdate(w http.ResponseWriter, r *http.Request) {
	runtime, ok := s.configurableRuntime(w)
	if !ok {
		return
	}
	var section config.ServerConfig
	if err := s.decodeJSON(r, &section); err != nil {
		writeAdminDecodeError(w, err)
		return
	}
	candidate := runtime.RedactedConfig()
	candidate.Server = section
	s.applySecurityConfig(w, runtime, candidate, "server_update_failed")
}

func (s *Server) securityAdminGet(w http.ResponseWriter, _ *http.Request) {
	runtime, ok := s.configurableRuntime(w)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, runtime.RedactedConfig().Admin)
}

func (s *Server) securityAdminUpdate(w http.ResponseWriter, r *http.Request) {
	runtime, ok := s.configurableRuntime(w)
	if !ok {
		return
	}
	var section config.AdminConfig
	if err := s.decodeJSON(r, &section); err != nil {
		writeAdminDecodeError(w, err)
		return
	}
	candidate := runtime.RedactedConfig()
	candidate.Admin = section
	s.applySecurityConfig(w, runtime, candidate, "admin_update_failed")
}

func (s *Server) securityEdgeProxyGet(w http.ResponseWriter, _ *http.Request) {
	runtime, ok := s.configurableRuntime(w)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, runtime.RedactedConfig().EdgeProxy)
}

func (s *Server) securityEdgeProxyUpdate(w http.ResponseWriter, r *http.Request) {
	runtime, ok := s.configurableRuntime(w)
	if !ok {
		return
	}
	var section config.EdgeProxyConfig
	if err := s.decodeJSON(r, &section); err != nil {
		writeAdminDecodeError(w, err)
		return
	}
	candidate := runtime.RedactedConfig()
	candidate.EdgeProxy = section
	s.applySecurityConfig(w, runtime, candidate, "edgeproxy_settings_update_failed")
}

func (s *Server) securityWAFGet(w http.ResponseWriter, _ *http.Request) {
	runtime, ok := s.configurableRuntime(w)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, runtime.RedactedConfig().WAF)
}

func (s *Server) securityWAFUpdate(w http.ResponseWriter, r *http.Request) {
	runtime, ok := s.configurableRuntime(w)
	if !ok {
		return
	}
	var section config.WAFConfig
	if err := s.decodeJSON(r, &section); err != nil {
		writeAdminDecodeError(w, err)
		return
	}
	candidate := runtime.RedactedConfig()
	candidate.WAF = section
	s.applySecurityConfig(w, runtime, candidate, "waf_update_failed")
}

func (s *Server) applySecurityConfig(w http.ResponseWriter, runtime configRuntime, candidate config.Config, errorCode string) {
	if err := runtime.ReplaceConfig(candidate); err != nil {
		var restart interface{ RestartRequired() bool }
		if errors.As(err, &restart) && restart.RestartRequired() {
			writeJSON(w, http.StatusAccepted, map[string]any{
				"accepted": true, "restart_required": true, "message": err.Error(),
				"watch": runtime.WatchStatusMap(),
			})
			return
		}
		writeError(w, http.StatusBadRequest, errorCode, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"applied": true, "watch": runtime.WatchStatusMap()})
}

func (s *Server) configWatch(w http.ResponseWriter, _ *http.Request) {
	runtime, ok := s.configurableRuntime(w)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, runtime.WatchStatusMap())
}

func (s *Server) edgeConfigGet(w http.ResponseWriter, r *http.Request) {
	s.forward(w, r, http.MethodGet, "/api/v1/config", nil)
}
func (s *Server) edgeConfigReplace(w http.ResponseWriter, r *http.Request) {
	body, ok := s.readForwardBody(w, r)
	if !ok {
		return
	}
	var summary struct {
		Routes []struct {
			Name string `json:"name"`
		} `json:"routes"`
	}
	if err := json.Unmarshal(body, &summary); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_body", err.Error())
		return
	}
	for policyRoute := range s.runtime.Config().RoutePolicies {
		found := false
		for _, route := range summary.Routes {
			if strings.EqualFold(strings.TrimSpace(policyRoute), strings.TrimSpace(route.Name)) {
				found = true
				break
			}
		}
		if !found {
			writeError(w, http.StatusConflict, "route_policy_conflict", "EdgeProxy config would remove a route that still has a SecurityEdge policy override")
			return
		}
	}
	s.forwardRawBody(w, r, http.MethodPut, "/api/v1/config", body)
}
func (s *Server) edgeConfigReload(w http.ResponseWriter, r *http.Request) {
	s.forwardAndReloadEdgeRoutes(w, r, http.MethodPost, "/api/v1/config/reload", nil)
}
func (s *Server) edgeConfigWatch(w http.ResponseWriter, r *http.Request) {
	s.forward(w, r, http.MethodGet, "/api/v1/config/watch", nil)
}
func (s *Server) edgeRoutesList(w http.ResponseWriter, r *http.Request) {
	s.forward(w, r, http.MethodGet, "/api/v1/routes", r.URL.Query())
}
func (s *Server) edgeRoutesCreate(w http.ResponseWriter, r *http.Request) {
	s.forwardBody(w, r, http.MethodPost, "/api/v1/routes")
}
func (s *Server) edgeRouteGet(w http.ResponseWriter, r *http.Request) {
	s.forward(w, r, http.MethodGet, edgeRoutePath(r), r.URL.Query())
}
func (s *Server) edgeRouteUpdate(w http.ResponseWriter, r *http.Request) {
	s.forwardBody(w, r, http.MethodPut, edgeRoutePath(r))
}
func (s *Server) edgeRouteDelete(w http.ResponseWriter, r *http.Request) {
	// Remove a matching SecurityEdge policy override before deleting the shared
	// route. This keeps the route-table watcher valid. If EdgeProxy rejects the
	// deletion, restore the policy so the two control planes remain transactional.
	routeName := r.PathValue("route")
	cfg := s.runtime.Config()
	var policyKey string
	var policy config.Policy
	for key, value := range cfg.RoutePolicies {
		if strings.EqualFold(key, routeName) {
			policyKey, policy = key, value
			break
		}
	}
	if policyKey != "" {
		if err := s.runtime.DeleteRoutePolicy(policyKey); err != nil {
			writeError(w, http.StatusConflict, "policy_cleanup_failed", err.Error())
			return
		}
	}
	raw, status, err := s.runtime.EdgeJSON(r.Context(), http.MethodDelete, edgeRoutePath(r), r.URL.Query(), nil)
	if err != nil || status >= http.StatusBadRequest {
		if policyKey != "" {
			if rollbackErr := s.runtime.UpdateRoutePolicy(policyKey, policy); rollbackErr != nil {
				writeError(w, http.StatusInternalServerError, "route_delete_rollback_failed", rollbackErr.Error())
				return
			}
		}
		if err != nil {
			writeError(w, http.StatusBadGateway, "edgeproxy_unavailable", err.Error())
			return
		}
		writeRaw(w, status, raw)
		return
	}
	if err := s.reloadEdgeRouteTable(); err != nil {
		writeError(w, http.StatusConflict, "route_table_reload_failed", err.Error())
		return
	}
	s.runtime.Audit("route_deleted", "EdgeProxy route and matching policy override deleted", map[string]string{"route": routeName})
	writeRaw(w, status, raw)
}
func (s *Server) edgeOriginsList(w http.ResponseWriter, r *http.Request) {
	s.forward(w, r, http.MethodGet, edgeOriginCollectionPath(r), r.URL.Query())
}
func (s *Server) edgeOriginsCreate(w http.ResponseWriter, r *http.Request) {
	s.forwardBody(w, r, http.MethodPost, edgeOriginCollectionPath(r))
}
func (s *Server) edgeOriginGet(w http.ResponseWriter, r *http.Request) {
	s.forward(w, r, http.MethodGet, edgeOriginPath(r), r.URL.Query())
}
func (s *Server) edgeOriginUpdate(w http.ResponseWriter, r *http.Request) {
	s.forwardBody(w, r, http.MethodPut, edgeOriginPath(r))
}
func (s *Server) edgeOriginDelete(w http.ResponseWriter, r *http.Request) {
	s.forwardAndReloadEdgeRoutes(w, r, http.MethodDelete, edgeOriginPath(r), r.URL.Query())
}

func edgeRoutePath(r *http.Request) string {
	return "/api/v1/routes/" + url.PathEscape(r.PathValue("route"))
}
func edgeOriginCollectionPath(r *http.Request) string { return edgeRoutePath(r) + "/origins" }
func edgeOriginPath(r *http.Request) string {
	return edgeOriginCollectionPath(r) + "/" + url.PathEscape(r.PathValue("origin"))
}

func (s *Server) forwardBody(w http.ResponseWriter, r *http.Request, method, path string) {
	body, ok := s.readForwardBody(w, r)
	if !ok {
		return
	}
	s.forwardRawBody(w, r, method, path, body)
}

func (s *Server) readForwardBody(w http.ResponseWriter, r *http.Request) (json.RawMessage, bool) {
	defer r.Body.Close()
	data, err := io.ReadAll(io.LimitReader(r.Body, s.cfg.MaxRequestBodyBytes+1))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_body", err.Error())
		return nil, false
	}
	if int64(len(data)) > s.cfg.MaxRequestBodyBytes {
		writeError(w, http.StatusRequestEntityTooLarge, "body_too_large", "request body exceeds the configured admin limit")
		return nil, false
	}
	if len(bytes.TrimSpace(data)) == 0 || !json.Valid(data) {
		writeError(w, http.StatusBadRequest, "invalid_body", "request body must contain valid JSON")
		return nil, false
	}
	return json.RawMessage(data), true
}

func (s *Server) forwardRawBody(w http.ResponseWriter, r *http.Request, method, path string, body json.RawMessage) {
	raw, status, err := s.runtime.EdgeJSON(r.Context(), method, path, r.URL.Query(), body)
	if err != nil {
		writeError(w, http.StatusBadGateway, "edgeproxy_unavailable", err.Error())
		return
	}
	if status < http.StatusBadRequest {
		if err := s.reloadEdgeRouteTable(); err != nil {
			writeError(w, http.StatusConflict, "route_table_reload_failed", "EdgeProxy accepted the change but SecurityEdge could not reload the shared route table: "+err.Error())
			return
		}
	}
	writeRaw(w, status, raw)
}

func (s *Server) forwardAndReloadEdgeRoutes(w http.ResponseWriter, r *http.Request, method, path string, query url.Values) {
	raw, status, err := s.runtime.EdgeJSON(r.Context(), method, path, query, nil)
	if err != nil {
		writeError(w, http.StatusBadGateway, "edgeproxy_unavailable", err.Error())
		return
	}
	if status < http.StatusBadRequest {
		if err := s.reloadEdgeRouteTable(); err != nil {
			writeError(w, http.StatusConflict, "route_table_reload_failed", "EdgeProxy accepted the change but SecurityEdge could not reload the shared route table: "+err.Error())
			return
		}
	}
	writeRaw(w, status, raw)
}

func (s *Server) reloadEdgeRouteTable() error {
	runtime, ok := s.runtime.(interface{ ReloadEdgeRoutes() error })
	if !ok {
		return nil
	}
	return runtime.ReloadEdgeRoutes()
}
