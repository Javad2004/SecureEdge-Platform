package admin

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"unicode/utf8"

	"github.com/Javad2004/SecureEdge-Platform/apps/edgeproxy/internal/config"
	"github.com/Javad2004/SecureEdge-Platform/apps/edgeproxy/internal/control"
)

const maxControlBodyBytes int64 = 4 << 20

func (s *Server) configGet(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.controller.Config())
}

func (s *Server) configReplace(w http.ResponseWriter, r *http.Request) {
	var candidate config.Config
	if err := decodeControlJSON(r, &candidate); err != nil {
		writeControlDecodeError(w, err)
		return
	}
	result, err := s.controller.Replace(candidate, "admin_replace")
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "config_rejected", err.Error())
		return
	}
	writeApplyResult(w, result)
}

func (s *Server) configReload(w http.ResponseWriter, _ *http.Request) {
	result, err := s.controller.Reload("admin_reload")
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "reload_failed", err.Error())
		return
	}
	writeApplyResult(w, result)
}

func (s *Server) configWatch(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.controller.WatchStatus())
}

func (s *Server) routesList(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"routes": s.controller.Config().Routes})
}

func (s *Server) routesCreate(w http.ResponseWriter, r *http.Request) {
	var route config.RouteConfig
	if err := decodeControlJSON(r, &route); err != nil {
		writeControlDecodeError(w, err)
		return
	}
	result, err := s.controller.Update(func(cfg *config.Config) error {
		if _, exists := control.FindRoute(cfg, route.Name); exists {
			return fmt.Errorf("route %q already exists", route.Name)
		}
		cfg.Routes = append(cfg.Routes, route)
		return nil
	}, "admin_create_route")
	if err != nil {
		writeAPIError(w, http.StatusConflict, "route_create_failed", err.Error())
		return
	}
	writeCreateResult(w, result)
}

func (s *Server) routeGet(w http.ResponseWriter, r *http.Request) {
	cfg := s.controller.Config()
	index, ok := control.FindRoute(&cfg, r.PathValue("route"))
	if !ok {
		writeAPIError(w, http.StatusNotFound, "route_not_found", "route was not found")
		return
	}
	writeJSON(w, http.StatusOK, cfg.Routes[index])
}

func (s *Server) routeUpdate(w http.ResponseWriter, r *http.Request) {
	var route config.RouteConfig
	if err := decodeControlJSON(r, &route); err != nil {
		writeControlDecodeError(w, err)
		return
	}
	name := r.PathValue("route")
	result, err := s.controller.Update(func(cfg *config.Config) error {
		index, ok := control.FindRoute(cfg, name)
		if !ok {
			return errNotFound
		}
		if !strings.EqualFold(strings.TrimSpace(route.Name), strings.TrimSpace(cfg.Routes[index].Name)) {
			return errors.New("route names are immutable; create a new route and delete the old route instead")
		}
		route.Name = cfg.Routes[index].Name
		cfg.Routes[index] = route
		return nil
	}, "admin_update_route")
	writeMutationResult(w, result, err, "route_not_found", "route_update_failed")
}

func (s *Server) routeDelete(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("route")
	result, err := s.controller.Update(func(cfg *config.Config) error {
		index, ok := control.FindRoute(cfg, name)
		if !ok {
			return errNotFound
		}
		cfg.Routes = append(cfg.Routes[:index], cfg.Routes[index+1:]...)
		return nil
	}, "admin_delete_route")
	writeMutationResult(w, result, err, "route_not_found", "route_delete_failed")
}

func (s *Server) originsList(w http.ResponseWriter, r *http.Request) {
	cfg := s.controller.Config()
	index, ok := control.FindRoute(&cfg, r.PathValue("route"))
	if !ok {
		writeAPIError(w, http.StatusNotFound, "route_not_found", "route was not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"origins": cfg.Routes[index].Upstreams})
}

func (s *Server) originsCreate(w http.ResponseWriter, r *http.Request) {
	var origin config.UpstreamConfig
	if err := decodeControlJSON(r, &origin); err != nil {
		writeControlDecodeError(w, err)
		return
	}
	routeName := r.PathValue("route")
	result, err := s.controller.Update(func(cfg *config.Config) error {
		index, ok := control.FindRoute(cfg, routeName)
		if !ok {
			return errNotFound
		}
		route := &cfg.Routes[index]
		if _, exists := control.FindOrigin(route, origin.Name); exists {
			return fmt.Errorf("origin %q already exists", origin.Name)
		}
		route.Upstreams = append(route.Upstreams, origin)
		return nil
	}, "admin_create_origin")
	if errors.Is(err, errNotFound) {
		writeAPIError(w, http.StatusNotFound, "route_not_found", "route not found")
		return
	}
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "origin_create_failed", err.Error())
		return
	}
	writeCreateResult(w, result)
}

func (s *Server) originGet(w http.ResponseWriter, r *http.Request) {
	cfg := s.controller.Config()
	routeIndex, ok := control.FindRoute(&cfg, r.PathValue("route"))
	if !ok {
		writeAPIError(w, http.StatusNotFound, "route_not_found", "route was not found")
		return
	}
	originIndex, ok := control.FindOrigin(&cfg.Routes[routeIndex], r.PathValue("origin"))
	if !ok {
		writeAPIError(w, http.StatusNotFound, "origin_not_found", "origin was not found")
		return
	}
	writeJSON(w, http.StatusOK, cfg.Routes[routeIndex].Upstreams[originIndex])
}

func (s *Server) originUpdate(w http.ResponseWriter, r *http.Request) {
	var origin config.UpstreamConfig
	if err := decodeControlJSON(r, &origin); err != nil {
		writeControlDecodeError(w, err)
		return
	}
	routeName, originName := r.PathValue("route"), r.PathValue("origin")
	result, err := s.controller.Update(func(cfg *config.Config) error {
		routeIndex, ok := control.FindRoute(cfg, routeName)
		if !ok {
			return errNotFound
		}
		route := &cfg.Routes[routeIndex]
		originIndex, ok := control.FindOrigin(route, originName)
		if !ok {
			return errNotFound
		}
		if other, exists := control.FindOrigin(route, origin.Name); exists && other != originIndex {
			return fmt.Errorf("origin %q already exists", origin.Name)
		}
		route.Upstreams[originIndex] = origin
		return nil
	}, "admin_update_origin")
	writeMutationResult(w, result, err, "origin_not_found", "origin_update_failed")
}

func (s *Server) originDelete(w http.ResponseWriter, r *http.Request) {
	routeName, originName := r.PathValue("route"), r.PathValue("origin")
	result, err := s.controller.Update(func(cfg *config.Config) error {
		routeIndex, ok := control.FindRoute(cfg, routeName)
		if !ok {
			return errNotFound
		}
		route := &cfg.Routes[routeIndex]
		originIndex, ok := control.FindOrigin(route, originName)
		if !ok {
			return errNotFound
		}
		if len(route.Upstreams) == 1 {
			return errors.New("a route must retain at least one origin")
		}
		route.Upstreams = append(route.Upstreams[:originIndex], route.Upstreams[originIndex+1:]...)
		return nil
	}, "admin_delete_origin")
	writeMutationResult(w, result, err, "origin_not_found", "origin_delete_failed")
}

var errNotFound = errors.New("not found")

func writeMutationResult(w http.ResponseWriter, result control.ApplyResult, err error, notFoundCode, failureCode string) {
	if errors.Is(err, errNotFound) {
		writeAPIError(w, http.StatusNotFound, notFoundCode, strings.ReplaceAll(notFoundCode, "_", " "))
		return
	}
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, failureCode, err.Error())
		return
	}
	writeApplyResult(w, result)
}

func writeCreateResult(w http.ResponseWriter, result control.ApplyResult) {
	status := http.StatusCreated
	if result.RestartRequired {
		status = http.StatusAccepted
	}
	writeJSON(w, status, result)
}

func writeApplyResult(w http.ResponseWriter, result control.ApplyResult) {
	status := http.StatusOK
	if result.RestartRequired {
		status = http.StatusAccepted
	}
	writeJSON(w, status, result)
}

func decodeControlJSON(r *http.Request, target any) error {
	defer r.Body.Close()
	data, err := io.ReadAll(io.LimitReader(r.Body, maxControlBodyBytes+1))
	if err != nil {
		return err
	}
	if int64(len(data)) > maxControlBodyBytes {
		return fmt.Errorf("request body exceeds %d bytes", maxControlBodyBytes)
	}
	if !utf8.Valid(data) {
		return errors.New("request body must be valid UTF-8")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("request body must contain exactly one JSON value")
		}
		return err
	}
	return nil
}

func writeControlDecodeError(w http.ResponseWriter, err error) {
	status := http.StatusBadRequest
	code := "invalid_body"
	if strings.Contains(err.Error(), "exceeds") {
		status = http.StatusRequestEntityTooLarge
		code = "body_too_large"
	}
	writeAPIError(w, status, code, err.Error())
}
