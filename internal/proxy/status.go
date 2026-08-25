package proxy

import "time"

const RuntimeStatusSchemaV1 = "goreecloud-gateway-runtime-status/v1"

// RuntimeStatus is a privacy-safe aggregate snapshot of Gateway data-plane
// state. It intentionally excludes hostnames, backend URLs, request data,
// headers, client identifiers, credentials, and other sensitive material.
type RuntimeStatus struct {
	Schema          string    `json:"schema"`
	GeneratedAt     time.Time `json:"generated_at"`
	Services        int       `json:"services"`
	Routes          int       `json:"routes"`
	Backends        int       `json:"backends"`
	HealthyBackends int       `json:"healthy_backends"`
	Unhealthy       int       `json:"unhealthy_backends"`
	Unknown         int       `json:"unknown_backends"`
}

// StatusSnapshot returns aggregate runtime evidence suitable for later
// Wardveil Security, Privacy Shield, Monitor, and Manager adapters without
// exposing request content or infrastructure identifiers.
func (h *Handler) StatusSnapshot(now time.Time) RuntimeStatus {
	status := RuntimeStatus{Schema: RuntimeStatusSchemaV1, GeneratedAt: now}
	cfg := h.cfg.Load()
	if cfg == nil {
		return status
	}

	status.Services = len(cfg.Services)
	for _, route := range cfg.Routes {
		if route.Enabled {
			status.Routes++
		}
	}
	for _, backend := range cfg.Backends {
		if !backend.Enabled {
			continue
		}
		status.Backends++
		h.healthMu.RLock()
		state, ok := h.healthState[backend.ID]
		h.healthMu.RUnlock()
		if !ok {
			status.Unknown++
			continue
		}
		if state.result.Healthy {
			status.HealthyBackends++
		} else {
			status.Unhealthy++
		}
	}
	return status
}
