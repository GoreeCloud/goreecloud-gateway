package config

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

type Config struct {
	Schema   string    `json:"schema"`
	Services []Service `json:"services"`
	Routes   []Route   `json:"routes"`
	Backends []Backend `json:"backends"`
}

type Service struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	BackendIDs []string `json:"backend_ids"`
}

type Route struct {
	ID         string   `json:"id"`
	ServiceID  string   `json:"service_id"`
	Hostname   string   `json:"hostname"`
	PathPrefix string   `json:"path_prefix"`
	Methods    []string `json:"methods"`
	Exposure   string   `json:"exposure"`
	Enabled    bool     `json:"enabled"`
}

type Backend struct {
	ID         string `json:"id"`
	URL        string `json:"url"`
	Enabled    bool   `json:"enabled"`
	HealthPath string `json:"health_path"`
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil { return nil, err }
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil { return nil, err }
	if err := cfg.Validate(); err != nil { return nil, err }
	return &cfg, nil
}

func (c *Config) Validate() error {
	if c.Schema != "goreecloud-gateway-config/v1" { return fmt.Errorf("unsupported schema %q", c.Schema) }
	services := map[string]Service{}
	backends := map[string]Backend{}
	for _, b := range c.Backends {
		if b.ID == "" || b.URL == "" { return fmt.Errorf("backend id and url are required") }
		if _, ok := backends[b.ID]; ok { return fmt.Errorf("duplicate backend %q", b.ID) }
		backends[b.ID] = b
	}
	for _, s := range c.Services {
		if s.ID == "" { return fmt.Errorf("service id is required") }
		if _, ok := services[s.ID]; ok { return fmt.Errorf("duplicate service %q", s.ID) }
		for _, id := range s.BackendIDs { if _, ok := backends[id]; !ok { return fmt.Errorf("service %q references missing backend %q", s.ID, id) } }
		services[s.ID] = s
	}
	seen := map[string]string{}
	for _, r := range c.Routes {
		if !r.Enabled { continue }
		if _, ok := services[r.ServiceID]; !ok { return fmt.Errorf("route %q references missing service %q", r.ID, r.ServiceID) }
		if r.Hostname == "" { return fmt.Errorf("route %q hostname is required", r.ID) }
		if r.PathPrefix == "" { r.PathPrefix = "/" }
		key := strings.ToLower(r.Hostname)+"\x00"+r.PathPrefix+"\x00"+strings.Join(r.Methods, ",")
		if prior, ok := seen[key]; ok { return fmt.Errorf("route %q conflicts with %q", r.ID, prior) }
		seen[key] = r.ID
	}
	return nil
}

func (c *Config) Service(id string) (Service, bool) { for _, s := range c.Services { if s.ID == id { return s, true } }; return Service{}, false }
func (c *Config) Backend(id string) (Backend, bool) { for _, b := range c.Backends { if b.ID == id { return b, true } }; return Backend{}, false }
