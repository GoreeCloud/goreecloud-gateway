// Package publication validates GoreeCloud Gateway publication policy before
// any data-plane configuration is generated or applied.
package publication

import (
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"strings"
)

const SchemaVersion = 1

const (
	ExposurePublic  = "public"
	ExposurePrivate = "private"
)

const maxRoutes = 256

type Config struct {
	SchemaVersion int     `json:"schema_version"`
	Routes        []Route `json:"routes"`
}

type Route struct {
	Hostname     string   `json:"hostname"`
	Upstream     string   `json:"upstream"`
	Exposure     string   `json:"exposure"`
	AllowedCIDRs []string `json:"allowed_cidrs,omitempty"`
}

func Validate(config Config) error {
	if config.SchemaVersion != SchemaVersion {
		return fmt.Errorf("unsupported publication schema version %d", config.SchemaVersion)
	}
	if len(config.Routes) == 0 {
		return errors.New("publication policy must contain at least one route")
	}
	if len(config.Routes) > maxRoutes {
		return fmt.Errorf("publication policy exceeds %d routes", maxRoutes)
	}

	seen := make(map[string]struct{}, len(config.Routes))
	for i, route := range config.Routes {
		if err := validateRoute(route); err != nil {
			return fmt.Errorf("route %d: %w", i, err)
		}
		host := strings.ToLower(route.Hostname)
		if _, ok := seen[host]; ok {
			return fmt.Errorf("route %d: duplicate hostname %q", i, route.Hostname)
		}
		seen[host] = struct{}{}
	}
	return nil
}

func validateRoute(route Route) error {
	if err := validateHostname(route.Hostname); err != nil {
		return err
	}
	if err := validateUpstream(route.Upstream); err != nil {
		return err
	}

	switch route.Exposure {
	case ExposurePublic:
		if len(route.AllowedCIDRs) != 0 {
			return errors.New("public route must not define allowed CIDRs")
		}
	case ExposurePrivate:
		if len(route.AllowedCIDRs) == 0 {
			return errors.New("private route requires at least one allowed CIDR")
		}
		for _, raw := range route.AllowedCIDRs {
			prefix, err := netip.ParsePrefix(raw)
			if err != nil || prefix.Masked().String() != raw {
				return fmt.Errorf("invalid canonical allowed CIDR %q", raw)
			}
		}
	default:
		return fmt.Errorf("unsupported exposure %q", route.Exposure)
	}
	return nil
}

func validateHostname(host string) error {
	if host == "" || host != strings.ToLower(host) || len(host) > 253 {
		return errors.New("hostname must be a non-empty lowercase DNS name")
	}
	if strings.ContainsAny(host, "/:@[]* ") || strings.HasPrefix(host, ".") || strings.HasSuffix(host, ".") {
		return errors.New("hostname must be a canonical DNS name without scheme, port, wildcard, or trailing dot")
	}
	labels := strings.Split(host, ".")
	if len(labels) < 2 {
		return errors.New("hostname must contain at least two DNS labels")
	}
	for _, label := range labels {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return errors.New("hostname contains an invalid DNS label")
		}
		for _, r := range label {
			if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
				return errors.New("hostname contains an invalid DNS label")
			}
		}
	}
	return nil
}

func validateUpstream(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return errors.New("upstream must be a valid URL")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return errors.New("upstream scheme must be http or https")
	}
	if u.Host == "" || u.User != nil {
		return errors.New("upstream must have a host and must not contain credentials")
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return errors.New("upstream must not contain query parameters or a fragment")
	}
	if u.Path != "" && u.Path != "/" {
		return errors.New("upstream must not contain an application path")
	}
	return nil
}
