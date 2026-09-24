package proxy

import (
	"net/http"
	"strings"
)

var hopByHopRequestHeaders = []string{
	"Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Proxy-Connection",
	"TE",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
}

var untrustedForwardingRequestHeaders = []string{
	"Forwarded",
	"X-Real-IP",
	"X-Client-IP",
	"X-Original-Forwarded-For",
	"X-Cluster-Client-IP",
	"True-Client-IP",
	"CF-Connecting-IP",
}

// SanitizeInboundForwardingHeaders removes client-supplied forwarding identity
// without touching HTTP upgrade semantics. The authoritative reverse-proxy
// runtime uses this before emitting forwarding metadata derived from accepted
// connection context.
func SanitizeInboundForwardingHeaders(header http.Header) {
	if header == nil {
		return
	}
	for name := range header {
		if isUntrustedForwardingRequestHeader(name) {
			delete(header, name)
		}
	}
}

// SanitizeInboundProxyHeaders removes client-supplied forwarding identity and
// hop-by-hop request headers. Runtime ingress should prefer the forwarding-only
// sanitizer and allow net/http/httputil.ReverseProxy to normalize hop-by-hop
// headers so WebSocket and other supported upgrades remain functional.
func SanitizeInboundProxyHeaders(header http.Header) {
	if header == nil {
		return
	}

	for _, token := range strings.Split(header.Get("Connection"), ",") {
		name := strings.TrimSpace(token)
		if name != "" {
			header.Del(name)
		}
	}

	for _, name := range hopByHopRequestHeaders {
		header.Del(name)
	}
	SanitizeInboundForwardingHeaders(header)
}

func isUntrustedForwardingRequestHeader(name string) bool {
	if strings.HasPrefix(strings.ToLower(name), "x-forwarded-") {
		return true
	}
	for _, blocked := range untrustedForwardingRequestHeaders {
		if strings.EqualFold(name, blocked) {
			return true
		}
	}
	return false
}
