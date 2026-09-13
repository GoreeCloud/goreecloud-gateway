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

// SanitizeInboundProxyHeaders removes client-supplied forwarding identity and
// hop-by-hop request headers from an inbound request header set. The function
// deliberately does not add trusted forwarding metadata; that is a separate
// runtime-policy responsibility and must be derived from accepted connection
// context rather than copied from the client request.
func SanitizeInboundProxyHeaders(header http.Header) {
	if header == nil {
		return
	}

	// RFC connection options can name additional hop-by-hop headers. Remove the
	// named fields before deleting Connection itself.
	for _, token := range strings.Split(header.Get("Connection"), ",") {
		name := strings.TrimSpace(token)
		if name != "" {
			header.Del(name)
		}
	}

	for _, name := range hopByHopRequestHeaders {
		header.Del(name)
	}

	// Treat the whole X-Forwarded-* namespace as client-controlled. Enumerating
	// only familiar variants leaves room for an upstream application to trust a
	// less common forwarding field that Gateway accidentally passed through.
	// Iterate the actual map keys so even non-canonical casing is removed.
	for name := range header {
		if isUntrustedForwardingRequestHeader(name) {
			delete(header, name)
		}
	}
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
