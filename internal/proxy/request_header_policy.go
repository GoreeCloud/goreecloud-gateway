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
	"X-Forwarded-For",
	"X-Forwarded-Host",
	"X-Forwarded-Proto",
	"X-Forwarded-Port",
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
	for _, name := range untrustedForwardingRequestHeaders {
		header.Del(name)
	}
}
