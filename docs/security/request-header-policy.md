# Gateway Request-Header Policy

## Status

Development security foundation only. The sanitizer and trusted-proxy address resolver in `internal/proxy` are not, by themselves, production ingress authority and do not change the current Caddy production boundary.

## Threat model

An Internet or otherwise untrusted client can send forwarding and client-identity headers that resemble metadata normally added by a trusted reverse proxy. Passing those fields upstream unchanged can allow an application to mistake client-controlled data for Gateway-observed connection identity.

GoreeCloud Gateway therefore needs a strict separation between:

1. untrusted inbound request metadata;
2. Gateway-observed transport context; and
3. trusted forwarding metadata deliberately emitted by an accepted Gateway policy.

## Development sanitizer

`SanitizeInboundProxyHeaders` removes:

- standard hop-by-hop request headers;
- additional hop-by-hop fields named by the inbound `Connection` header;
- the complete client-supplied `X-Forwarded-*` namespace, including uncommon variants rather than only a fixed subset;
- other forwarding and client-address headers such as `Forwarded`, `X-Real-IP`, and provider-specific client-IP fields.

The sanitizer intentionally preserves ordinary application headers such as `Authorization`, `Cookie`, and application-specific metadata. Application authentication remains the responsibility of the application or its accepted authentication authority.

## Trusted-proxy client-address foundation

`TrustedProxyPolicy` adds a separate, non-wired client-address derivation primitive for future reviewed ingress integration.

The policy:

- accepts only explicitly configured exact IP addresses or CIDR ranges as trusted proxy peers;
- rejects malformed, empty, unspecified, multicast, zoned, and IPv4-mapped IPv6 trust entries;
- treats an untrusted direct peer as the client and ignores any supplied forwarding chain;
- for an explicitly trusted direct peer, parses `X-Forwarded-For` strictly as an IP-only chain and walks it from right to left;
- skips only addresses that are themselves inside the configured trusted-proxy set;
- returns the first untrusted address as the candidate client identity;
- fails closed when a trusted peer supplies no chain, a malformed chain, or a chain containing only trusted proxy addresses;
- supports ordinary IPv4 and IPv6 peers without converting a forwarding header into authority by itself.

This primitive does not read configuration from the environment, does not mutate requests, does not emit forwarding headers, and is not invoked by the authoritative proxy handler in this Development slice. A later integration must bind the reviewed trusted-proxy configuration to the accepted listener/runtime and prove the sequencing between peer validation, client-address derivation, sanitization, and backend forwarding.

## No implicit trust reconstruction

The current source still does not create replacement `Forwarded` or `X-Forwarded-*` values. A later runtime integration must derive any trusted forwarding metadata from accepted connection context and an explicit Gateway policy. Client-supplied values must never be used as the source of that identity unless the direct peer and forwarding chain have passed the separately configured trusted-proxy policy.

## Required runtime integration gates

Before these primitives are wired into authoritative ingress, the Gateway runtime must define and test:

- the exact point at which peer trust and client-address derivation occur;
- the exact point at which sanitization occurs before backend dispatch;
- the reviewed source and lifecycle for trusted-proxy CIDRs;
- client-address derivation for IPv4 and IPv6 across direct and proxied connections;
- TLS scheme and original-host derivation;
- WebSocket and HTTP upgrade behavior after hop-by-hop normalization;
- privacy-minimized observability for forwarded identity;
- Caddy parity tests and migration evidence;
- rollback behavior and independent runtime acceptance.

Until those gates are satisfied, Caddy remains production-authoritative and this code remains a bounded native security primitive.
