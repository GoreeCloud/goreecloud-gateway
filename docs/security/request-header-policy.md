# Gateway Request-Header Policy

## Status

Development security foundation only. The sanitizer in `internal/proxy` is not, by itself, production ingress authority and does not change the current Caddy production boundary.

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

## No implicit trust reconstruction

This slice deliberately does not create replacement `Forwarded` or `X-Forwarded-*` values. A later runtime integration must derive any trusted forwarding metadata from accepted connection context and an explicit Gateway policy. Client-supplied values must never be used as the source of that identity unless a separately configured trusted-proxy chain has been validated.

## Required runtime integration gates

Before the sanitizer is wired into authoritative ingress, the Gateway runtime must define and test:

- the exact point at which sanitization occurs before backend dispatch;
- trusted proxy and direct-client connection semantics;
- client-address derivation for IPv4 and IPv6;
- TLS scheme and original-host derivation;
- WebSocket and HTTP upgrade behavior after hop-by-hop normalization;
- privacy-minimized observability for forwarded identity;
- Caddy parity tests and migration evidence;
- rollback behavior and independent runtime acceptance.

Until those gates are satisfied, Caddy remains production-authoritative and this code remains a bounded native security primitive.
