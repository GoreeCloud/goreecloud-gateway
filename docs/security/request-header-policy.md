# Gateway Request-Header Policy

## Status

Development runtime-enforcement candidate only. The Gateway proxy handler now applies the trusted-proxy and forwarding-identity policy described here, but this source state is not production ingress authority and does not change the current Caddy production boundary.

## Threat model

An Internet or otherwise untrusted client can send forwarding and client-identity headers that resemble metadata normally added by a trusted reverse proxy. Passing those fields upstream unchanged can allow an application to mistake client-controlled data for Gateway-observed connection identity.

GoreeCloud Gateway therefore keeps a strict separation between:

1. untrusted inbound request metadata;
2. Gateway-observed transport context; and
3. trusted forwarding metadata deliberately emitted by Gateway after policy evaluation.

## Runtime forwarding sanitization

The authoritative Development proxy handler resolves client identity before backend dispatch and removes client-supplied forwarding identity from the request.

`SanitizeInboundForwardingHeaders` removes:

- the complete client-supplied `X-Forwarded-*` namespace, including uncommon variants;
- `Forwarded`;
- `X-Real-IP`;
- `X-Client-IP`;
- `X-Original-Forwarded-For`;
- `X-Cluster-Client-IP`;
- `True-Client-IP`; and
- `CF-Connecting-IP`.

The forwarding-only sanitizer intentionally preserves ordinary application headers such as `Authorization`, `Cookie`, and application-specific metadata. Application authentication remains the responsibility of the application or its accepted authentication authority.

`SanitizeInboundProxyHeaders` remains available for contexts that require complete hop-by-hop cleanup, but the runtime reverse-proxy path does not use it before upgrade handling.

## Trusted-proxy runtime policy

The configuration-level `trusted_proxies` list accepts reviewed exact IP addresses or CIDR ranges. Configuration validation rejects malformed, empty, unspecified, multicast, zoned, and IPv4-mapped IPv6 trust entries before a normal Gateway startup or reload can accept them.

`TrustedProxyPolicy` then applies the following request-time rules:

- an untrusted direct peer is treated as the client and any supplied forwarding chain is ignored;
- an explicitly trusted direct peer must supply a valid IP-only `X-Forwarded-For` chain;
- the chain is evaluated from right to left;
- only addresses inside the configured trusted-proxy set are skipped;
- the first untrusted address becomes the resolved client address;
- a trusted peer with missing, malformed, or entirely trusted forwarding data fails closed; and
- IPv4 and IPv6 peers are supported without making a forwarding header authoritative by itself.

The proxy handler stores the validated Gateway configuration and trusted-proxy policy as one runtime state so a normal reload does not deliberately publish a new configuration with a mismatched trust policy.

## Gateway-derived forwarding metadata

After resolving the accepted client address and removing client-controlled forwarding identity, the Development proxy emits bounded replacement metadata for the backend:

- `X-Forwarded-For` from the resolved client address;
- `X-Forwarded-Host` from the original inbound request host; and
- `X-Forwarded-Proto` from the observed inbound transport (`https` only when the request reached the handler with TLS state, otherwise `http`).

The original inbound Host is preserved toward the backend instead of being replaced by the backend target host.

The runtime does not currently emit RFC `Forwarded`; applications must not infer authority from a missing or client-supplied `Forwarded` field.

## Upgrade and streaming safety

Go `net/http/httputil.ReverseProxy` remains responsible for hop-by-hop normalization and upgrade forwarding. Gateway's runtime security path therefore removes untrusted forwarding identity without preemptively deleting the `Connection` and `Upgrade` semantics needed for supported WebSocket and other HTTP upgrades.

The repository retains automated upgrade-tunneling and streaming tests. Exact-head CI must remain green before this source increment can be treated as validated Development evidence.

## Remaining production gates

This source integration closes only the repository-level wiring gap. Before Gateway can replace Caddy on the VPS, the exact candidate still requires:

- exact-head source, Platform Contract, isolated runtime, and sustained-load validation;
- current nine-system Integral Platform System evaluation and accepted evidence where applicable;
- target-VPS review of the actual Caddy configuration, listeners, certificates, Docker networks, host firewall, and published routes;
- direct and trusted-proxy IPv4/IPv6 acceptance in the target topology;
- TLS scheme and original-host acceptance against representative backends;
- WebSocket, streaming, and any applicable gRPC behavior on the target environment;
- privacy-minimized observability for client and forwarding identity;
- Caddy route, certificate, redirect, TLS, and error-behavior parity evidence;
- current backup and recovery verification;
- a reversible listener-transfer and rollback rehearsal; and
- explicit production migration approval followed by post-cutover verification.

Until those gates are satisfied, Caddy remains production-authoritative and GoreeCloud Gateway remains a Development candidate.
