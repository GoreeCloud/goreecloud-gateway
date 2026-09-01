# GoreeCloud Gateway Architecture

## Current State

GoreeCloud publication is currently served by Caddy. GoreeCloud Gateway has branding and product identity but has not yet replaced the runtime data plane.

Gateway now owns two mutation-free control-plane boundaries: Infrastructure Status v1 and publication-policy preflight. A configured local publication file is size-bounded, decoded with unknown fields rejected, validated for route/exposure/upstream safety, and converted into a deterministic plan before the development service starts.

## Proposed State

GoreeCloud Gateway becomes the GoreeCloud-owned ingress and publication control plane. It will own service-publication policy, HTTPS policy, certificate lifecycle orchestration, configuration validation, reconciliation, and sanitized operational status. A proven proxy implementation may remain the data plane until Gateway's native data-plane work is independently accepted.

## Required Changes

1. **Implemented:** establish a strict Infrastructure Status v1 boundary.
2. **Implemented:** add publication configuration, strict local loading, validation, and deterministic planning without exposing a mutation API.
3. Add a restricted reconciler for the current Caddy data plane.
4. Add transactional configuration generation, validation, reload, and rollback.
5. Add certificate lifecycle orchestration without exposing private key material to Manager.
6. Add readiness, monitoring, backup/restore, upgrade/rollback, and security acceptance.
7. Replace transitional Caddy authority only after native Gateway data-plane acceptance proves parity and rollback safety.

## Dependencies

- GoreeCloud DNS for authoritative/resolver coordination.
- GoreeCloud Network for private service reachability and network policy.
- GoreeCloud Manager as a read-only status consumer, never an infrastructure mutation authority.
- GoreeCloud Identity, Privacy Shield, Wardveil Security, Mesh, Monitoring, and Everkeep according to platform policy.

## Security Boundary

The development control plane binds to `127.0.0.1:9080` by default and exposes only liveness and sanitized status. Publication policy is read only from an explicitly configured local file and is not returned by the HTTP service. Rejected policy input is not echoed by the loader, and validated policy is not applied to Caddy in this slice. No route mutation, certificate mutation, credential management, or Caddy admin proxy is implemented yet.
