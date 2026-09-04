# GoreeCloud Gateway

GoreeCloud Gateway is the planned first-party GoreeCloud reverse proxy, HTTPS gateway, ingress controller, certificate manager, routing/load-balancing system, and controlled web-service publication platform.

**Lifecycle:** Active Development

## Current accepted-main boundary

The accepted `main` branch is currently a governance, licensing, and branding foundation. It does **not** own production HTTP/HTTPS listener authority and does not contain the full native Gateway runtime.

Caddy remains production-authoritative for GoreeCloud web publication until Gateway completes migration-source parity, production-representative runtime, recovery/rollback, platform-integration, listener-transfer, and explicit production-acceptance gates.

Executable development remains isolated in separate draft pull requests, including the native foundation and Infrastructure Status/publication-preflight work. Their source/CI evidence must not be represented as accepted `main` behavior before their own review and merge gates are satisfied.

## Product role

Gateway is intended to provide:

- HTTP/HTTPS reverse proxying and TLS termination;
- automatic certificate lifecycle management;
- host, path, header, method, and approved protocol-aware routing;
- backend service definitions, health checks, load balancing, and failover;
- WebSocket and streaming proxying;
- staged configuration validation, preview, activation, history, and rollback;
- safe Docker-oriented service discovery and publication proposals;
- explicit Internal, Private, Restricted Public, and Public exposure classifications;
- privacy-minimized operational metrics and events;
- an administrative Glaze UI application, API, and CLI.

Gateway does not replace GoreeCloud DNS, Network, Identity, firewall policy, or application authentication. Those systems remain authoritative for their own domains.

## Production migration principle

Discovery or configuration must never publish a backend automatically. Production cutover from Caddy must be reversible and evidence-bound. A source build that can proxy traffic is not sufficient for production authority.

Required migration evidence includes configuration/route parity, TLS and renewal behavior, upgraded/streaming connections, production-representative load/backpressure, backup/restore, rollback, listener ownership, observability, required platform-system acceptance, and explicit cutover approval.

## GoreeCloud platform requirements

Stable qualification requires substantive, current accepted integration with:

- Glaze UI for the administrative application and adaptive/accessibility contract;
- Wardveil Security for exposure, listener, route, TLS, certificate, backend, and configuration-integrity security state;
- Privacy Shield for minimal logging, redaction, retention, sensitive-header protection, client-information minimization, and privacy-safe metrics;
- Everkeep for configuration snapshots, export/import, known-good retention, backup/restore, rollback, and disaster-recovery evidence;
- GoreeCloud Mesh for governed service coordination where applicable;
- GoreeCloud Identity for approved administrative identity/authentication without making Gateway the platform identity provider;
- GoreeCloud governance for publication and production-cutover authority.

Decorative identities do not satisfy these integration gates.

## Canonical identity

Branding authority is `GoreeCloud/goreecloud-branding-assets`. The canonical Gateway product artwork is `products/gateway/app-icon.svg`. Local artwork is a synchronized consumer derivative only and does not establish implementation or network authority.

See [BRANDING.md](BRANDING.md).

## Repository governance

This repository maintains the required root records:

- `README.md`
- `SPECIFICATIONS.md`
- `FEATURES.md`
- `BENEFITS.md`
- `COMPETITIVE-OBJECTIVES.md`
- `BRANDING.md`

The authoritative project record is `GoreeCloud/Projects/Project Specification — Gateway`; chronological implementation evidence is recorded in `GoreeCloud/Changelogs/Change Log — Gateway`.

## License

Unless otherwise noted, GoreeCloud-owned repository source is licensed under the GNU Affero General Public License version 3. Third-party dependencies and protocol/cryptographic libraries retain their own applicable licenses and notices.
