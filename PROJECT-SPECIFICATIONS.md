# GoreeCloud Gateway — Project Specifications

**Repository:** `GoreeCloud/goreecloud-gateway`  
**Project type:** First-party infrastructure application and service  
**Lifecycle:** Active Development; Caddy remains production-authoritative  
**Migration baseline:** `da5dc01ba8bcee6236b2fa7da587022ed6c967d8`  
**License:** GNU AGPL-3.0 for GoreeCloud-owned source unless otherwise noted  
**Canonical authority:** This file becomes the authoritative project specification once accepted on the default branch.

## Migration and precedence

This file consolidates the former root `SPECIFICATIONS.md` with still-applicable requirements and historical context from Google Drive **Project Specification — Gateway.docx** (file ID `1zn5LS-Ce8RvPxxmUrEwhNUVK_FfrXGou`).

The repository and accepted `main` state control current implementation claims. Historical Drive candidate revisions and pre-integration branch descriptions remain provenance and must not override newer repository evidence.

Current implementation state is governed by `IMPLEMENTED-FEATURES.md`; open obligations by `PLANNED-FEATURES.md`; chronology by `CHANGELOGS.md`.

## 1. Project identity and purpose

GoreeCloud Gateway is the first-party GoreeCloud reverse proxy, application proxy, ingress controller, HTTPS gateway, certificate manager, routing/load-balancing platform, and controlled web-service publication system.

Gateway is intended eventually to replace the application-level production-gateway role currently served by Caddy while remaining original GoreeCloud software. Narrow protocol, cryptographic, standards, and other foundational dependencies may be used when appropriate, but a complete third-party reverse-proxy product must not become Gateway's application foundation or identity.

Gateway is both an infrastructure application providing administration, API, CLI, configuration workflows, status, and evidence, and an infrastructure service operating the HTTP/HTTPS data plane.

## 2. Scope and authority boundaries

Gateway owns approved HTTP/HTTPS publication, routing, proxy behavior, TLS termination, certificate orchestration, backend selection, and Gateway-owned configuration state.

Gateway does not become the authoritative DNS server, VPN/overlay network, firewall, identity provider, application authentication system, or general-purpose network-management platform. The applicable GoreeCloud platform systems retain their own authority.

Creating or discovering a backend does not authorize publication.

## 3. Control-plane and data-plane architecture

The control plane manages the administrative UI/API, canonical configuration, Service/Route/Backend objects, discovery proposals, certificate orchestration, validation/preview, audit/configuration history, rollback state, and status/evidence.

The data plane manages HTTP/HTTPS listeners, TLS termination, routing, reverse proxying, backend selection, health-aware failover, runtime policy enforcement, connection/backpressure controls, WebSocket/streaming behavior, metrics, and structured events.

A temporary control-plane failure should not unnecessarily terminate traffic already using the last-known-good data-plane configuration unless a security condition requires fail-closed behavior.

## 4. Core configuration model

Gateway uses first-party **Service**, **Route**, and **Backend** objects.

- A Service represents a logical application/service and may have routes and multiple backends.
- A Route defines approved match conditions and maps incoming traffic to a Service.
- A Backend is an actual destination such as a container, VM service, host-local service, or explicitly configured network endpoint.

A Backend may exist without publication. A Service may exist without a Route. A Route may remain draft or disabled.

Candidate configuration follows:

`Draft → Validate → Preview → Activate → Observe → Retain or Roll Back`

Validation must fail closed on unsafe or ambiguous state, including duplicate/conflicting routes, invalid backend targets, missing TLS requirements, listener conflicts, unsupported combinations, invalid access policies, unsafe public exposure, missing referenced objects, and required reachability/health failures.

An invalid candidate must never replace a known-good active configuration.

## 5. Publication classification

Every active publication requires an explicit classification:
- Internal
- Private
- Restricted Public
- Public

Private operation is the default.

Route activation requires validation of hostname/match intent, destination, TLS behavior, access policy, listener ownership, backend state, and conflicts.

Discovery produces proposed state only unless a separately governed automation policy explicitly authorizes a narrow activation workflow.

## 6. Proxy and traffic requirements

The product direction includes HTTP/1.1 and HTTP/2 reverse proxying, host/path/header/method matching, approved protocol-aware routing, WebSocket/streaming proxying, timeouts, connection limits, backpressure controls, backend health checks, graceful configuration reloads, redirects/header transforms, compression where appropriate, static/dynamic backends, and health-aware load balancing/failover.

HTTP/3 may be enabled only after separate dependency, security, runtime, performance, and production acceptance.

Backend endpoints must remain bounded to valid supported network targets and reject malformed or unsafe endpoint state.

## 7. HTTPS and certificate management

Gateway will provide first-party automatic HTTPS and certificate lifecycle management, including ACME account lifecycle, issuance/renewal, DNS-01, permitted HTTP-01/TLS-ALPN-01 paths, wildcard workflows, inventory/expiry/history/failure state, protected certificate/key storage boundaries, and approved internal/private certificate support.

Current Development source includes provider-neutral DNS-01 boundaries, a bounded Porkbun TXT adapter, RFC 8555 order-based DNS-01 issuance/renewal foundations, exact propagation/cleanup semantics, fresh key/CSR generation, encrypted ACME account-key persistence, registration/TOS controls, rollover preparation/execution, authority probing, recovery, and operator CLI wiring.

Those source capabilities do not establish live production CA/provider acceptance or target-VPS certificate parity.

Certificate failure must fail safely and must never silently downgrade intended HTTPS publication to unencrypted transport.

## 8. Dynamic discovery

Initial discovery focuses on Docker. Discovery may identify eligible workloads, networks, candidate ports, approved publication metadata, and conflicts, but must create proposed state rather than uncontrolled live publication.

Future adapters may support Kubernetes or other runtimes, but no external orchestrator is required for core Gateway operation.

## 9. Administrative experience and Glaze UI

Gateway will provide a first-party Glaze UI administrative experience covering Overview, Services, Routes, Backends, Certificates, Discovery, Access, Traffic, Logs, Security, Health, Configuration, and Settings as applicable.

Administrative presentation must use the current accepted Stable Glaze UI contract at candidate acceptance time and must truthfully present provider-owned state without manufacturing authorization, security, privacy, recovery, or operational truth.

Whole-application conformance requires rendered, accessibility, adaptive/form-factor, interaction, performance, resilience, rollback, and representative-target evidence; source mapping alone is insufficient.

## 10. Security requirements

Gateway is private by default.

Administrative write operations must be authenticated, authorized, auditable, bounded, least-privilege, and designed to prevent accidental broad exposure.

Gateway must protect credentials and secrets, certificate/private-key material, cookies/authentication material, sensitive request bodies/headers, administrative sessions, service identity/authorization context, configuration integrity, and dependency/supply-chain integrity.

Public exposure, listener ownership, certificate activation, route activation, and administrative changes require explicit authority and fail-closed validation.

## 11. Privacy requirements

Privacy Shield governs applicable Gateway privacy behavior.

Routine views, logs, metrics, and evidence must minimize data and must not expose reusable credentials, cookies, tokens, authentication material, private request bodies, or sensitive headers.

Requirements include minimal logging by default, explicit access-log controls, redaction, client-information minimization, retention controls, privacy-safe metrics/evidence, and separation of operationally necessary data from optional diagnostics.

## 12. Data, storage, recovery, and portability

Gateway must preserve sufficient canonical configuration and known-good history to recover from route, backend, TLS, redirect/header, WebSocket, health-check, exposure, or administrative-lockout regressions.

Required continuity direction includes configuration snapshots/history, export/import, certificate metadata preservation, backup/restore contracts, last-known-good retention, rollback, migration portability, disaster-recovery documentation, and recovery evidence.

Gateway must be recoverable without relying on undocumented runtime state.

## 13. API and CLI

Gateway will provide documented first-party API and CLI surfaces for approved health/status inspection, object listing, candidate configuration creation/modification, validation, activation, rollback, export/import, discovery review, and certificate-state inspection.

Write operations must remain authenticated, authorized, auditable, and bounded.

## 14. Integral Platform Systems

Stable qualification requires substantive, evidence-backed evaluation of all nine Integral Platform Systems:

- **GoreeCloud Manager** — bounded administration, lifecycle controls, approvals, operational visibility, remediation.
- **Privacy Shield** — logging minimization, redaction, retention, sensitive-data handling, privacy evidence.
- **Wardveil Security** — exposure/listener/route/TLS/backend/configuration-integrity security state.
- **Everkeep** — snapshots, export/import, backup/restore, rollback, recovery, migration continuity.
- **Glaze UI** — administrative presentation, interaction, accessibility, adaptive behavior, state semantics.
- **GoreeCloud Mesh** — governed service/capability coordination where applicable.
- **GoreeCloud Identity** — approved administrative/service identity without making Gateway the identity authority.
- **GoreeCloud Policy** — shared policy decisions/enforcement coordination while preserving Gateway-owned routing/publication-rule authority.
- **GoreeCloud Observability** — health, metrics, diagnostics, performance, dependency state, freshness, provenance, and operational evidence.

Names, badges, metadata, or documentation-only references are not integration evidence.

## 15. Deployment and operations

During Development, Gateway must use isolated/non-conflicting listeners and must not interfere with Caddy production authority.

Target production listener ownership, only after accepted cutover, is TCP 80 and TCP 443 for Gateway, plus UDP 443 only when HTTP/3 is separately approved.

Gateway must provide privacy-safe structured evidence for routing, backend health, connections, certificates, configuration activation/validation, proxy failures, latency where justified, security findings, and recovery state.

## 16. Caddy migration and cutover

Caddy remains production-authoritative until Gateway completes the full migration and production-acceptance process.

Required evidence includes independently reviewed migration-source identity; route/backend/listener/TLS parity; certificate issuance/renewal rehearsal; WebSocket/streaming and applicable HTTP/2/gRPC behavior; target Docker/network/firewall parity; production-representative load/latency/error/backpressure evidence; backup/restore and known-good recovery; reversible rollback to Caddy; observability; access parity; target-environment platform integrations; exact artifact/deployment identity; listener-ownership governance; and explicit production-cutover authorization.

Source CI, isolated runtime tests, and migration contracts may establish Development or rehearsal eligibility only. They do not authorize production cutover.

## 17. Testing and acceptance

Acceptance must remain exact-revision and evidence-bound.

Source-level gates include repository governance, Platform Contract validation, Gateway native foundation tests, isolated runtime acceptance, isolated sustained load, vulnerability reachability, configuration parity, and other applicable tests.

Production readiness additionally requires representative target-VPS/runtime evidence, security/privacy/recovery review, actual migration-source parity, deployment identity, rollback proof, and explicit approval.

Passing CI does not establish Release Candidate, Production Acceptance, Stable, or listener ownership.

## 18. Current accepted implementation boundary

Accepted `main` contains the Development foundation recorded in `IMPLEMENTED-FEATURES.md`, including first-party proxy/control-plane source, deterministic routing/backend selection, health-aware failover, streaming/upgraded connections, trusted-proxy/forwarding-identity controls, validation/recovery/rollback primitives, migration/parity evidence, Infrastructure Status/publication preflight, ACME/DNS-01 foundations, and source-level platform integration/evidence contracts.

It does not establish live target-VPS parity, production ACME/provider credentials or live issuance acceptance, production SLO/capacity evidence, target backup/restore/rollback, accepted runtime integration of all nine platform systems, production listener ownership, Caddy retirement, Release Candidate, Production Acceptance, or Stable status.

## 19. Maintenance and retirement

Maintain compatibility and migration safety across configuration schema, APIs, protocols, stored state, certificates, deployment tooling, and platform contracts.

Major architecture, ownership, licensing, repository, migration, production-cutover, rollback, or retirement decisions must be recorded in `PROJECT-RECORD.md`.

Gateway must not retire Caddy until Gateway is the authorized and verified production gateway and rollback remains proven.

## Related repository documentation

- [README.md](README.md)
- [PROJECT-RECORD.md](PROJECT-RECORD.md)
- [IMPLEMENTED-FEATURES.md](IMPLEMENTED-FEATURES.md)
- [PLANNED-FEATURES.md](PLANNED-FEATURES.md)
- [CHANGELOGS.md](CHANGELOGS.md)
- [FEATURES.md](FEATURES.md)
- [SECURITY.md](SECURITY.md)
- [BRANDING.md](BRANDING.md)
