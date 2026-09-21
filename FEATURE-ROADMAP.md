# GoreeCloud Gateway — Feature Roadmap

**Status:** Active roadmap control  
**As of:** 2026-09-21  
**Authoritative project record:** Project Specification — Gateway  
**Canonical repository:** GoreeCloud/goreecloud-gateway  
**Drive control:** `GoreeCloud/Feature Roadmap/GoreeCloud Gateway/FEATURE-ROADMAP.docx`

## Purpose

This file is the repository-side feature roadmap control for GoreeCloud Gateway. It records the exact Development candidate and the remaining target-VPS, governance, recovery, platform-system, and release gates for a possible controlled replacement of Caddy.

## Current verified Development checkpoint

Authoritative `main` remains `463474069ccb85202bc72125de9b1ea9226c0bea`. Draft PR #9 remains the active source candidate on `stabilize/caddy-replacement-20260918` at exact head `3dfd73e2ef46fa8910d85b2d7c5206fe9d3b6970`.

Fresh exact-head validation is green across Platform Contract `35630288270`, Repository Governance `35630287019`, Gateway Native Foundation `35630286980`, Gateway Isolated Runtime Acceptance `35630287189`, Gateway Isolated Sustained Load `35630287103`, and Gateway Vulnerability Reachability `35630287005`.

The candidate requires current Stable GLAZE UI V1.6 / 1.6.0 for any future administrative application but correctly leaves that integration blocked. Caddy remains production-authoritative. No VPS listener, firewall, DNS, certificate, Docker, or Caddy state has been changed. The next authoritative migration gate is the exact-candidate read-only Caddy/VPS preflight on `goreecloud-vps-01`; no authorized remote-shell connector is available in this ChatGPT environment.

## Roadmap

| ID | Feature / obligation | Priority | Current state |
| --- | --- | --- | --- |
| FR-001 | Keep repository/Drive roadmap and task controls synchronized with live authoritative state. | High | Ongoing control |
| FR-002 | Capture sanitized live Caddy/VPS route, listener, certificate, firewall, Docker-network, and 80/443 ownership baseline using the exact candidate collector. | P0 | Blocked here by unavailable authorized remote-shell execution |
| FR-003 | Build independently reviewed Caddy-to-Gateway route/backend/TLS migration-source parity evidence. | P0 | Open; depends on live preflight |
| FR-004 | Complete target certificate lifecycle rehearsal: registration/TOS, wrapping-key provisioning/escrow, staging DNS-01 issuance, renewal, failure/rate-limit handling, rollover/recovery. | P0 | Open |
| FR-005 | Package and run exact Gateway artifact beside Caddy on non-conflicting target ports; verify TLS/SNI, Host/forwarding identity, upgrades/streaming, health/failover, load, logs, and resources. | P0 | Open |
| FR-006 | Rehearse target backup/restore and reversible Caddy rollback before listener transfer. | P0 | Open |
| FR-007 | Transfer public listener ownership governance only after target acceptance supports it. | P0 | Blocked |
| FR-008 | Complete nine Integral Platform System integrations, current Glaze administrative experience, observability/security gates, release provenance, Production acceptance, and Stable qualification. | High | Open |
| FR-009 | Retire Caddy only after controlled cutover and post-cutover acceptance prove it is no longer required. | P0 | Not authorized |

## Maintenance and synchronization

This roadmap and the corresponding canonical Drive roadmap must remain materially synchronized with one another and with the authoritative project or service record. Update both copies whenever feature scope, priority, dependency, implementation status, cancellation, supersession, recommendation, or verification state materially changes.

No feature may be represented as complete or Stable solely because it appears in this roadmap. Completion and lifecycle claims require the applicable authoritative implementation, validation, review, release, production, and stabilization evidence.

## Reconciliation rule

At each material feature change, reconcile this roadmap against current authoritative repository state, the applicable platform-system requirements, and GoreeCloud Tasks Management. Missing obligations, stale status, duplicated work, roadmap drift, or undocumented disposition changes are defects to correct.
