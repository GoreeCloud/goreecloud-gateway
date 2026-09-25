# GoreeCloud Gateway — Project Record

**Repository:** `GoreeCloud/goreecloud-gateway`  
**Lifecycle:** Active Development; production gateway authority remains with Caddy  
**Migration baseline:** `da5dc01ba8bcee6236b2fa7da587022ed6c967d8`  
**Record purpose:** Significant project history, architecture/governance decisions, migration evidence, lifecycle boundaries, and project-document migration provenance  
**Canonical authority:** This file becomes the repository-local project record once accepted on the default branch.

## Project origin and first-party direction

GoreeCloud Gateway was defined as an original GoreeCloud-owned reverse proxy, HTTPS gateway, ingress controller, certificate manager, routing/load-balancing system, and controlled web-service publication platform.

The governing product decision is to replace the application-level role of Caddy only after a reversible, evidence-backed migration. Caddy, Traefik, and Nginx Proxy Manager may inform requirements and interoperability, but Gateway is not a fork or rebranding of those products.

The original Drive specification established the Service / Route / Backend model, explicit publication classifications, staged configuration lifecycle, control-plane/data-plane separation, first-party administrative UI, certificate lifecycle, Docker discovery, rollback, and platform-system integration requirements.

## 2026-08 — Native Development foundation

During August 2026 the Development line accumulated exact-revision source and isolated-runtime evidence for first-party proxy/routing foundations, WebSocket/streaming behavior, configuration validation and last-known-good recovery, migration-evidence contracts, deterministic configuration-parity fingerprints, isolated sustained-load evidence, privacy-minimized evidence, and certificate/ACME/DNS-01 foundations.

The Drive project specification contains exact historical candidate SHAs and workflow states from this period. Those values are source-era provenance only; accepted repository history and current `main` state control present implementation claims.

## 2026-09-01 — Accepted repository governance baseline

PR #4, **Add required Gateway repository governance records**, merged exact head `65f07f492a48789f7fee87e973ffb03d88720ab6` as `24afa12796daa64d81d6776b0c36a6eb50d13598`.

That tranche established the original root documentation baseline, explicit AGPL-3.0 licensing material, repository-governance validation, and the dedicated Repository Governance workflow without integrating the separate executable Development stack.

Caddy remained production-authoritative.

## 2026-09-24 — Feature/changelog governance migration

PR #12, **Migrate Gateway feature and changelog governance to Git-native records**, merged as `a5dae8e47372ad1efd13e34f2b85f380a6ad61e5`.

It established:
- `IMPLEMENTED-FEATURES.md`;
- `PLANNED-FEATURES.md`;
- `CHANGELOGS.md`;
- retirement of root `FEATURE-ROADMAP.md`; and
- repository-local feature/change authority instead of a synchronized Drive-roadmap model.

The migrated legacy Drive feature roadmap was removed only after accepted-main verification.

## 2026-09-24 — Native Gateway source integration

PR #9, **Stabilize Gateway for staged Caddy replacement**, merged exact candidate head `fdf501a6d80fea8f9b758ca80682b8c601ce8e10` as `0e0172d4b7766b6e497e9182546277ff7ab537a7`.

Exact-head gates recorded on the PR included Repository Governance, Platform Contract, Gateway Native Foundation, Isolated Runtime Acceptance, Isolated Sustained Load, and Vulnerability Reachability.

The integrated source established the Development runtime/control-plane foundation, routing/backend selection, failover, streaming/upgraded-connection handling, trusted-proxy/forwarding-identity controls, recovery/rollback, migration/parity evidence, Infrastructure Status/publication preflight, ACME/DNS-01 foundations, account-key controls, and operator CLI foundations.

The merge did not authorize production cutover, target-VPS mutation, listener transfer, Caddy retirement, production credentials, Release Candidate, or Stable status.

## 2026-09-24 — Post-integration repository reconciliation

PR #13, **Reconcile Gateway repository records after Development source integration**, merged as current migration baseline `da5dc01ba8bcee6236b2fa7da587022ed6c967d8`.

It reconciled README, feature records, specifications, notes, and changelog language from candidate-state wording to accepted-main Development source while retaining Caddy production authority.

## Current operational boundary

Current accepted source is substantial but production replacement remains blocked by target-environment evidence.

Open obligations include:
- sanitized read-only Caddy/VPS preflight on `goreecloud-vps-01`;
- reviewed migration-source manifest;
- route/listener/backend/TLS/certificate/Docker-network parity;
- non-conflicting alternate-port rehearsal;
- target WebSocket/streaming and applicable HTTP/2/gRPC behavior;
- production-representative latency/error-rate/load/backpressure evidence;
- protected production ACME/DNS credentials and live issuance/renewal acceptance;
- target backup/restore/recovery/rollback;
- accepted runtime integration of all nine Integral Platform Systems;
- listener-ownership governance;
- explicit production-cutover authorization.

Caddy remains authoritative for public TCP 80/443 publication until those gates pass.

## Repository protection gap

As of the migration baseline, GitHub reports `main` unprotected and no active repository rulesets. GitHub issue #14 tracks branch-protection/required-check remediation.

The connected GitHub application does not expose branch-protection/ruleset mutation, so this project record must not claim that protection is enforced.

## 2026-09-25 — Project specifications/project record migration candidate

This migration:
- creates root `PROJECT-SPECIFICATIONS.md`;
- creates root `PROJECT-RECORD.md`;
- consolidates former root `SPECIFICATIONS.md` into the mandatory canonical specification filename;
- reconciles the complete active Drive **Project Specification — Gateway.docx** with current accepted repository state;
- separates normative requirements from exact-revision historical evidence;
- updates README repository-document authority;
- updates repository-governance validation to require the two canonical project files and reject the retired competing `SPECIFICATIONS.md`; and
- retires root `SPECIFICATIONS.md` on the migration branch only after incorporation.

**Drive source:** Project Specification — Gateway.docx  
**Drive file ID:** `1zn5LS-Ce8RvPxxmUrEwhNUVK_FfrXGou`  
**Drive deletion status:** **Blocked.** The source must remain until this migration is accepted, exact default-branch readback succeeds, applicable review/check gates pass, and no reconciliation discrepancy remains.

The archived Drive source **Project Specification — Gateway** (file ID `1fItkmDwzeJOtGa7_KWx66BULzzzPE6ErZymLmcCBp2k`) remains migration/history input and must not override the active source or current repository state.

## Ongoing maintenance

Update this record for significant architecture decisions, repository changes, production migration/cutover, listener ownership, certificate-authority changes, incidents, recovery events, licensing changes, major platform integrations, lifecycle promotions, Caddy retirement, or project retirement.

Routine implementation chronology belongs in `CHANGELOGS.md`; feature-state inventory belongs in `IMPLEMENTED-FEATURES.md` and `PLANNED-FEATURES.md`.
