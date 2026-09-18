# RFC 8555 DNS-01 Renewal Issuer

## Status

Development certificate-automation candidate only. This source does not authorize live production issuance, certificate publication, listener transfer, or Caddy retirement.

## Architecture

GoreeCloud Gateway now composes four bounded layers for certificate renewal:

1. `RenewalRequest` proves that a known certificate profile is renewal-eligible.
2. `ACMERenewalIssuer` performs an RFC 8555 order flow for the exact requested DNS names.
3. `DNS01Provider` presents and removes only ACME DNS-01 challenge records. Porkbun is the first implementation.
4. `IssueValidateAndStageRenewal` independently validates returned certificate/key material and stages it without authorizing production cutover.

The RFC 8555 protocol implementation uses only `golang.org/x/crypto/acme` behind Gateway-owned orchestration. Gateway does not use `autocert`, because account lifecycle, challenge policy, cleanup, key handling, staging, rollback, and production authority must remain explicit GoreeCloud-controlled decisions.

## Fail-closed behavior

The issuer:

- requires an already registered, valid ACME account;
- does not automatically register accounts or accept certificate-authority terms of service;
- accepts only an absolute HTTPS ACME directory URL;
- refuses HTTP redirects in the ACME HTTP client;
- requests orders only for the exact normalized DNS names in `RenewalRequest`;
- rejects unexpected order identifiers and authorization identities;
- accepts only DNS-01 for pending authorizations in this implementation;
- derives DNS-01 values from the ACME account key through the protocol library;
- waits for the exact TXT value to become observable before challenge acceptance;
- removes each exact challenge record after authorization;
- treats challenge-cleanup failure as an issuance blocker and will not finalize the order after such a failure;
- attempts bounded cleanup even if the caller cancels the primary operation;
- generates a fresh ECDSA P-256 certificate key for finalization;
- emits PKCS#8 private-key material only to the existing validation/staging boundary;
- never places ACME account keys, certificate private keys, DNS provider credentials, or challenge values in ordinary evidence structures; and
- rejects pre-finalized orders because Gateway cannot prove ownership of the corresponding certificate private key.

## Account-state boundary

ACME account registration, terms-of-service review/acceptance, account-key generation, protected account-key persistence, rollover, recovery, and revocation remain separate work. The renewal issuer intentionally fails if its supplied account key is not already registered and valid.

No ACME account key is committed to this repository.

## DNS propagation boundary

The default propagation waiter uses the configured/system Go DNS resolver with bounded polling. Target-VPS acceptance must determine the approved resolver strategy and prove that the same public DNS state observed by the certificate authority becomes visible reliably without exposing challenge values in logs.

## Dependency provenance

The Development candidate pins `golang.org/x/crypto v0.57.0` and imports only `golang.org/x/crypto/acme`. Provenance and the upstream BSD-3-Clause license are retained under `third_party/`.

Gateway now declares Go 1.27.1 for this candidate. The earlier Go 1.24 line was removed from the stabilization branch because it is outside the current supported Go release window. Current vulnerability review remains mandatory before Stable qualification.

## Remaining production gates

Before Gateway can assume Caddy's certificate-management role, the exact candidate still requires:

- approved ACME account creation and protected persistence/recovery;
- explicit terms-of-service review and acceptance handling;
- live Porkbun DNS-01 rehearsal using scoped runtime-only credentials;
- authoritative/public DNS propagation acceptance on `goreecloud-vps-01`;
- real CA staging issuance and renewal for representative GoreeCloud names, including wildcard behavior where required;
- rate-limit, retry, cancellation, stale-challenge, partial-failure, and provider-outage acceptance;
- certificate-key and ACME-account-key backup/recovery policy;
- exact certificate inventory/parity comparison with Caddy;
- renewal scheduling and failure alerting;
- target-environment Privacy Shield, Wardveil Security, Everkeep, Policy, Observability, and Manager evidence; and
- explicit production migration authorization.

Until those gates pass, Caddy remains production-authoritative.
