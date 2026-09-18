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

The Go vulnerability database currently associates `GO-2026-5932` with the `golang.org/x/crypto` module because its unmaintained `openpgp` subpackages are unsafe by design. Gateway does not import those packages; it imports only `golang.org/x/crypto/acme`. The exact-head vulnerability workflow must continue to prove zero imported-package and zero reachable findings. This is a scoped technical non-applicability determination for the current source graph, not a blanket waiver for future `x/crypto` usage.

## Remaining production gates

Before Gateway can assume Caddy's certificate-management role, the exact candidate still requires:

- approved operator execution of the wired ACME account registration flow after human TOS review, plus protected wrapping-key provisioning/escrow and target-environment recovery rehearsal;
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


## Account-key rollover preparation

The Development source now includes a non-network preparation boundary for future RFC 8555 account-key rollover.

Before any CA-side key-change operation can be implemented, Gateway can:

- load and authenticate the currently active encrypted account-key envelope;
- generate a fresh replacement account key;
- encrypt the replacement key under the same externally supplied 256-bit wrapping key;
- bind the immutable rollover bundle to the exact ACME directory, current account public-key SHA-256 fingerprint, replacement-key type, and replacement public-key SHA-256 fingerprint;
- write the bundle as an owner-only direct child of the protected account-state root;
- reject symlink paths, broad permissions, malformed metadata, wrong wrapping keys, and bundles copied outside the state root; and
- fail closed if the active account-key fingerprint changes after preparation.

This means a future CA key-change transaction can require recoverable replacement-key state to exist before it sends the RFC 8555 rollover request. The current slice does **not** send a key-change request, activate the replacement envelope, remove the old envelope, or claim rollback has been tested. Those steps remain blocked until a transaction model proves that a CA-success/local-persistence failure cannot strand the account.


## Transactional account-key rollover execution

The Development source now includes the CA-side execution boundary, but no live CA rollover has been performed in this workflow.

For a prepared rollover bundle, Gateway now:

1. revalidates the active account identity and decrypts the prepared replacement key;
2. writes an immutable encrypted retired copy of the current active envelope;
3. builds and durably stages a complete replacement active envelope in the same protected state directory;
4. refuses to call the CA if unresolved pending activation state already exists;
5. sends the RFC 8555 account-key rollover only after both recovery artifacts exist;
6. removes the staged replacement and leaves the old active envelope unchanged when the CA rejects the rollover; and
7. after CA success, atomically renames the staged replacement over the active envelope and synchronizes the state directory.

The prepared rollover bundle and retired encrypted envelope are intentionally retained after success. The returned receipt contains fingerprints and basenames only and cannot authorize production cutover.

A returned ACME error and a remote-success/local-activation failure are both treated as distributed-transaction uncertainty cases. The replacement private key remains recoverable from the prepared bundle and the fully formed pending active envelope remains on disk if the final rename fails, but an approved operator recovery/probing workflow is still required before live use so Gateway can distinguish CA-success from CA-failure after process loss without blindly replaying the key-change request.


## Read-only rollover authority probe

The Development source now includes the non-mutating recovery probe required by uncertain account-key rollover outcomes.

The probe refuses to run unless the active account envelope, prepared rollover bundle, and pending replacement envelope form one consistent state: the active fingerprint must match the bundle's old-account fingerprint, and the pending envelope's key type/fingerprint must match the prepared replacement identity.

It then creates independent ACME clients for the old and replacement keys and performs RFC 8555 existing-account lookup with each key. It never calls the key-change endpoint.

The privacy-safe report contains only the CA directory, probe time, old/new public-key fingerprints, optional ACME account status strings, state-file basenames, and one of these classifications:

- `old-authoritative`: old key is recognized; replacement key is not;
- `new-authoritative`: replacement key is recognized; old key is not;
- `both-recognized`: both keys are recognized and operator review remains required;
- `neither-recognized`: neither key is recognized and operator review remains required; or
- `inconclusive`: a transport/protocol/response failure prevents a trustworthy classification.

Transport or protocol failures are never converted into an authority guess. The probe does not activate a pending envelope, remove a retired envelope, delete a prepared bundle, retry rollover, or authorize production cutover. Recovery activation policy and operator wiring remain separate gates.


## Local rollover recovery execution

The Development source now includes a local recovery executor built on the read-only authority probe.

Recovery always performs a fresh old/new-key probe immediately before local state mutation and requires an explicit expected outcome. Only these two outcomes are actionable:

- `old-authoritative`: Gateway verifies the old active envelope still matches the prepared bundle, preserves an encrypted retired snapshot, removes the non-authoritative pending replacement, synchronizes the state directory, and verifies the old account envelope remains loadable.
- `new-authoritative`: Gateway verifies the same state invariants, preserves the encrypted retired old envelope, atomically renames the pending replacement over the active envelope, synchronizes the state directory, and verifies the replacement envelope decrypts to the expected new fingerprint.

`both-recognized`, `neither-recognized`, and `inconclusive` are hard stops and never mutate local state. A mismatch between the fresh probe result and the operator's explicit expected outcome is also a hard stop.

Recovery receipts contain only directory/fingerprint/action/basename evidence and cannot authorize production cutover. Operator CLI wiring, live CA rehearsal, target secret provisioning, and target recovery rehearsal remain required before this path can be accepted for production use.
