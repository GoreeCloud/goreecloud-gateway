# Porkbun DNS-01 Provider

## Status

Development certificate-automation foundation only. This adapter does not authorize production certificate issuance, live certificate publication, listener ownership, or Caddy retirement.

## Governing deployment context

The current GoreeCloud domain architecture uses Porkbun-controlled DNS and ACME DNS-01 for Caddy certificate validation. GoreeCloud Gateway therefore needs an equivalent first-party challenge path before it can prove certificate-management parity.

The provider in `internal/tlsconfig/porkbun_dns01.go` is deliberately narrower than a general DNS client.

## Security boundary

The provider:

- is fixed to Porkbun's official HTTPS API endpoint in production construction;
- accepts one explicitly configured DNS zone;
- creates only `TXT` records below the `_acme-challenge` namespace;
- rejects requested names outside that configured zone before making a network call;
- returns only the exact created record ID and challenge record name required for cleanup;
- deletes only that exact record ID;
- never exposes a broad delete-by-name/type operation;
- sends API credentials in request headers rather than serializing them into Gateway configuration or evidence;
- refuses HTTP redirects so credentials cannot be forwarded to a different endpoint;
- supplies idempotency keys for write operations;
- caps API response bodies;
- does not include provider response bodies, challenge values, or credentials in returned errors; and
- remains context-cancellable.

Porkbun API keys used by a future target runtime should be separately scoped to the required domain and, where practical, to the Gateway host/source network. The reusable secret key must remain outside Git and outside ordinary task/evidence records.

## API behavior

The adapter uses Porkbun API v3 DNS record creation and exact-ID deletion:

- `POST /dns/create/{domain}`
- `POST /dns/delete/{domain}/{id}`

Challenge record creation uses a 600-second TTL and records the record ID returned by Porkbun for exact cleanup.

## Remaining ACME work

This adapter does **not** yet implement the ACME order lifecycle. A later provider-neutral ACME issuer must still:

1. create or load protected ACME account state;
2. initiate an RFC 8555 order for the exact requested DNS names;
3. choose DNS-01 challenges only under the approved policy;
4. derive challenge TXT values using the ACME account key;
5. call this bounded Porkbun provider to present each challenge;
6. verify DNS propagation through an approved resolver strategy;
7. accept/poll the ACME challenges and order;
8. generate the certificate private key and CSR in protected runtime memory/storage;
9. validate returned certificate identity before staging;
10. remove exact challenge records even when issuance fails; and
11. retain privacy-safe evidence without storing API credentials, challenge values, account private keys, or certificate private keys in ordinary logs/evidence.

Production use additionally requires Porkbun sandbox/live-domain rehearsal, target-VPS secret handling, renewal failure/retry acceptance, rate-limit handling, backup/recovery of required account state, and Caddy parity evidence.
