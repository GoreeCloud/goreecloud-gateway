# Gateway Migration-Source Manifest

GoreeCloud Gateway uses `goreecloud-gateway-migration-source-manifest/v1` to bind configuration-parity evaluation to a retained, independently reviewed identity for the migration source.

For the current migration, `source_system` is fixed to `caddy`. A different source requires a separately reviewed contract rather than silently reusing this one.

The manifest contains only:

- recording time;
- migration-source system and environment labels;
- exact reviewed configuration SHA-256;
- aggregate service, route, backend, and certificate-profile counts;
- SHA-256 identity of the independent review evidence; and
- `production_cutover_authorized=false`.

It deliberately excludes hostnames, backend URLs, certificate paths, credentials, request data, route contents, certificate material, and private runtime diagnostics.

Gateway strictly decodes the manifest, rejects unknown or trailing JSON, requires valid immutable identities, verifies the aggregate counts against the candidate Gateway configuration, and then evaluates the candidate configuration fingerprint against the reviewed migration-source fingerprint.

## Local parity verifier

`cmd/gateway-migration-verify` provides a fail-closed local verification path for a candidate Gateway configuration and an independently reviewed migration-source manifest. It requires all three inputs explicitly:

```sh
go run ./cmd/gateway-migration-verify \
  -config /path/to/gateway-candidate.json \
  -manifest /path/to/reviewed-caddy-source.json \
  -source-revision 0123456789abcdef0123456789abcdef01234567
```

The command:

1. validates the candidate Gateway configuration;
2. strictly loads and validates the reviewed Caddy migration-source manifest;
3. verifies aggregate counts and the deterministic configuration fingerprint;
4. validates the resulting parity evidence; and
5. emits only the minimized `goreecloud-gateway-config-parity-evidence/v1` JSON on success.

A mismatch, malformed input, invalid source revision, or cutover-authorizing source manifest exits nonzero and emits no acceptance evidence. The verifier does not discover, connect to, read, reload, or mutate Caddy. It operates only on the explicit reviewed files supplied to it and cannot authorize production cutover.

A valid manifest does not prove that it was correctly derived from live Caddy state. The target-environment migration-preparation process must independently produce, review, retain, and govern the source configuration identity and its review evidence. Only then can the resulting parity evidence support a migration gate.

This contract cannot authorize production cutover. Caddy remains production-authoritative until all remaining migration gates and explicit production approval pass.
