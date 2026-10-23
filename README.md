# Deterministic Timeline Runtime

DTR is the reusable infrastructure extracted from the tested BTZ S10 implementation. It provides canonical deterministic encodings, checkpoint seals, a bounded atomic coordinator, resumable-kernel interfaces, source fencing models, publication-v6/v7 construction and verification, retained-publication chaining, anti-rollback sequencing and adaptive playout buffering.

DTR deliberately does not contain BTZ mechanics, payments, pricing, animation projection, rendering, ledger classification or a concrete canister application. `examples/competitive-life` is the small second-kernel boundary test.

## Verify

```sh
npm ci
npm test
cargo +1.94.1 test --workspace --locked
cargo +1.94.1 fmt --all -- --check
cargo +1.94.1 clippy --workspace --all-targets --locked -- -D warnings
npm pack --dry-run --json
```

The JavaScript package exposes explicit subpaths such as `@dtr/timeline-runtime/client/verification`, `@dtr/timeline-runtime/runtime/coordinator` and `@dtr/timeline-runtime/observation/publication`. The Rust crates share this repository revision and are consumed through exact revisions from the public `https://github.com/aodl/dtr.git` remote.

See [architecture and ownership](docs/ARCHITECTURE.md) and [extraction provenance](EXTRACTION.json).

No registry package is published by this repository. A consumer must pin an immutable Git revision for the Rust crates and use a reviewed `npm pack` artifact for the JavaScript client.

## S14 shared additions (published at 1f47c1a)

`IngestOrdered { start, end, inputs, anchor }` / JavaScript `ingestOrdered`
admits at most 256 strictly ordered explicit positions in `[start,end)`.
Admission is atomic with source progress; gaps describe the adapter's stream,
not independently inspected global records. A zero-width range must retain its
anchor; an advancing empty range may replace it. Existing dense admission and
canonical public formats are unchanged.

`certificateVerifier({network,rootKey})` and `liveClient({network,rootKey,
canister_id,host})` share the existing certificate/observation implementation.
`network: 'ic'` uses the SDK mainnet root and rejects `rootKey` overrides.
`network: 'pocketic-local'` requires an explicit pinned root. Configuration is
trusted deployment input, never query-string or server-selected policy.
Compatibility local wrappers remain. Neither path fetches a root key.

## Authenticated epoch checkpoint (0.13.0 candidate)

See [the epoch wire and host contract](docs/EPOCH_TRANSITION.md). One explicit, drained v6 → v7 boundary can change application identity and state without rewriting historical seals or publications. This candidate requires consumer and installed-IC verification before deployment.
