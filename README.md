# Deterministic Timeline Runtime

DTR is the reusable infrastructure extracted from the tested BTZ S10 implementation. It provides canonical deterministic encodings, checkpoint seals, a bounded atomic coordinator, resumable-kernel interfaces, source fencing models, publication-v6 construction and verification, retained-publication chaining, anti-rollback sequencing and adaptive playout buffering.

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

The JavaScript package exposes explicit subpaths such as `@dtr/timeline-runtime/client/verification`, `@dtr/timeline-runtime/runtime/coordinator` and `@dtr/timeline-runtime/observation/publication`. The Rust crates share this repository revision and are consumed through exact Git revisions once an authorized remote exists.

See [architecture and ownership](docs/ARCHITECTURE.md) and [extraction provenance](EXTRACTION.json).

No package is published by this repository. A consumer must pin an immutable Git revision for the Rust crates and use a reviewed `npm pack` artifact for the JavaScript client until an authorized distribution remote exists.
