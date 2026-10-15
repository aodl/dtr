# Current status — S14 shared changes, local and unpublished

DTR remains generic and independent of BTZ. The S11 implementation pin `71e59e93cf49a3656689679b538b4c3f138787f8` remains the published dependency consumed by BTZ until the user publishes and the consumer pins are deliberately updated.

Two narrow local API changes are implemented:

- `5e2af85`: `IngestOrdered { start, end, inputs, anchor }`, with JavaScript `ingestOrdered`. Shares validation with dense admission, preserves original sparse positions and atomically commits progress/inputs. Existing canonical encodings, dense behavior and Life remain unchanged.
- `7df2a45`: `certificateVerifier` / `liveClient` take explicit network/deployment configuration. Mainnet uses the SDK root and rejects root overrides. Local compatibility wrappers share the same verifier/transport. Existing freshness, canister, delegation, artifact, predecessor and rollback checks remain.

Executed locally: 190 JavaScript tests, 31 Rust tests (including Life), Rust formatting and Clippy passed. Raw logs are `.work/s14/dtr-b-js.log`, `.work/s14/dtr-a-rust.log` and `.work/s14/dtr-clippy.log`. These tests bind the substantive API implementation revision `7df2a459b37b04fc142d1f615a6da82dcc9c16f2`; this later status-only commit does not add another runtime change.

The actual inspected package is `@dtr/timeline-runtime@0.12.0`, built from `7df2a45`, at `.work/s14/dtr-timeline-runtime-0.12.0.tgz`, SHA-256 `b9c1a060a2c51a1270f7b08274759ebeac7c1e8c79f974a81ad2dad274c3f03b`. BTZ tests this exact local package and Rust sources through explicit temporary overrides. No permanent sibling dependency or Git URL rewrite is installed.

No remote Git action, package publication, mainnet deployment or new CI run occurred. The next boundary is user publication of `checkpoint/s14-sparse-input-mainnet-client`, followed by BTZ's actual immutable pin/package/lock update and consumer/application verification. Do not claim remote-pinned validation before that step.
