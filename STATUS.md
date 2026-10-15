# Current status — S14 shared changes, local and unpublished

DTR remains generic and independent of BTZ. The S11 implementation pin `71e59e93cf49a3656689679b538b4c3f138787f8` remains the published dependency consumed by BTZ until the user publishes and the consumer pins are deliberately updated.

Two narrow local API changes are implemented:

- `5e2af85`: `IngestOrdered { start, end, inputs, anchor }`, with JavaScript `ingestOrdered`. Shares validation with dense admission, preserves original sparse positions and atomically commits progress/inputs. Existing canonical encodings, dense behavior and Life remain unchanged.
- `7df2a45`: `certificateVerifier` / `liveClient` take explicit network/deployment configuration. Mainnet uses the SDK root and rejects root overrides. Local compatibility wrappers share the same verifier/transport. Existing freshness, canister, delegation, artifact, predecessor and rollback checks remain.

Initial API verification at `7df2a459b37b04fc142d1f615a6da82dcc9c16f2` passed 190 JavaScript tests, 31 Rust tests (including Life), formatting and Clippy. Those historical logs remain `.work/s14/dtr-b-js.log`, `.work/s14/dtr-a-rust.log` and `.work/s14/dtr-clippy.log`.

A follow-up sparse-admission regression normalizes supported numeric/string positions before persistence. Without normalization, sealing then restoring an accepted numeric position failed with reservation divergence. The regression now requires identical images and public outputs for BigInt, number and decimal-string positions. Its standalone logs are `.work/s14/normalization/js.log` and `rust.log`; all 191 JavaScript and 31 Rust tests pass. No third shared API was added.

The final inspected package is `@dtr/timeline-runtime@0.12.0`, at `.work/s14/final/dtr-timeline-runtime-0.12.0.tgz`, SHA-256 `3e04294abee75b7b8a42d72000fb09068ce8700567729af98b9f7aa53470cdcb`. It includes the normalization correction. BTZ must test this exact artifact and Rust sources through explicit temporary overrides. The earlier `b9c1a060…` package remains historical development evidence. No permanent sibling dependency or Git URL rewrite is installed.

No remote Git action, package publication, mainnet deployment or new CI run occurred. The next boundary is user publication of `checkpoint/s14-sparse-input-mainnet-client`, followed by BTZ's actual immutable pin/package/lock update and consumer/application verification. Do not claim remote-pinned validation before that step.
