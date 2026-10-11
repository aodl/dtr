# S11 standalone DTR extraction

On 11 October 2026, the reusable deterministic timeline implementation was imported from `aodl/placeholder` source revision `7ff33b8573e7191deb6a3b23f748bb988ccc280f` into local DTR commit `71e59e93cf49a3656689679b538b4c3f138787f8`.

The repository owns the portable seal/core and source-fencing crates, the native wire/coordinator crates, publication and certificate-verification clients, bounded source/storage models, playout sequencing, and the competitive-Life conformance example. It contains no BTZ physics, command/payment classification, scoring, projection, renderer, canister entry point or deployment configuration.

The optional-render predecessor issue was reproduced before extraction and corrected by rejecting retained-chain authentication whenever either catalog has a render artifact. Rendered catalogs remain supported only through a directly authenticated certificate or pinned-root path. This is the only intentional validation tightening; canonical game formats and publication v6 are unchanged.

Local evidence passed 186 JavaScript tests and 29 Rust tests, format, Clippy and package inventory. An actual `npm pack` artifact was installed in an isolated consumer, and a four-crate Rust consumer compiled from a bare repository reconstructed from a Git bundle without either source checkout. The BTZ repository separately passed its source/native/Wasm, S10-baseline upgrade, PocketIC ledger/archive, live certificate and sandboxed-browser matrix against these artifacts.

The repository has no remote. Consequently remote clean-clone and fresh DTR CI are BLOCKED, not passed. The prepared workflow will run the standalone suite and retain its logs once an authorized remote is created and pushed. No package or release was published.
