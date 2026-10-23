# Authenticated epoch candidate — local, not published

Branch `checkpoint/authenticated-epoch-transition` descends from local master
`1649788` and published S14 `1f47c1a`. It implements the single generic v6→v7
checkpoint described in [the wire contract](docs/EPOCH_TRANSITION.md), package
0.13.0. Historical S14 and prior release tags are unchanged. The branch-cleanup
inventory below is historical evidence from before this implementation.

Local gates: 199 JavaScript tests, 35 Rust tests (locked/offline), format and
Clippy with warnings denied. Shared Rust/JS byte fixture and independent Life
checks cover the new boundary. Raw results: `.work/epoch/`. B2Z installed-IC
consumer/transition verification is a separate required gate. No consumer may
claim this candidate as a published immutable remote pin before user publication.

User publication: push this feature branch without force; after CI and consumer
review, fast-forward supported master and retain a release tag. No remote Git
operation, package publication or mainnet action was performed for this candidate.

---

# Current status — local master prepared, 2026-10-22

Local `master` is based directly on published S14 `1f47c1a0a104875bd13475d561b8d5aa10770d99`. The historical status below predates that publication. Current B2Z consumes this exact Rust revision and packaged client 0.12.0; its vendor artifact SHA-256 is `933f42b1187c45083c4f6c69e6851fe2c77e15e8fa8fd198e13187ad3ff13d8f`.

Audit: three local branches before cleanup, three matching local remote-tracking refs, one clean worktree, no transition implementation in reachable commits, uncommitted files or candidate paths. The only unreachable commit, `87d0b05bd162da200b27f45dacfed7639ecac844`, is the pre-amend S14 normalization correction; its code is identical to `1f47c1a` and only STATUS differs. No authenticated history/schema transition has been implemented or discovered. Current host Action remains Ingest/IngestOrdered/Seal/Step/Publish. Do not claim an unpublished transition pin.

Local validation at S14: 191 JS and 31 Rust tests PASS, formatting and Clippy PASS, locked/offline Cargo. Raw evidence: `.work/branch-cleanup/`. No DTR code, dependencies or public encodings change in this cleanup.

Immutable local annotated tags `dtr-s14-0.12.0` and `dtr-s11-extraction` retain the published milestones. Existing branches are not deleted, rewritten or force-updated. Remote state is the user-verified inventory plus matching cached tracking refs; no fetch/ls-remote/push or GitHub setting change was performed.

User sequence: push `master` without force; push both milestone tags; change GitHub's default branch to `master`; verify S14 remains an ancestor and tags resolve correctly; only then optionally prune obsolete checkpoint/main branches through a separate user review. Keep `master` for supported releases, temporary feature branches while active, permanent tags for pinned milestones. Do not change consumer pins for branch spelling. The history/schema transition remains future separately scoped work.

---

# Current status — S14 shared changes, local and unpublished

DTR remains generic and independent of BTZ. The S11 implementation pin `71e59e93cf49a3656689679b538b4c3f138787f8` remains the published dependency consumed by BTZ until the user publishes and the consumer pins are deliberately updated.

Two narrow local API changes are implemented:

- `5e2af85`: `IngestOrdered { start, end, inputs, anchor }`, with JavaScript `ingestOrdered`. Shares validation with dense admission, preserves original sparse positions and atomically commits progress/inputs. Existing canonical encodings, dense behavior and Life remain unchanged.
- `7df2a45`: `certificateVerifier` / `liveClient` take explicit network/deployment configuration. Mainnet uses the SDK root and rejects root overrides. Local compatibility wrappers share the same verifier/transport. Existing freshness, canister, delegation, artifact, predecessor and rollback checks remain.

Initial API verification at `7df2a459b37b04fc142d1f615a6da82dcc9c16f2` passed 190 JavaScript tests, 31 Rust tests (including Life), formatting and Clippy. Those historical logs remain `.work/s14/dtr-b-js.log`, `.work/s14/dtr-a-rust.log` and `.work/s14/dtr-clippy.log`.

A follow-up sparse-admission regression normalizes supported numeric/string positions before persistence. Without normalization, sealing then restoring an accepted numeric position failed with reservation divergence. The regression now requires identical images and public outputs for BigInt, number and decimal-string positions. Its standalone logs are `.work/s14/normalization/js.log` and `rust.log`; all 191 JavaScript and 31 Rust tests pass. No third shared API was added.

The final inspected package is `@dtr/timeline-runtime@0.12.0`, at `.work/s14/final/dtr-timeline-runtime-0.12.0.tgz`, SHA-256 `3e04294abee75b7b8a42d72000fb09068ce8700567729af98b9f7aa53470cdcb`. It includes the normalization correction. BTZ must test this exact artifact and Rust sources through explicit temporary overrides. The earlier `b9c1a060…` package remains historical development evidence. No permanent sibling dependency or Git URL rewrite is installed.

No remote Git action, package publication, mainnet deployment or new CI run occurred. The next boundary is user publication of `checkpoint/s14-sparse-input-mainnet-client`, followed by BTZ's actual immutable pin/package/lock update and consumer/application verification. Do not claim remote-pinned validation before that step.
