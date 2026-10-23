# One authenticated epoch checkpoint

The trusted host calls Rust `Coordinator::prepare_transition(identity, output,
metadata_hash)` / JS `prepareTransition(identity, output, metadataHash)`, reviews
or persists the returned `Epoch`, then proposes/applies `Action::Transition` /
`{kind:'transition',epoch,state_hex,event_hex,score_hex}`. There is no untrusted
remote state-replacement API. Application-specific placement, schema validation,
source cutover evidence and authorization belong to the consumer.

A checkpoint requires a committed predecessor seal, no stage or reservation,
no pending input and identical admitted/retired/head source positions. It changes
neither logical time nor source cursor/anchor. Source identity is unchanged; at
least one rules/configuration/schema identity changes. Inputs admitted after the
checkpoint use the new identity. Pending commands must be drained by the host
beforehand, never reinterpreted by this operation.

## Wire commitments

Epoch v1 is canonical typed JSON with exactly these fields:

- `version:1`, `previous_publication_hex` (canonical, non-render v6 catalog,
  maximum 16 KiB), `new_identity` (all four existing identity hashes).
- `segment_id` (previous ordinal + 1), `logical_boundary`, `source_cursor`
  (existing uint64 typed integers), `source_anchor`.
- `state_hash`, `event_hash`, `score_hash`, `metadata_hash` (32-byte hex).
- `transition_hash`: SHA-256 of ASCII `DTREPOCH1` followed by canonical encoding
  of all preceding fields, excluding `transition_hash` itself.

The embedded catalog binds the previous publication, manifest, state and complete
identity. The checkpoint head uses the transition hash as its manifest hash and
has no simulation seal. It consumes a publication ordinal, but zero logical time.
The application supplies the new output bytes; all three hashes are checked.

The resulting coordinator record is v6, journal v3, publication v7. Publication
v7 adds exactly one `epoch` field to v6. Subsequent simulation seals use
`DTRSEAL2`: the existing 308-byte seal layout with the domain changed from
`DTRSEAL1` and the 32-byte transition hash appended. Every new seal binds the same
epoch proof, including after predecessor retention eviction. `DTRMANI1` is
unchanged. The first new seal chains directly to the checkpoint hash and state.

Legacy records remain v5/journal v2, publications remain v6, and seals remain
`DTRSEAL1` with no optional field serialized. Historical v5 publication adapters
cannot encode an epoch. Existing historical bytes are not upgraded in place.

## Atomicity and verification

Proposals are immutable and revision-fenced. The consumer must persist the whole
replacement atomically, as with Seal/Step/Publish. A pre-root failure retains the
old epoch; a post-root lost acknowledgement restores the new epoch. Repeating the
identical transition and output is a no-op, even after further segments. A
conflicting request fails. Restore checks both the current epoch and its embedded
predecessor manifest commitment. Kernel validation remains application-owned.

A certified-data root covers the complete publication v7. Client verification
checks the epoch commitment, old v6 manifest, new identity and seal binding before
issuing a verified ticket. Retained predecessor verification crosses the exact
embedded old publication, then resumes consecutive seals. A client behind the
cutover uses explicit snapshot resync; its identity, time, source and ordinal
anti-rollback floor must fit the authenticated predecessor boundary. A v7 session
cannot roll back to v6 or silently replace the epoch. Fresh startup authenticates
the current epoch proof even when old artifacts have been evicted. Artifact
retention remains bounded and does not become an archival availability promise.

This version deliberately supports **one v6 → v7 crossing per history**, not
recursive epochs, registries, scripts or governance. A second crossing is rejected.
The 16 KiB predecessor limit bounds certification and restore work; a host whose
catalog exceeds that limit must report incompatibility rather than discard fields.
No topology, payments, economics or canister logic is included in DTR.

## Evidence

`tests/fixtures/epoch-v1.json` is the shared Rust/JS public-byte vector. Both
implementations check the exact predecessor, epoch, checkpoint, successor seal and
successor publication bytes. Rust and JS toy-kernel tests cover drained boundaries,
corruption, source mismatch, atomic retry/recovery and post-transition seals.
Independent competitive-Life tests exercise the same operation. Client tests cover
retained predecessors, eviction, fresh startup, explicit resync and rollback.
Existing v6-only and historical encoding tests remain enabled.
