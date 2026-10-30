# Authenticated epoch checkpoints

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

Epoch v2 is used only after an existing v1 or v2 epoch. Its publication v8 proof
keeps the same boundary, output and metadata commitments but replaces the embedded
catalog with:

- the SHA-256 and bounded head/identity summary of the exact predecessor
  publication;
- the predecessor epoch hash and monotonically increasing transition index; and
- a constant-size chain hash derived from all preceding transition hashes.

The v2 transition commitment uses the `DTREPOCH2` domain. The chain accumulator
uses `DTREPOCHCHAIN1`. A v2 object keeps `previous_publication_hex` as the empty
string and cannot recursively embed another catalog. Its size therefore remains
bounded as transition count grows. Publication v8 carries epoch v2; its ordinary
successor seals remain DTRSEAL2 and bind the current transition hash.

## Atomicity and verification

Proposals are immutable and revision-fenced. The consumer must persist the whole
replacement atomically, as with Seal/Step/Publish. A pre-root failure retains the
old epoch; a post-root lost acknowledgement restores the new epoch. Repeating the
identical transition and output is a no-op, even after further segments. A
conflicting request fails. Restore checks both the current epoch and its embedded
predecessor manifest commitment. Kernel validation remains application-owned.

A certified-data root covers the complete current publication. Client verification
checks the epoch commitment, predecessor summary, new identity and seal binding
before issuing a verified ticket. Retained predecessor verification crosses the
exact embedded v6 publication or exact v8 predecessor hash, then resumes
consecutive seals. A client behind the cutover uses explicit snapshot resync; its
identity, time, source and ordinal anti-rollback floor must fit the authenticated
predecessor boundary. A session cannot roll back across v6/v7/v8 or silently
replace an epoch. Fresh startup authenticates
the current epoch proof even when old artifacts have been evicted. Artifact
retention remains bounded and does not become an archival availability promise.

The 16 KiB predecessor limit still bounds the original v1 crossing. Later
crossings use the fixed summary and exact publication hash; when predecessor
bytes are retained, clients verify that direct link before continuing. No
recursive registry, migration script, topology, payments, economics or canister
logic is included in DTR.

## Evidence

`tests/fixtures/epoch-v1.json` is the shared Rust/JS public-byte vector. Both
implementations check the exact predecessor, epoch, checkpoint, successor seal and
successor publication bytes. Rust and JS toy-kernel tests cover drained boundaries,
corruption, source mismatch, atomic retry/recovery and post-transition seals.
Independent competitive-Life tests exercise first and later transitions. Client
tests cover v7/v8 retained predecessors, eviction, fresh startup, explicit resync
and rollback.
Existing v6-only and historical encoding tests remain enabled.

## Explicit application context checkpoints (epoch v3 / publication v9)

`prepare_checkpoint(output, metadata_hash)` / `prepareCheckpoint(output,
metadataHash)` commits an application-supplied context operation under the exact
existing source/rules/configuration/schema identity. This explicit operation
requires an authenticated epoch, with no pending input, reservation or unfinished
kernel stage. It advances the publication/transition index while preserving
logical time. It may also retire an already verified empty source prefix: the
source cursor and anchor come from the verified inbox, never from a supplied
position or hint. The v3 predecessor summary includes the old source anchor.
Without source advancement the anchor must remain unchanged; an empty advancing
prefix is acknowledged atomically with the checkpoint. Queued input can never
be discarded this way. Rules transitions retain their fully drained boundary. Consecutive checkpoints need no intervening simulation step.

The caller validates the application transformation and supplies the canonical
metadata preimage to its independent replay. DTR authenticates the state, event,
score and metadata hashes; it does not interpret clocks, lifecycle rules or any
application semantics. Context is not a source-stream record and never fabricates
source positions. No scheduler or time source is added to DTR.

Epoch v3 uses the `DTREPOCH3` commitment domain and a bounded predecessor summary.
It must preserve all identity fields. Existing v1/v2 rules transitions retain
their identity-change requirement and their published bytes. Publication v9 marks
an active context-checkpoint epoch. Normal successor seals retain `DTRSEAL2` and
bind its checkpoint hash. A later explicit rules transition uses the existing
rules-transition proof with a verified v9 predecessor; wire envelope numbers do
not replace the monotonic publication index or application rules identity.

Clients must support this proof before an application activates the capability.
Certificate verification, deployment binding, source boundaries, same-height
conflict detection and monotonic head protection remain mandatory. An older
client fails closed on the new envelope; there is no trust fallback. Content-pin
unit vectors demonstrate shared bytes, not IC certificate authenticity.
