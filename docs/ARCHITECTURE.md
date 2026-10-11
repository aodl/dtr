# Architecture and ownership

DTR owns deterministic logical-time and seal primitives, canonical wire encoding, the generic coordinator, resumable-kernel boundaries, generic source fencing models, bounded publication construction, publication/certificate verification, retained-chain validation, anti-rollback sequencing, playout buffering and competitive-Life conformance.

A consuming game owns state rules, command interpretation, payments, scoring, projections, rendering, canister assembly and deployment configuration. The dependency direction is always game → DTR. DTR contains no BTZ import or BTZ-specific envelope.

The Rust `Kernel`/`ResumableKernel` interfaces accept canonical state, inputs and a sealed logical interval. A game supplies deterministic begin/restore/step/result behavior. Work partitions and interruptions may change private cursors but must not change committed state, events, scores or manifests.

The JavaScript client verifies directly authenticated publication roots and artifacts. Retained predecessor chaining is limited to null-render catalogs because optional render bytes are not part of the authoritative manifest. A rendered catalog requires its own directly authenticated root.
