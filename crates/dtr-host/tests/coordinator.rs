//! Pure host tests with a deliberately non-BTZ toy kernel. Native execution is still a gate.
use dtr_host::{Action, Coordinator, Identity, Input, Kernel, Output, Progress, Seal};
use dtr_wire::{decode, encode, hash, Int, Result};
use serde::{Deserialize, Serialize};
#[derive(Clone, Copy)]
struct Toy;
#[derive(Serialize, Deserialize)]
struct Cursor {
    done: usize,
}
impl Kernel for Toy {
    fn begin(&self, _: &[u8], _: &[Input], _: &Seal) -> Result<Vec<u8>> {
        encode(&Cursor { done: 0 })
    }
    fn validate_cursor(&self, b: &[u8], h: &str) -> Result<()> {
        if hash(b) != h {
            return Err("cursor integrity".into());
        }
        let c: Cursor = decode(b)?;
        if c.done > 3 {
            return Err("cursor bounds".into());
        }
        Ok(())
    }
    fn step(&self, b: &[u8], budget: usize) -> Result<(Vec<u8>, Progress)> {
        let mut c: Cursor = decode(b)?;
        let used = budget.min(3 - c.done);
        c.done += used;
        Ok((
            encode(&c)?,
            Progress {
                used,
                complete: c.done == 3,
            },
        ))
    }
    fn result(&self, b: &[u8]) -> Result<Output> {
        let c: Cursor = decode(b)?;
        if c.done != 3 {
            return Err("incomplete".into());
        }
        Ok(Output {
            state: vec![3],
            events: vec![6],
            scores: vec![9],
        })
    }
}
fn fresh() -> Coordinator<Toy> {
    Coordinator::create(
        &[0],
        Identity {
            source_id: "01".repeat(32),
            rules_hash: "02".repeat(32),
            config_hash: "03".repeat(32),
            schema_hash: "04".repeat(32),
        },
        0,
        0,
        "00".repeat(32),
        Toy,
    )
    .unwrap()
}
fn load(h: &mut Coordinator<Toy>) {
    let b = h.snapshot().unwrap();
    *h = Coordinator::restore(&b, &hash(&b), Toy).unwrap();
}
fn fill(h: &mut Coordinator<Toy>) {
    h.apply(Action::Ingest {
        start: Int::from(0),
        records: vec![Some("aa".into()), None],
        anchor: "ab".repeat(32),
    })
    .unwrap();
    h.apply(Action::Seal {
        logical_end: Int::from(1),
    })
    .unwrap();
}
#[test]
fn retirement_and_publication_are_one_change() {
    let mut h = fresh();
    fill(&mut h);
    assert_eq!(h.record.journal.head.state_hex, "00");
    h.apply(Action::Step { budget: 3 }).unwrap();
    assert_eq!(h.record.inbox.retired_to, Int::from(0));
    let m = h
        .record
        .journal
        .stage
        .as_ref()
        .unwrap()
        .ready_hash
        .clone()
        .unwrap();
    h.apply(Action::Publish {
        manifest_hash: m.clone(),
    })
    .unwrap();
    assert_eq!(h.record.inbox.retired_to, Int::from(2));
    assert!(h.record.inbox.pending.is_empty());
    let b = h.snapshot().unwrap();
    h.apply(Action::Publish { manifest_hash: m }).unwrap();
    assert_eq!(h.snapshot().unwrap(), b);
}
#[test]
fn resumes_every_operation() {
    let mut h = fresh();
    fill(&mut h);
    load(&mut h);
    for _ in 0..3 {
        h.apply(Action::Step { budget: 1 }).unwrap();
        load(&mut h);
    }
    let m = h
        .record
        .journal
        .stage
        .as_ref()
        .unwrap()
        .ready_hash
        .clone()
        .unwrap();
    h.apply(Action::Publish { manifest_hash: m }).unwrap();
    load(&mut h);
    assert_eq!(h.record.journal.head.state_hex, "03");
}
#[test]
fn stale_proposal_is_rejected() {
    let mut h = fresh();
    fill(&mut h);
    let p = h.propose(Action::Step { budget: 1 }).unwrap();
    h.apply(Action::Step { budget: 2 }).unwrap();
    assert!(h.commit(p).is_err());
}
#[test]
fn failed_operation_does_not_mutate() {
    let mut h = fresh();
    let b = h.snapshot().unwrap();
    assert!(h.apply(Action::Step { budget: 1 }).is_err());
    assert_eq!(h.snapshot().unwrap(), b);
}
#[test]
fn rejects_unmatched_source_and_reservation() {
    let mut h = fresh();
    fill(&mut h);
    h.record.inbox.reservation = None;
    assert!(h.validate().is_err());
    let mut h = fresh();
    h.record.inbox.source_id = "ff".repeat(32);
    assert!(h.validate().is_err());
}
#[test]
fn publication_contains_only_committed_data() {
    let mut h = fresh();
    let before = dtr_host::observation::publication(&h.record).unwrap();
    fill(&mut h);
    h.apply(Action::Step { budget: 1 }).unwrap();
    let during = dtr_host::observation::publication(&h.record).unwrap();
    assert_eq!(before.artifacts, during.artifacts);
    assert_eq!(before.sha256, during.sha256);
}

fn ordered(start: u64, end: u64, positions: &[u64]) -> Action {
    Action::IngestOrdered {
        start: Int(start.into()),
        end: Int(end.into()),
        anchor: "aa".repeat(32),
        inputs: positions
            .iter()
            .map(|p| Input {
                position: Int((*p).into()),
                payload_hex: "ab".into(),
            })
            .collect(),
    }
}
#[test]
fn sparse_admission_survives_restore_and_stale_fences() {
    let mut h = fresh();
    let stale = h.propose(ordered(0, 801, &[100, 109, 800])).unwrap();
    h.apply(ordered(0, 801, &[100, 109, 800])).unwrap();
    load(&mut h);
    let saved = h.snapshot().unwrap();
    assert!(h.commit(stale).is_err());
    assert!(h.apply(ordered(0, 801, &[100, 109, 800])).is_err());
    assert_eq!(h.snapshot().unwrap(), saved);
    h.apply(Action::Seal {
        logical_end: Int::from(1),
    })
    .unwrap();
    assert_eq!(h.record.journal.stage.as_ref().unwrap().inputs.len(), 3);
    h.apply(ordered(801, 1_000_000_000, &[])).unwrap();
    load(&mut h);
}
#[test]
fn invalid_sparse_admission_is_atomic() {
    let mut h = fresh();
    let saved = h.snapshot().unwrap();
    for action in [
        ordered(1, 2, &[1]),
        ordered(0, 2, &[1, 1]),
        ordered(0, 3, &[2, 1]),
        ordered(0, 2, &[2]),
        ordered(0, 0, &[0]),
        ordered(0, 0, &[]),
        ordered(0, 2, &vec![1; 257]),
    ] {
        assert!(h.apply(action).is_err());
        assert_eq!(h.snapshot().unwrap(), saved);
    }
    let mut overflow = ordered(0, 1, &[]);
    if let Action::IngestOrdered { end, .. } = &mut overflow {
        *end = Int((u128::from(u64::MAX) + 1).into());
    }
    assert!(h.apply(overflow).is_err());
    let mut large = ordered(0, 1, &[0]);
    if let Action::IngestOrdered { inputs, .. } = &mut large {
        inputs[0].payload_hex = "ff".repeat(1025);
    }
    assert!(h.apply(large).is_err());
    assert_eq!(h.snapshot().unwrap(), saved);
    for n in 0..16 {
        let start = n * 256;
        h.apply(ordered(
            start,
            start + 256,
            &(start..start + 256).collect::<Vec<_>>(),
        ))
        .unwrap();
    }
    let full = h.snapshot().unwrap();
    assert!(h.apply(ordered(4096, 4097, &[4096])).is_err());
    assert_eq!(h.snapshot().unwrap(), full);
}

fn committed() -> Coordinator<Toy> {
    let mut h = fresh();
    fill(&mut h);
    finish(&mut h, None);
    h
}
fn finish(h: &mut Coordinator<Toy>, end: Option<u64>) {
    if let Some(end) = end {
        h.apply(Action::Seal {
            logical_end: Int(end.into()),
        })
        .unwrap();
    }
    h.apply(Action::Step { budget: 3 }).unwrap();
    h.apply(Action::Publish {
        manifest_hash: h
            .record
            .journal
            .stage
            .as_ref()
            .unwrap()
            .ready_hash
            .clone()
            .unwrap(),
    })
    .unwrap();
}
fn next_identity() -> Identity {
    Identity {
        rules_hash: "05".repeat(32),
        schema_hash: "06".repeat(32),
        ..fresh().record.journal.identity
    }
}
fn output() -> Output {
    Output {
        state: vec![4],
        events: vec![7],
        scores: vec![9],
    }
}
fn transition(e: &dtr_host::epoch::Epoch) -> Action {
    Action::Transition {
        epoch: Box::new(e.clone()),
        state_hex: "04".into(),
        event_hex: "07".into(),
        score_hex: "09".into(),
    }
}
#[test]
fn epoch_shared_public_bytes() {
    use dtr_host::observation::publication;
    use dtr_wire::hex;
    let mut h = committed();
    let previous = publication(&h.record).unwrap();
    let e = h
        .prepare_transition(next_identity(), &output(), "cd".repeat(32))
        .unwrap();
    h.apply(transition(&e)).unwrap();
    let checkpoint = publication(&h.record).unwrap();
    load(&mut h);
    finish(&mut h, Some(2));
    let successor = publication(&h.record).unwrap();
    let actual = serde_json::json!({
        "previous_publication_hex": hex(&previous.bytes),
        "epoch_hex": hex(&encode(&e).unwrap()),
        "checkpoint_publication_hex": hex(&checkpoint.bytes),
        "successor_seal_hex": hex(&h.record.journal.head.seal.as_ref().unwrap().bytes().unwrap()),
        "successor_publication_hex": hex(&successor.bytes),
    });
    // Explicit generator mode writes only a caller-selected review artifact, never a golden.
    if let Ok(path) = std::env::var("DTR_EPOCH_REVIEW_VECTOR") {
        std::fs::write(path, serde_json::to_vec_pretty(&actual).unwrap()).unwrap();
    } else {
        let expected: serde_json::Value =
            serde_json::from_str(include_str!("../../../tests/fixtures/epoch-v1.json")).unwrap();
        assert_eq!(actual, expected);
    }
    assert_eq!(
        previous.bytes,
        dtr_wire::unhex(actual["previous_publication_hex"].as_str().unwrap()).unwrap()
    );
    assert_eq!(
        h.record
            .journal
            .head
            .seal
            .as_ref()
            .unwrap()
            .bytes()
            .unwrap()
            .len(),
        340
    );
    assert_eq!(previous.data.head.seal.unwrap().bytes().unwrap().len(), 308);
}
#[test]
fn epoch_boundary_validation_and_atomic_retry_recovery() {
    let mut h = fresh();
    assert!(h
        .prepare_transition(next_identity(), &output(), "cd".repeat(32))
        .is_err());
    fill(&mut h);
    assert!(h
        .prepare_transition(next_identity(), &output(), "cd".repeat(32))
        .is_err());
    finish(&mut h, None);
    let e = h
        .prepare_transition(next_identity(), &output(), "cd".repeat(32))
        .unwrap();
    let old = h.snapshot().unwrap();
    let p = h.propose(transition(&e)).unwrap();
    assert_eq!(h.snapshot().unwrap(), old); // Interrupted before outer-root persistence.
    load(&mut h);
    h.apply(transition(&e)).unwrap();
    assert!(h.commit(p).is_err()); // A stale proposal cannot overwrite the committed transition.
    load(&mut h); // Lost acknowledgement after root persistence.
    let checkpoint = h.snapshot().unwrap();
    h.apply(transition(&e)).unwrap();
    assert_eq!(h.snapshot().unwrap(), checkpoint);
    finish(&mut h, Some(2));
    load(&mut h);
    let later = h.snapshot().unwrap();
    h.apply(transition(&e)).unwrap();
    assert_eq!(h.snapshot().unwrap(), later);
    assert!(h
        .prepare_transition(next_identity(), &output(), "cd".repeat(32))
        .is_err());
    for empty in [false, true] {
        let mut h = committed();
        h.apply(ordered(2, 10, if empty { &[] } else { &[3] }))
            .unwrap();
        let saved = h.snapshot().unwrap();
        assert!(h
            .prepare_transition(next_identity(), &output(), "cd".repeat(32))
            .is_err());
        assert!(h.apply(transition(&e)).is_err());
        assert_eq!(h.snapshot().unwrap(), saved);
    }
}
#[test]
fn epoch_corruption_and_wrong_predecessor_are_rejected_atomically() {
    let mut h = committed();
    let e = h
        .prepare_transition(next_identity(), &output(), "cd".repeat(32))
        .unwrap();
    let saved = h.snapshot().unwrap();
    for n in 0..6 {
        let mut wrong = e.clone();
        match n {
            0 => wrong.metadata_hash = "ee".repeat(32),
            1 => wrong.source_cursor = Int::from(3),
            2 => wrong.source_anchor = "00".repeat(32),
            3 => wrong.state_hash = "ff".repeat(32),
            4 => wrong.previous_publication_hex = "00".into(),
            _ => wrong.new_identity.source_id = "ff".repeat(32),
        }
        if n != 0 {
            wrong.transition_hash = wrong.commitment().unwrap();
        }
        assert!(h.apply(transition(&wrong)).is_err());
        assert_eq!(h.snapshot().unwrap(), saved);
    }
    let mut other = committed();
    finish(&mut other, Some(2));
    let wrong = other
        .prepare_transition(next_identity(), &output(), "cd".repeat(32))
        .unwrap();
    assert!(h.apply(transition(&wrong)).is_err());
    h.apply(transition(&e)).unwrap();
    finish(&mut h, Some(2));
    h.record
        .journal
        .epoch
        .as_mut()
        .unwrap()
        .previous_publication_hex = "00".into();
    let damaged = h.snapshot().unwrap();
    assert!(Coordinator::restore(&damaged, &hash(&damaged), Toy).is_err());
}

#[test]
fn committed_head_memo_never_trusts_mutated_public_records() {
    let mut h = fresh();
    fill(&mut h);
    h.apply(Action::Step { budget: 3 }).unwrap();
    let ready = h
        .record
        .journal
        .stage
        .as_ref()
        .unwrap()
        .ready_hash
        .clone()
        .unwrap();
    h.apply(Action::Publish {
        manifest_hash: ready,
    })
    .unwrap();
    h.validate().unwrap();
    let original = h.snapshot().unwrap();
    for field in 0..7 {
        let mut changed = Coordinator::restore(&original, &hash(&original), Toy).unwrap();
        changed.validate().unwrap(); // warm exact-head proof
        match field {
            0 => changed.record.journal.head.state_hex = "04".into(),
            1 => changed.record.journal.head.event_hex = "07".into(),
            2 => changed.record.journal.head.score_hex = "0a".into(),
            3 => changed.record.journal.head.manifest_hash = "aa".repeat(32),
            4 => changed.record.journal.identity.rules_hash = "bb".repeat(32),
            5 => changed.record.inbox.last_ack = None,
            _ => {
                changed
                    .record
                    .journal
                    .head
                    .seal
                    .as_mut()
                    .unwrap()
                    .source_anchor = "cc".repeat(32)
            }
        }
        assert!(changed.validate().is_err());
        let clean = Coordinator::restore(&original, &hash(&original), Toy).unwrap();
        changed.record = clean.record;
        changed.validate().unwrap();
        assert_eq!(changed.snapshot().unwrap(), original);
    }
}

#[test]
fn validated_record_session_rejects_stale_mutations_and_is_transactional() {
    let mut h = fresh();
    fill(&mut h);
    let original = h.snapshot().unwrap();
    h.validate().unwrap();
    let proposal = h.propose(Action::Step { budget: 1 }).unwrap();
    // A computed-but-uncommitted proposal cannot change the exported checkpoint.
    assert_eq!(h.snapshot().unwrap(), original);
    let before = h.record.clone();
    h.record.inbox.cursor = Int::from(99);
    // Ordered admission permits advancing over absent records while a sealed
    // stage is unfinished. A changed record must be validated, not rejected
    // solely for differing from the previous proof.
    h.validate().unwrap();
    let advanced = h.snapshot().unwrap();
    Coordinator::restore(&advanced, &hash(&advanced), Toy).unwrap();
    h.record.inbox.version = 999;
    assert!(h.validate().is_err());
    h.record = before;
    h.validate().unwrap();
    let before = h.snapshot().unwrap();
    assert!(h
        .apply(Action::Publish {
            manifest_hash: "aa".repeat(32)
        })
        .is_err());
    assert_eq!(h.snapshot().unwrap(), before);
    h.commit(proposal).unwrap();
    let committed = h.snapshot().unwrap();
    let restored = Coordinator::restore(&committed, &hash(&committed), Toy).unwrap();
    assert_eq!(restored.snapshot().unwrap(), committed);
    for field in 0..5 {
        let mut changed = Coordinator::restore(&committed, &hash(&committed), Toy).unwrap();
        match field {
            0 => changed.record.journal.stage.as_mut().unwrap().cursor_hash = "00".repeat(32),
            1 => changed.record.journal.stage.as_mut().unwrap().cursor_hex = "00".into(),
            2 => changed.record.inbox.reservation.as_mut().unwrap().seal_hash = "00".repeat(32),
            3 => changed.record.inbox.source_id = "ff".repeat(32),
            _ => changed.record.version = 999,
        }
        assert!(changed.validate().is_err());
    }
}

#[test]
fn explicit_idle_checkpoints_preserve_clock_source_and_recovery() {
    let mut h = committed();
    let e = h
        .prepare_transition(next_identity(), &output(), "cd".repeat(32))
        .unwrap();
    h.apply(transition(&e)).unwrap();
    let boundary = h.record.journal.head.logical_end.clone();
    let source = h.record.inbox.cursor.clone();
    for n in 0..48 {
        let old = dtr_host::observation::publication(&h.record).unwrap();
        let e = h
            .prepare_checkpoint(&output(), hash(format!("context:{n}").as_bytes()))
            .unwrap();
        assert_eq!(e.version, 3);
        assert_eq!(e.new_identity, next_identity());
        assert_eq!(e.logical_boundary, boundary);
        assert_eq!(e.source_cursor, source);
        assert!(h
            .prepare_transition(next_identity(), &output(), "ef".repeat(32))
            .is_err());
        e.expected_predecessor(&old.bytes).unwrap();
        h.apply(transition(&e)).unwrap();
        load(&mut h);
        let p = dtr_host::observation::publication(&h.record).unwrap();
        assert_eq!(p.data.version, 9);
        assert!(p.bytes.len() < 8192);
        let saved = h.snapshot().unwrap();
        h.apply(transition(&e)).unwrap();
        assert_eq!(saved, h.snapshot().unwrap());
    }
    finish(&mut h, Some(2));
    let seal = h.record.journal.head.seal.as_ref().unwrap();
    assert_eq!(seal.logical_start, boundary);
    assert_eq!(seal.source_from, source);
}

#[test]
fn checkpoint_identity_context_and_source_corruption_are_atomic_failures() {
    let mut h = committed();
    let first = h
        .prepare_transition(next_identity(), &output(), "cd".repeat(32))
        .unwrap();
    h.apply(transition(&first)).unwrap();
    let e = h.prepare_checkpoint(&output(), "ef".repeat(32)).unwrap();
    let saved = h.snapshot().unwrap();
    for n in 0..7 {
        let mut bad = e.clone();
        match n {
            0 => bad.new_identity.rules_hash = "ff".repeat(32),
            1 => bad.source_cursor = Int::from(3),
            2 => bad.logical_boundary = Int::from(2),
            3 => bad.source_anchor = "ff".repeat(32),
            4 => bad.predecessor.as_mut().unwrap().publication_hash = "ff".repeat(32),
            5 => bad.previous_chain_hash = Some("ff".repeat(32)),
            _ => bad.transition_index = Some(Int::from(9)),
        }
        bad.transition_hash = bad.commitment().unwrap();
        assert!(h.apply(transition(&bad)).is_err());
        assert_eq!(saved, h.snapshot().unwrap());
    }
    let mut bad = e.clone();
    bad.metadata_hash = "ff".repeat(32);
    assert!(h.apply(transition(&bad)).is_err());
    assert_eq!(saved, h.snapshot().unwrap());
    h.apply(Action::Ingest {
        start: Int::from(2),
        records: vec![Some("aa".into())],
        anchor: "ab".repeat(32),
    })
    .unwrap();
    let pending = h.snapshot().unwrap();
    assert!(h.prepare_checkpoint(&output(), "ef".repeat(32)).is_err());
    assert_eq!(pending, h.snapshot().unwrap());
}

#[test]
fn same_identity_checkpoint_public_bytes_match_independent_js() {
    use dtr_host::observation::publication;
    use dtr_wire::hex;
    let mut h = committed();
    let first_rule = h
        .prepare_transition(next_identity(), &output(), "cd".repeat(32))
        .unwrap();
    h.apply(transition(&first_rule)).unwrap();
    let previous = publication(&h.record).unwrap();
    let one = h.prepare_checkpoint(&output(), "ef".repeat(32)).unwrap();
    h.apply(transition(&one)).unwrap();
    let first = publication(&h.record).unwrap();
    let two = h.prepare_checkpoint(&output(), "dd".repeat(32)).unwrap();
    h.apply(transition(&two)).unwrap();
    let second = publication(&h.record).unwrap();
    finish(&mut h, Some(2));
    let successor = publication(&h.record).unwrap();
    let actual = serde_json::json!({"previous_publication_hex":hex(&previous.bytes),"first_epoch_hex":hex(&encode(&one).unwrap()),"first_publication_hex":hex(&first.bytes),"second_epoch_hex":hex(&encode(&two).unwrap()),"second_publication_hex":hex(&second.bytes),"successor_seal_hex":hex(&h.record.journal.head.seal.as_ref().unwrap().bytes().unwrap()),"successor_publication_hex":hex(&successor.bytes)});
    let expected: serde_json::Value = serde_json::from_str(include_str!(
        "../../../tests/fixtures/application-checkpoint-v3.json"
    ))
    .unwrap();
    assert_eq!(actual, expected);
}

#[test]
fn checkpoint_acknowledges_only_an_already_verified_empty_prefix() {
    let mut h = committed();
    let first = h
        .prepare_transition(next_identity(), &output(), "cd".repeat(32))
        .unwrap();
    h.apply(transition(&first)).unwrap();
    let old = dtr_host::observation::publication(&h.record).unwrap();
    h.apply(Action::IngestOrdered {
        start: Int::from(2),
        end: Int(9_007_199_254_741_000u64.into()),
        inputs: vec![],
        anchor: "bc".repeat(32),
    })
    .unwrap();
    let mut new_identity = next_identity();
    new_identity.config_hash = "08".repeat(32);
    assert!(h
        .prepare_transition(new_identity, &output(), "cd".repeat(32))
        .is_err());
    let e = h.prepare_checkpoint(&output(), "ef".repeat(32)).unwrap();
    assert_eq!(e.source_cursor, Int(9_007_199_254_741_000u64.into()));
    assert_eq!(e.logical_boundary, Int::from(1));
    e.expected_predecessor(&old.bytes).unwrap();
    h.apply(transition(&e)).unwrap();
    assert_eq!(h.record.inbox.retired_to, e.source_cursor);
    load(&mut h);
    h.apply(Action::IngestOrdered {
        start: e.source_cursor.clone(),
        end: Int(9_007_199_254_741_001u64.into()),
        inputs: vec![Input {
            position: e.source_cursor,
            payload_hex: "aa".into(),
        }],
        anchor: "bd".repeat(32),
    })
    .unwrap();
    let saved = h.snapshot().unwrap();
    assert!(h.prepare_checkpoint(&output(), "ef".repeat(32)).is_err());
    assert_eq!(saved, h.snapshot().unwrap());
}
