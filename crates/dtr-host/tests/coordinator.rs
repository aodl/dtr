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
