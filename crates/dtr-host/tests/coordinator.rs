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
