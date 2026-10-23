//! The same epoch API works with the independent competitive-Life kernel.
use dtr_core::ResumableKernel;
use dtr_host::{Action, Coordinator, Identity, Input, Kernel, Output, Progress, Seal};
use dtr_wire::{hash, hex, unhex, Result};
use life_conformance::{Board, Cursor};
#[derive(Clone, Copy)]
struct Life;
fn number(n: &dtr_wire::Int) -> Result<u64> {
    u64::try_from(&n.0).map_err(error)
}
fn error(e: impl std::fmt::Debug) -> String {
    format!("{e:?}")
}
impl Kernel for Life {
    fn begin(&self, state: &[u8], inputs: &[Input], seal: &Seal) -> Result<Vec<u8>> {
        if !inputs.is_empty() {
            return Err("no input adapter in this example".into());
        }
        let board = Board::decode(state).map_err(error)?;
        if board.generation != number(&seal.logical_start)? {
            return Err("Life generation boundary".into());
        }
        let count = number(&seal.logical_end)? - number(&seal.logical_start)?;
        Ok(Cursor::new(board, count.try_into().map_err(error)?)
            .map_err(error)?
            .snapshot())
    }
    fn validate_cursor(&self, bytes: &[u8], expected: &str) -> Result<()> {
        if hash(bytes) != expected {
            return Err("cursor integrity".into());
        }
        Cursor::restore(bytes).map_err(error)?;
        Ok(())
    }
    fn step(&self, bytes: &[u8], budget: usize) -> Result<(Vec<u8>, Progress)> {
        let mut c = Cursor::restore(bytes).map_err(error)?;
        let mut used = 0;
        while used < budget && !c.complete() {
            c.step(1).map_err(error)?;
            used += 1;
        }
        Ok((
            c.snapshot(),
            Progress {
                used,
                complete: c.complete(),
            },
        ))
    }
    fn result(&self, bytes: &[u8]) -> Result<Output> {
        let c = Cursor::restore(bytes).map_err(error)?;
        if !c.complete() {
            return Err("Life unfinished".into());
        }
        Ok(Output {
            state: c.state.encode(),
            events: c.event_bytes(),
            scores: c.score_bytes(),
        })
    }
}
fn finish(h: &mut Coordinator<Life>, end: u64) {
    h.apply(Action::Seal {
        logical_end: dtr_wire::Int(end.into()),
    })
    .unwrap();
    while h.record.journal.stage.as_ref().unwrap().phase == "running" {
        h.apply(Action::Step { budget: 7 }).unwrap();
        let bytes = h.snapshot().unwrap();
        *h = Coordinator::restore(&bytes, &hash(&bytes), Life).unwrap();
    }
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
#[test]
fn life_generation_and_cell_owners_survive_epoch_and_restart() {
    let initial = Board::new(
        4,
        4,
        0,
        vec![0, 0, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0],
    )
    .unwrap();
    let identity = Identity {
        source_id: "01".repeat(32),
        rules_hash: "02".repeat(32),
        config_hash: "03".repeat(32),
        schema_hash: "04".repeat(32),
    };
    let mut h = Coordinator::create(
        &initial.encode(),
        identity.clone(),
        0,
        0,
        "00".repeat(32),
        Life,
    )
    .unwrap();
    finish(&mut h, 1);
    let old = dtr_host::observation::publication(&h.record).unwrap();
    let output = Output {
        state: unhex(&h.record.journal.head.state_hex).unwrap(),
        events: vec![],
        scores: vec![],
    };
    let next = Identity {
        config_hash: "ff".repeat(32),
        ..identity
    };
    let epoch = h
        .prepare_transition(next, &output, "aa".repeat(32))
        .unwrap();
    h.apply(Action::Transition {
        epoch: Box::new(epoch.clone()),
        state_hex: hex(&output.state),
        event_hex: String::new(),
        score_hex: String::new(),
    })
    .unwrap();
    let bytes = h.snapshot().unwrap();
    h = Coordinator::restore(&bytes, &hash(&bytes), Life).unwrap();
    assert_eq!(
        unhex(&h.record.journal.head.state_hex).unwrap(),
        output.state
    );
    finish(&mut h, 2);
    assert_eq!(
        h.record
            .journal
            .head
            .seal
            .as_ref()
            .unwrap()
            .epoch_hash
            .as_ref(),
        Some(&epoch.transition_hash)
    );
    assert_eq!(
        Board::decode(&unhex(&h.record.journal.head.state_hex).unwrap())
            .unwrap()
            .generation,
        2
    );
    assert_eq!(epoch.previous_publication_hex, hex(&old.bytes));
}
