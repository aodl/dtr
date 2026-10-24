//! S05 pure deterministic coordinator. No IC, game, clock or network dependency.
//! The embedding storage adapter must atomically persist a proposed complete image.
#![forbid(unsafe_code)]
use dtr_wire::{decode, encode, hash, hex, unhex, Int, Result};
use num_traits::ToPrimitive;
use serde::{Deserialize, Serialize};
pub mod epoch;
use epoch::Epoch;

const SAFE: u64 = (1u64 << 53) - 1;
pub const MAX_IMAGE: usize = 8 * 1024 * 1024;
const ZERO: &str = "0000000000000000000000000000000000000000000000000000000000000000";
fn nat(n: u64) -> Int {
    Int(n.into())
}
fn number(n: &Int) -> Result<u64> {
    n.0.to_u64().ok_or_else(|| "unsigned 64-bit field".into())
}
fn inc(n: &mut u64) -> Result<()> {
    if *n >= SAFE {
        return Err("revision exhausted".into());
    }
    *n += 1;
    Ok(())
}
fn digest(s: &str) -> Result<Vec<u8>> {
    let b = unhex(s)?;
    if b.len() != 32 {
        return Err("hash length".into());
    }
    Ok(b)
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Identity {
    pub source_id: String,
    pub rules_hash: String,
    pub config_hash: String,
    pub schema_hash: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Input {
    pub position: Int,
    pub payload_hex: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Seal {
    pub segment_id: Int,
    pub logical_start: Int,
    pub logical_end: Int,
    pub source_from: Int,
    pub source_to_exclusive: Int,
    pub input_count: u32,
    pub source_id: String,
    pub source_anchor: String,
    pub rules_hash: String,
    pub config_hash: String,
    pub schema_hash: String,
    pub previous_state: String,
    pub previous_manifest: String,
    pub input_root: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub epoch_hash: Option<String>,
}
impl Seal {
    pub fn bytes(&self) -> Result<Vec<u8>> {
        let id = number(&self.segment_id)?;
        let start = number(&self.logical_start)?;
        let end = number(&self.logical_end)?;
        let from = number(&self.source_from)?;
        let to = number(&self.source_to_exclusive)?;
        if end <= start
            || to < from
            || self.input_count > 4096
            || u64::from(self.input_count) > to - from
        {
            return Err("seal bounds".into());
        }
        let mut b = if self.epoch_hash.is_some() {
            b"DTRSEAL2".to_vec()
        } else {
            b"DTRSEAL1".to_vec()
        };
        for n in [id, start, end, from, to] {
            b.extend_from_slice(&n.to_be_bytes());
        }
        b.extend_from_slice(&self.input_count.to_be_bytes());
        for s in [
            &self.source_id,
            &self.source_anchor,
            &self.rules_hash,
            &self.config_hash,
            &self.schema_hash,
            &self.previous_state,
            &self.previous_manifest,
            &self.input_root,
        ] {
            b.extend(digest(s)?);
        }
        if let Some(epoch) = &self.epoch_hash {
            b.extend(digest(epoch)?);
        }
        Ok(b)
    }
    fn matches(&self, i: &Identity) -> bool {
        self.source_id == i.source_id
            && self.rules_hash == i.rules_hash
            && self.config_hash == i.config_hash
            && self.schema_hash == i.schema_hash
    }
}
pub fn input_root(inputs: &[Input], from: u64, to: u64) -> Result<String> {
    if to < from || inputs.len() > 4096 {
        return Err("input bounds".into());
    }
    let mut prior = None;
    let mut b = b"DTRINPUT1".to_vec();
    b.extend_from_slice(&(inputs.len() as u32).to_be_bytes());
    for i in inputs {
        let pos = number(&i.position)?;
        let payload = unhex(&i.payload_hex)?;
        if pos < from || pos >= to || prior.is_some_and(|p| pos <= p) || payload.len() > 1024 {
            return Err("input order/bounds".into());
        }
        prior = Some(pos);
        b.extend_from_slice(&pos.to_be_bytes());
        b.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        b.extend(payload);
    }
    Ok(hash(&b))
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub version: u32,
    pub seal_hash: String,
    pub state_hash: String,
    pub event_hash: String,
    pub score_hash: String,
    pub manifest_hash: String,
}
pub(crate) fn manifest_root(seal: &Seal, hashes: [&String; 3]) -> Result<String> {
    let mut b = b"DTRMANI1".to_vec();
    b.extend(digest(&hash(&seal.bytes()?))?);
    for h in hashes {
        b.extend(digest(h)?);
    }
    Ok(hash(&b))
}
pub fn manifest(seal: &Seal, out: &Output) -> Result<Manifest> {
    let hashes = [
        hash(&seal.bytes()?),
        hash(&out.state),
        hash(&out.events),
        hash(&out.scores),
    ];
    let mut b = b"DTRMANI1".to_vec();
    for h in &hashes {
        b.extend(digest(h)?);
    }
    Ok(Manifest {
        version: 1,
        seal_hash: hashes[0].clone(),
        state_hash: hashes[1].clone(),
        event_hash: hashes[2].clone(),
        score_hash: hashes[3].clone(),
        manifest_hash: hash(&b),
    })
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Head {
    pub segment_id: Option<Int>,
    pub logical_end: Int,
    pub source_to_exclusive: Int,
    pub manifest_hash: String,
    pub state_hash: String,
    pub state_hex: String,
    pub seal: Option<Seal>,
    pub event_hex: String,
    pub score_hex: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stage {
    pub phase: String,
    pub fence: u64,
    pub seal: Seal,
    pub inputs: Vec<Input>,
    pub cursor_hex: String,
    pub cursor_hash: String,
    pub ready_hash: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Journal {
    pub version: u32,
    pub revision: u64,
    pub identity: Identity,
    pub fence: u64,
    pub stage: Option<Stage>,
    pub head: Head,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub epoch: Option<Epoch>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Reservation {
    pub seal: Seal,
    pub seal_hash: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Inbox {
    pub version: u32,
    pub revision: u64,
    pub source_id: String,
    pub cursor: Int,
    pub retired_to: Int,
    pub source_anchor: String,
    pub pending: Vec<Input>,
    pub reservation: Option<Reservation>,
    pub last_ack: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Record {
    pub version: u32,
    pub revision: u64,
    pub journal: Journal,
    pub inbox: Inbox,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Action {
    Ingest {
        start: Int,
        records: Vec<Option<String>>,
        anchor: String,
    },
    /// Adapter-verified sparse range; gaps do not imply independently inspected records.
    IngestOrdered {
        start: Int,
        end: Int,
        inputs: Vec<Input>,
        anchor: String,
    },
    Seal {
        logical_end: Int,
    },
    Step {
        budget: usize,
    },
    Publish {
        manifest_hash: String,
    },
    Transition {
        epoch: Box<Epoch>,
        state_hex: String,
        event_hex: String,
        score_hex: String,
    },
}
#[derive(Clone, Debug)]
pub struct Output {
    pub state: Vec<u8>,
    pub events: Vec<u8>,
    pub scores: Vec<u8>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Progress {
    pub used: usize,
    pub complete: bool,
}
pub trait Kernel {
    fn begin(&self, state: &[u8], inputs: &[Input], seal: &Seal) -> Result<Vec<u8>>;
    fn validate_cursor(&self, bytes: &[u8], expected_hash: &str) -> Result<()>;
    fn step(&self, cursor: &[u8], budget: usize) -> Result<(Vec<u8>, Progress)>;
    fn result(&self, cursor: &[u8]) -> Result<Output>;
}
#[derive(Clone, Debug)]
pub struct Proposal {
    pub expected: u64,
    pub record: Record,
    pub progress: Option<Progress>,
    pub unchanged: bool,
}
pub struct Coordinator<K: Kernel> {
    pub record: Record,
    kernel: K,
}

/// One validation/transition for dense and ordered admission. A zero-width range
/// must be empty and retain its anchor; an empty advancing range may change it.
fn admit(i: &mut Inbox, start: &Int, end: &Int, inputs: Vec<Input>, anchor: String) -> Result<()> {
    let from = number(start)?;
    let to = number(end)?;
    digest(&anchor)?;
    if from != number(&i.cursor)? || inputs.len() > 256 {
        return Err("source prefix/page".into());
    }
    input_root(&inputs, from, to)?;
    if i.pending.len() + inputs.len() > 4096 {
        return Err("inbox backpressure".into());
    }
    if from == to && anchor != i.source_anchor {
        return Err("empty prefix anchor change".into());
    }
    i.pending.extend(inputs);
    i.cursor = nat(to);
    i.source_anchor = anchor;
    inc(&mut i.revision)
}
fn selected(i: &Inbox, cutoff: u64) -> Result<Vec<Input>> {
    if cutoff < number(&i.retired_to)? || cutoff > number(&i.cursor)? {
        return Err("unverified cutoff".into());
    }
    let mut out = Vec::new();
    for p in &i.pending {
        if number(&p.position)? < cutoff {
            out.push(p.clone());
        }
    }
    Ok(out)
}
fn validate_seal(j: &Journal, s: &Seal, inputs: &[Input]) -> Result<()> {
    s.bytes()?;
    if !s.matches(&j.identity)
        || s.epoch_hash.as_ref() != j.epoch.as_ref().map(|e| &e.transition_hash)
        || s.previous_state != j.head.state_hash
        || s.previous_manifest != j.head.manifest_hash
        || s.logical_start != j.head.logical_end
        || s.source_from != j.head.source_to_exclusive
    {
        return Err("seal identity/previous head".into());
    }
    let next = match &j.head.segment_id {
        None => 0,
        Some(n) => number(n)?.checked_add(1).ok_or("segment overflow")?,
    };
    if number(&s.segment_id)? != next
        || s.input_count as usize != inputs.len()
        || s.input_root
            != input_root(
                inputs,
                number(&s.source_from)?,
                number(&s.source_to_exclusive)?,
            )?
    {
        return Err("seal input/sequence".into());
    }
    Ok(())
}
impl<K: Kernel> Coordinator<K> {
    pub fn create(
        state: &[u8],
        identity: Identity,
        logical_start: u64,
        source_from: u64,
        anchor: String,
        kernel: K,
    ) -> Result<Self> {
        let head = Head {
            segment_id: None,
            logical_end: nat(logical_start),
            source_to_exclusive: nat(source_from),
            manifest_hash: ZERO.into(),
            state_hash: hash(state),
            state_hex: hex(state),
            seal: None,
            event_hex: String::new(),
            score_hex: String::new(),
        };
        let inbox = Inbox {
            version: 2,
            revision: 0,
            source_id: identity.source_id.clone(),
            cursor: nat(source_from),
            retired_to: nat(source_from),
            source_anchor: anchor,
            pending: Vec::new(),
            reservation: None,
            last_ack: None,
        };
        let journal = Journal {
            version: 2,
            revision: 0,
            identity,
            fence: 0,
            stage: None,
            head,
            epoch: None,
        };
        let c = Self {
            record: Record {
                version: 5,
                revision: 0,
                journal,
                inbox,
            },
            kernel,
        };
        c.validate()?;
        Ok(c)
    }
    pub fn restore(bytes: &[u8], expected: &str, kernel: K) -> Result<Self> {
        if bytes.len() > MAX_IMAGE || hash(bytes) != expected {
            return Err("coordinator integrity".into());
        }
        let c = Self {
            record: decode(bytes)?,
            kernel,
        };
        c.validate()?;
        if encode(&c.record)? != bytes {
            return Err("coordinator schema encoding".into());
        }
        Ok(c)
    }
    pub fn snapshot(&self) -> Result<Vec<u8>> {
        let b = encode(&self.record)?;
        if b.len() > MAX_IMAGE {
            return Err("coordinator byte capacity".into());
        }
        Ok(b)
    }
    pub fn validate(&self) -> Result<()> {
        self.validate_record(&self.record)
    }
    fn validate_record(&self, r: &Record) -> Result<()> {
        let j = &r.journal;
        let i = &r.inbox;
        let h = &j.head;
        if !matches!(
            (r.version, j.version, j.epoch.is_some()),
            (5, 2, false) | (6, 3, true)
        ) || i.version != 2
            || [r.revision, j.revision, j.fence, i.revision]
                .iter()
                .any(|n| *n > SAFE)
        {
            return Err("coordinator schema/revision".into());
        }
        for s in [
            &j.identity.source_id,
            &j.identity.rules_hash,
            &j.identity.config_hash,
            &j.identity.schema_hash,
            &i.source_anchor,
            &h.manifest_hash,
        ] {
            digest(s)?;
        }
        number(&h.logical_end)?;
        if j.identity.source_id != i.source_id || h.source_to_exclusive != i.retired_to {
            return Err("coordinator source/head divergence".into());
        }
        input_root(&i.pending, number(&i.retired_to)?, number(&i.cursor)?)?;
        if hash(&unhex(&h.state_hex)?) != h.state_hash {
            return Err("committed state mismatch".into());
        }
        if let Some(e) = &j.epoch {
            e.validate_head(h, &j.identity)?;
        }
        if let Some(s) = &h.seal {
            if s.epoch_hash.as_ref() != j.epoch.as_ref().map(|e| &e.transition_hash) {
                return Err("seal epoch mismatch".into());
            }
            let out = Output {
                state: unhex(&h.state_hex)?,
                events: unhex(&h.event_hex)?,
                scores: unhex(&h.score_hex)?,
            };
            if !s.matches(&j.identity)
                || h.segment_id.as_ref() != Some(&s.segment_id)
                || h.logical_end != s.logical_end
                || h.source_to_exclusive != s.source_to_exclusive
                || manifest(s, &out)?.manifest_hash != h.manifest_hash
                || i.last_ack.as_ref() != Some(&h.manifest_hash)
            {
                return Err("committed manifest/ack mismatch".into());
            }
        } else if let Some(e) = &j.epoch {
            if h.segment_id.as_ref() != Some(&e.segment_id)
                || i.last_ack.as_ref() != Some(&e.transition_hash)
            {
                return Err("epoch acknowledgement".into());
            }
        } else if h.segment_id.is_some() || h.manifest_hash != ZERO || i.last_ack.is_some() {
            return Err("genesis head".into());
        }
        match (&j.stage, &i.reservation) {
            (None, None) => {}
            (Some(stage), Some(res)) => {
                validate_seal(j, &stage.seal, &stage.inputs)?;
                if stage.fence != j.fence
                    || !matches!(stage.phase.as_str(), "running" | "ready")
                    || stage.seal != res.seal
                    || hash(&res.seal.bytes()?) != res.seal_hash
                    || selected(i, number(&stage.seal.source_to_exclusive)?)? != stage.inputs
                {
                    return Err("reserved stage divergence".into());
                }
                let b = unhex(&stage.cursor_hex)?;
                self.kernel.validate_cursor(&b, &stage.cursor_hash)?;
                if stage.phase == "ready"
                    && stage.ready_hash.as_ref()
                        != Some(&manifest(&stage.seal, &self.kernel.result(&b)?)?.manifest_hash)
                {
                    return Err("ready output mismatch".into());
                }
            }
            _ => return Err("coordinator reservation divergence".into()),
        }
        if encode(r)?.len() > MAX_IMAGE {
            return Err("coordinator byte capacity".into());
        }
        Ok(())
    }
    /// Trusted application supplies transformed bytes; no kernel/game semantics live here.
    /// The caller must validate its state transformation before requesting this commitment.
    pub fn prepare_transition(
        &self,
        identity: Identity,
        out: &Output,
        metadata_hash: String,
    ) -> Result<Epoch> {
        self.validate()?;
        self.transition_boundary()?;
        Epoch::make(
            &observation::publication(&self.record)?.bytes,
            identity,
            out,
            self.record.inbox.source_anchor.clone(),
            metadata_hash,
        )
    }
    fn transition_boundary(&self) -> Result<()> {
        let r = &self.record;
        let i = &r.inbox;
        let j = &r.journal;
        if j.stage.is_some()
            || i.reservation.is_some()
            || !i.pending.is_empty()
            || i.cursor != i.retired_to
            || i.cursor != j.head.source_to_exclusive
            || j.head.seal.is_none()
        {
            return Err("epoch requires drained committed boundary".into());
        }
        Ok(())
    }
    pub fn propose(&self, action: Action) -> Result<Proposal> {
        self.validate()?;
        let mut r = self.record.clone();
        let expected = r.revision;
        if expected >= SAFE {
            return Err("coordinator revision exhausted".into());
        }
        let mut progress = None;
        let mut unchanged = false;
        match action {
            Action::Transition {
                epoch,
                state_hex,
                event_hex,
                score_hex,
            } => {
                let out = Output {
                    state: unhex(&state_hex)?,
                    events: unhex(&event_hex)?,
                    scores: unhex(&score_hex)?,
                };
                epoch.validate()?;
                epoch.output_matches(&out)?;
                let retry = r.journal.epoch.as_ref() == Some(epoch.as_ref());
                if retry {
                    unchanged = true;
                } else {
                    self.transition_boundary()?;
                    let previous = observation::publication(&self.record)?.bytes;
                    epoch.expected_predecessor(&previous)?;
                    if epoch.source_cursor != r.inbox.cursor
                        || epoch.source_anchor != r.inbox.source_anchor
                    {
                        return Err("epoch expected predecessor/source".into());
                    }
                    r.version = 6;
                    r.journal.version = 3;
                    r.journal.identity = epoch.new_identity.clone();
                    r.journal.head = Head {
                        segment_id: Some(epoch.segment_id.clone()),
                        logical_end: epoch.logical_boundary.clone(),
                        source_to_exclusive: epoch.source_cursor.clone(),
                        manifest_hash: epoch.transition_hash.clone(),
                        state_hash: epoch.state_hash.clone(),
                        state_hex,
                        seal: None,
                        event_hex,
                        score_hex,
                    };
                    r.inbox.last_ack = Some(epoch.transition_hash.clone());
                    r.journal.epoch = Some(*epoch);
                    inc(&mut r.journal.fence)?;
                    inc(&mut r.journal.revision)?;
                    inc(&mut r.inbox.revision)?;
                }
            }
            Action::Ingest {
                start,
                records,
                anchor,
            } => {
                if records.len() > 256 {
                    return Err("source prefix/page".into());
                }
                let from = number(&start)?;
                let end = from
                    .checked_add(records.len() as u64)
                    .ok_or("source overflow")?;
                let inputs = records
                    .into_iter()
                    .enumerate()
                    .filter_map(|(offset, payload)| {
                        payload.map(|payload_hex| Input {
                            position: nat(from + offset as u64),
                            payload_hex,
                        })
                    })
                    .collect::<Vec<_>>();
                admit(&mut r.inbox, &start, &nat(end), inputs, anchor)?;
            }
            Action::IngestOrdered {
                start,
                end,
                inputs,
                anchor,
            } => {
                admit(&mut r.inbox, &start, &end, inputs, anchor)?;
            }
            Action::Seal { logical_end } => {
                let j = &mut r.journal;
                let i = &mut r.inbox;
                if j.stage.is_some() || i.reservation.is_some() {
                    return Err("coordinator already sealed".into());
                }
                let h = &j.head;
                let inputs = selected(i, number(&i.cursor)?)?;
                let id = match &h.segment_id {
                    None => 0,
                    Some(n) => number(n)?.checked_add(1).ok_or("segment overflow")?,
                };
                let s = Seal {
                    segment_id: nat(id),
                    logical_start: h.logical_end.clone(),
                    logical_end,
                    source_from: h.source_to_exclusive.clone(),
                    source_to_exclusive: i.cursor.clone(),
                    input_count: inputs.len() as u32,
                    source_id: j.identity.source_id.clone(),
                    source_anchor: i.source_anchor.clone(),
                    rules_hash: j.identity.rules_hash.clone(),
                    config_hash: j.identity.config_hash.clone(),
                    schema_hash: j.identity.schema_hash.clone(),
                    previous_state: h.state_hash.clone(),
                    previous_manifest: h.manifest_hash.clone(),
                    epoch_hash: j.epoch.as_ref().map(|e| e.transition_hash.clone()),
                    input_root: input_root(
                        &inputs,
                        number(&h.source_to_exclusive)?,
                        number(&i.cursor)?,
                    )?,
                };
                validate_seal(j, &s, &inputs)?;
                let bytes = self.kernel.begin(&unhex(&h.state_hex)?, &inputs, &s)?;
                i.reservation = Some(Reservation {
                    seal: s.clone(),
                    seal_hash: hash(&s.bytes()?),
                });
                inc(&mut i.revision)?;
                inc(&mut j.fence)?;
                j.stage = Some(Stage {
                    phase: "running".into(),
                    fence: j.fence,
                    seal: s,
                    inputs,
                    cursor_hex: hex(&bytes),
                    cursor_hash: hash(&bytes),
                    ready_hash: None,
                });
                inc(&mut j.revision)?;
            }
            Action::Step { budget } => {
                if budget == 0 || budget > 1_000_000 {
                    return Err("work budget".into());
                }
                let j = &mut r.journal;
                let s = j.stage.as_mut().ok_or("inactive fence")?;
                if s.phase != "running" || s.fence != j.fence {
                    return Err("inactive fence".into());
                }
                let (b, p) = self.kernel.step(&unhex(&s.cursor_hex)?, budget)?;
                if p.used > budget || (!p.complete && p.used == 0) {
                    return Err("kernel progress".into());
                }
                s.cursor_hex = hex(&b);
                s.cursor_hash = hash(&b);
                if p.complete {
                    s.phase = "ready".into();
                    s.ready_hash = Some(manifest(&s.seal, &self.kernel.result(&b)?)?.manifest_hash);
                }
                inc(&mut j.revision)?;
                progress = Some(p);
            }
            Action::Publish { manifest_hash } => {
                digest(&manifest_hash)?;
                let j = &mut r.journal;
                let i = &mut r.inbox;
                if let Some(s) = j.stage.as_ref() {
                    if s.phase != "ready" || s.ready_hash.as_ref() != Some(&manifest_hash) {
                        return Err("wrong/not-ready manifest".into());
                    }
                    let out = self.kernel.result(&unhex(&s.cursor_hex)?)?;
                    let m = manifest(&s.seal, &out)?;
                    if m.manifest_hash != manifest_hash {
                        return Err("output changed after ready".into());
                    }
                    let res = i.reservation.as_ref().ok_or("unmatched acknowledgement")?;
                    if res.seal_hash != hash(&s.seal.bytes()?) {
                        return Err("unmatched acknowledgement".into());
                    }
                    let cutoff = number(&s.seal.source_to_exclusive)?;
                    j.head = Head {
                        segment_id: Some(s.seal.segment_id.clone()),
                        logical_end: s.seal.logical_end.clone(),
                        source_to_exclusive: s.seal.source_to_exclusive.clone(),
                        seal: Some(s.seal.clone()),
                        state_hex: hex(&out.state),
                        state_hash: m.state_hash,
                        manifest_hash: m.manifest_hash.clone(),
                        event_hex: hex(&out.events),
                        score_hex: hex(&out.scores),
                    };
                    j.stage = None;
                    inc(&mut j.revision)?;
                    i.pending = selected_after(&i.pending, cutoff)?;
                    i.retired_to = nat(cutoff);
                    i.last_ack = Some(m.manifest_hash);
                    i.reservation = None;
                    inc(&mut i.revision)?;
                } else if j.head.manifest_hash == manifest_hash
                    && j.head.seal.is_some()
                    && i.reservation.is_none()
                    && i.last_ack.as_ref() == Some(&manifest_hash)
                {
                    unchanged = true;
                } else {
                    return Err("nothing ready to publish".into());
                }
            }
        }
        if !unchanged {
            inc(&mut r.revision)?;
        }
        self.validate_record(&r)?;
        Ok(Proposal {
            expected,
            record: r,
            progress,
            unchanged,
        })
    }
    /// Only internal proposals from this trusted host are accepted, never network-supplied ones.
    pub fn commit(&mut self, p: Proposal) -> Result<Option<Progress>> {
        if self.record.revision != p.expected {
            return Err("stale coordinator revision".into());
        }
        if !p.unchanged {
            self.record = p.record;
        }
        Ok(p.progress)
    }
    pub fn apply(&mut self, a: Action) -> Result<Option<Progress>> {
        let p = self.propose(a)?;
        self.commit(p)
    }
}
fn selected_after(inputs: &[Input], cutoff: u64) -> Result<Vec<Input>> {
    let mut out = Vec::new();
    for i in inputs {
        if number(&i.position)? >= cutoff {
            out.push(i.clone());
        }
    }
    Ok(out)
}

pub mod observation;
