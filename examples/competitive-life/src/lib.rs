//! Tiny competitive Life workload. Finite dead boundaries, majority birth color, minimum owner on a three-way tie.
//! No payments, prices, IC API, ambient clock or hidden randomness.
#![forbid(unsafe_code)]
use dtr_core::{CoreError, Progress, Reader, ResumableKernel};
use std::collections::BTreeMap;
pub const MAX_CELLS: usize = 1024;
pub const MAX_GENERATIONS: u8 = 32;
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LifeError {
    Bounds,
    Overflow,
    Incomplete,
    Codec,
    Core(CoreError),
}
impl From<CoreError> for LifeError {
    fn from(e: CoreError) -> Self {
        Self::Core(e)
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Board {
    pub width: u16,
    pub height: u16,
    pub generation: u64,
    pub cells: Vec<u16>,
}
impl Board {
    pub fn new(
        width: u16,
        height: u16,
        generation: u64,
        cells: Vec<u16>,
    ) -> Result<Self, LifeError> {
        let size = usize::from(width) * usize::from(height);
        if width == 0
            || height == 0
            || width > 64
            || height > 64
            || size > MAX_CELLS
            || size != cells.len()
        {
            return Err(LifeError::Bounds);
        }
        Ok(Self {
            width,
            height,
            generation,
            cells,
        })
    }
    pub fn encode(&self) -> Vec<u8> {
        let mut out = b"LIFE0001".to_vec();
        out.extend(self.width.to_be_bytes());
        out.extend(self.height.to_be_bytes());
        out.extend(self.generation.to_be_bytes());
        for c in &self.cells {
            out.extend(c.to_be_bytes());
        }
        out
    }
    pub fn decode(data: &[u8]) -> Result<Self, LifeError> {
        let mut r = Reader::new(data);
        if r.take(8)? != b"LIFE0001" {
            return Err(LifeError::Codec);
        }
        let w = r.u16()?;
        let h = r.u16()?;
        let g = r.u64()?;
        let size = usize::from(w) * usize::from(h);
        if size > MAX_CELLS {
            return Err(LifeError::Bounds);
        }
        let mut cells = Vec::with_capacity(size);
        for _ in 0..size {
            cells.push(r.u16()?);
        }
        r.end()?;
        Self::new(w, h, g, cells)
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event {
    pub generation: u64,
    pub cell: u32,
    pub before: u16,
    pub after: u16,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cursor {
    pub state: Board,
    start: u64,
    total: u8,
    remaining: u8,
    cell: usize,
    next: Vec<u16>,
    pub events: Vec<Event>,
    pub scores: BTreeMap<u16, u64>,
}
fn evolve(b: &Board, index: usize) -> u16 {
    let x = (index % usize::from(b.width)) as i32;
    let y = (index / usize::from(b.width)) as i32;
    let mut owners = Vec::with_capacity(8);
    for dy in -1..=1 {
        for dx in -1..=1 {
            if dx == 0 && dy == 0 {
                continue;
            }
            let (xx, yy) = (x + dx, y + dy);
            if xx >= 0 && yy >= 0 && xx < i32::from(b.width) && yy < i32::from(b.height) {
                let owner = b.cells[yy as usize * usize::from(b.width) + xx as usize];
                if owner != 0 {
                    owners.push(owner);
                }
            }
        }
    }
    let old = b.cells[index];
    if old != 0 {
        return if owners.len() == 2 || owners.len() == 3 {
            old
        } else {
            0
        };
    }
    if owners.len() != 3 {
        return 0;
    }
    owners.sort_unstable();
    if owners[0] == owners[1] {
        owners[0]
    } else if owners[1] == owners[2] {
        owners[1]
    } else {
        owners[0]
    }
}
impl Cursor {
    pub fn new(state: Board, generations: u8) -> Result<Self, LifeError> {
        Board::new(
            state.width,
            state.height,
            state.generation,
            state.cells.clone(),
        )?;
        if generations == 0 || generations > MAX_GENERATIONS {
            return Err(LifeError::Bounds);
        }
        state
            .generation
            .checked_add(u64::from(generations))
            .ok_or(LifeError::Overflow)?;
        Ok(Self {
            start: state.generation,
            next: vec![0; state.cells.len()],
            state,
            total: generations,
            remaining: generations,
            cell: 0,
            events: vec![],
            scores: BTreeMap::new(),
        })
    }
    pub fn complete(&self) -> bool {
        self.remaining == 0
    }
    pub fn event_bytes(&self) -> Vec<u8> {
        let mut out = b"LIFEEVT1".to_vec();
        out.extend((self.events.len() as u32).to_be_bytes());
        for e in &self.events {
            out.extend(e.generation.to_be_bytes());
            out.extend(e.cell.to_be_bytes());
            out.extend(e.before.to_be_bytes());
            out.extend(e.after.to_be_bytes());
        }
        out
    }
    pub fn score_bytes(&self) -> Vec<u8> {
        let mut out = b"LIFESCR1".to_vec();
        out.extend((self.scores.len() as u32).to_be_bytes());
        for (owner, units) in &self.scores {
            out.extend(owner.to_be_bytes());
            out.extend(units.to_be_bytes());
        }
        out
    }
    pub fn snapshot(&self) -> Vec<u8> {
        let b = self.state.encode();
        let e = self.event_bytes();
        let s = self.score_bytes();
        let mut out = b"LIFECUR1".to_vec();
        out.extend((b.len() as u32).to_be_bytes());
        out.extend(b);
        out.push(self.total);
        out.push(self.remaining);
        out.extend(self.start.to_be_bytes());
        out.extend((self.cell as u32).to_be_bytes());
        for c in &self.next {
            out.extend(c.to_be_bytes());
        }
        out.extend((e.len() as u32).to_be_bytes());
        out.extend(e);
        out.extend((s.len() as u32).to_be_bytes());
        out.extend(s);
        out
    }
    /// The host MUST authenticate the snapshot digest before decoding external bytes.
    pub fn restore(data: &[u8]) -> Result<Self, LifeError> {
        if data.len() > 2 * 1024 * 1024 {
            return Err(LifeError::Bounds);
        }
        let mut r = Reader::new(data);
        if r.take(8)? != b"LIFECUR1" {
            return Err(LifeError::Codec);
        }
        let n = r.u32()? as usize;
        let state = Board::decode(r.take(n)?)?;
        let total = r.take(1)?[0];
        let remaining = r.take(1)?[0];
        let start = r.u64()?;
        let cell = r.u32()? as usize;
        if total == 0
            || total > MAX_GENERATIONS
            || remaining > total
            || cell >= state.cells.len()
            || (remaining == 0 && cell != 0)
            || start.checked_add(u64::from(total - remaining)) != Some(state.generation)
        {
            return Err(LifeError::Bounds);
        }
        start
            .checked_add(u64::from(total))
            .ok_or(LifeError::Overflow)?;
        let mut next = Vec::with_capacity(state.cells.len());
        for _ in 0..state.cells.len() {
            next.push(r.u16()?);
        }
        if next[cell..].iter().any(|x| *x != 0) {
            return Err(LifeError::Codec);
        }
        let len = r.u32()? as usize;
        let mut er = Reader::new(r.take(len)?);
        if er.take(8)? != b"LIFEEVT1" {
            return Err(LifeError::Codec);
        }
        let count = er.u32()? as usize;
        if count > MAX_CELLS * usize::from(MAX_GENERATIONS) {
            return Err(LifeError::Bounds);
        }
        let mut events: Vec<Event> = Vec::with_capacity(count);
        for _ in 0..count {
            let e = Event {
                generation: er.u64()?,
                cell: er.u32()?,
                before: er.u16()?,
                after: er.u16()?,
            };
            let upper = state
                .generation
                .checked_add(if cell > 0 { 1 } else { 0 })
                .ok_or(LifeError::Overflow)?;
            if e.cell as usize >= state.cells.len()
                || e.before == e.after
                || e.generation <= start
                || e.generation > upper
                || (e.generation > state.generation && e.cell as usize >= cell)
            {
                return Err(LifeError::Codec);
            }
            if let Some(p) = events.last() {
                if (e.generation, e.cell) <= (p.generation, p.cell) {
                    return Err(LifeError::Codec);
                }
            }
            events.push(e);
        }
        er.end()?;
        let len = r.u32()? as usize;
        let mut sr = Reader::new(r.take(len)?);
        if sr.take(8)? != b"LIFESCR1" {
            return Err(LifeError::Codec);
        }
        let n = sr.u32()? as usize;
        if n > MAX_CELLS {
            return Err(LifeError::Bounds);
        }
        let mut scores = BTreeMap::new();
        let mut last = 0;
        let mut sum = 0u64;
        for _ in 0..n {
            let owner = sr.u16()?;
            let units = sr.u64()?;
            if owner <= last || units == 0 {
                return Err(LifeError::Codec);
            }
            sum = sum.checked_add(units).ok_or(LifeError::Overflow)?;
            scores.insert(owner, units);
            last = owner;
        }
        sr.end()?;
        r.end()?;
        let work = usize::from(total - remaining) * state.cells.len() + cell;
        if sum > work as u64 || events.len() > work {
            return Err(LifeError::Codec);
        }
        Ok(Self {
            state,
            start,
            total,
            remaining,
            cell,
            next,
            events,
            scores,
        })
    }
}
impl ResumableKernel for Cursor {
    type Error = LifeError;
    fn step(&mut self, work_units: u32) -> Result<Progress, Self::Error> {
        for _ in 0..work_units {
            if self.complete() {
                break;
            }
            let i = self.cell;
            let before = self.state.cells[i];
            let after = evolve(&self.state, i);
            if before != 0 {
                *self.scores.entry(before).or_insert(0) += 1;
            }
            self.next[i] = after;
            if before != after {
                self.events.push(Event {
                    generation: self.state.generation + 1,
                    cell: i as u32,
                    before,
                    after,
                });
            }
            self.cell += 1;
            if self.cell == self.state.cells.len() {
                self.state.cells =
                    std::mem::replace(&mut self.next, vec![0; self.state.cells.len()]);
                self.state.generation += 1;
                self.cell = 0;
                self.remaining -= 1;
            }
        }
        Ok(if self.complete() {
            Progress::Complete
        } else {
            Progress::Pending
        })
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }
    #[test]
    fn reference_vectors_under_different_budgets() {
        for line in include_str!("../../../tests/fixtures/life.tsv")
            .lines()
            .filter(|l| !l.starts_with('#') && !l.is_empty())
        {
            let p: Vec<_> = line.split('\t').collect();
            let b = Board::new(
                p[1].parse().unwrap(),
                p[2].parse().unwrap(),
                p[3].parse().unwrap(),
                p[5].split(',').map(|n| n.parse().unwrap()).collect(),
            )
            .unwrap();
            for budget in [1, 7, 1_000_000] {
                let mut c = Cursor::new(b.clone(), p[4].parse().unwrap()).unwrap();
                while !c.complete() {
                    c.step(budget).unwrap();
                    let snap = c.snapshot();
                    c = Cursor::restore(&snap).unwrap();
                    assert_eq!(c.snapshot(), snap);
                }
                assert_eq!(hex(&c.state.encode()), p[6]);
                assert_eq!(hex(&c.event_bytes()), p[7]);
                assert_eq!(hex(&c.score_bytes()), p[8]);
            }
        }
    }
    #[test]
    fn zero_work_does_not_advance() {
        let mut c = Cursor::new(Board::new(2, 2, 0, vec![1; 4]).unwrap(), 2).unwrap();
        let before = c.snapshot();
        assert_eq!(c.step(0), Ok(Progress::Pending));
        assert_eq!(before, c.snapshot());
    }
    #[test]
    fn board_codec_is_strict() {
        let b = Board::new(2, 2, 4, vec![0, 1, 2, 3]).unwrap();
        assert_eq!(Board::decode(&b.encode()).unwrap(), b);
        let mut bad = b.encode();
        bad.push(0);
        assert!(Board::decode(&bad).is_err());
    }
    #[test]
    fn generation_overflow_rejected() {
        assert!(Cursor::new(Board::new(1, 1, u64::MAX, vec![1]).unwrap(), 1).is_err());
    }
    #[test]
    fn snapshot_truncation_rejected() {
        let c = Cursor::new(Board::new(1, 1, 0, vec![1]).unwrap(), 1).unwrap();
        let s = c.snapshot();
        for n in 0..s.len() {
            assert!(Cursor::restore(&s[..n]).is_err());
        }
    }
}
