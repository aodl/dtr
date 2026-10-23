//! Deterministic, IC-independent interfaces and canonical segment seals.
//! Hashes are supplied by a host using a reviewed SHA-256 implementation.
#![forbid(unsafe_code)]

pub type Hash32 = [u8; 32];
pub const MAX_INPUTS: u32 = 4096;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoreError {
    InvalidInterval,
    InvalidRange,
    TooManyInputs,
    WrongSuccessor,
    IdentityChanged,
    Truncated,
    Trailing,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Progress {
    Pending,
    Complete,
}

/// Yield boundaries are operational only. Different work partitions must produce identical outputs.
pub trait ResumableKernel {
    type Error;
    fn step(&mut self, work_units: u32) -> Result<Progress, Self::Error>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Seal {
    pub segment_id: u64,
    pub logical_start: u64,
    pub logical_end: u64,
    pub source_from: u64,
    pub source_to_exclusive: u64,
    pub input_count: u32,
    pub source_id: Hash32,
    pub source_anchor: Hash32,
    pub rules_hash: Hash32,
    pub config_hash: Hash32,
    pub schema_hash: Hash32,
    pub previous_state: Hash32,
    pub previous_manifest: Hash32,
    pub input_root: Hash32,
    pub epoch_hash: Option<Hash32>,
}
impl Seal {
    pub fn validate(&self) -> Result<(), CoreError> {
        if self.logical_end <= self.logical_start {
            return Err(CoreError::InvalidInterval);
        }
        if self.source_to_exclusive < self.source_from {
            return Err(CoreError::InvalidRange);
        }
        if u64::from(self.input_count) > self.source_to_exclusive - self.source_from {
            return Err(CoreError::InvalidRange);
        }
        if self.input_count > MAX_INPUTS {
            return Err(CoreError::TooManyInputs);
        }
        Ok(())
    }
    pub fn encode(&self) -> Result<Vec<u8>, CoreError> {
        self.validate()?;
        let mut out = if self.epoch_hash.is_some() {
            b"DTRSEAL2".to_vec()
        } else {
            b"DTRSEAL1".to_vec()
        };
        for n in [
            self.segment_id,
            self.logical_start,
            self.logical_end,
            self.source_from,
            self.source_to_exclusive,
        ] {
            out.extend(n.to_be_bytes());
        }
        out.extend(self.input_count.to_be_bytes());
        for h in [
            self.source_id,
            self.source_anchor,
            self.rules_hash,
            self.config_hash,
            self.schema_hash,
            self.previous_state,
            self.previous_manifest,
            self.input_root,
        ] {
            out.extend(h);
        }
        if let Some(epoch) = self.epoch_hash {
            out.extend(epoch);
        }
        Ok(out)
    }
    /// Hash-link validation needs the committed manifest/state supplied separately by the host.
    pub fn follows(
        &self,
        prior: &Self,
        prior_manifest: Hash32,
        prior_state: Hash32,
    ) -> Result<(), CoreError> {
        self.validate()?;
        prior.validate()?;
        if prior.segment_id.checked_add(1) != Some(self.segment_id)
            || self.logical_start != prior.logical_end
            || self.source_from != prior.source_to_exclusive
            || self.previous_manifest != prior_manifest
            || self.previous_state != prior_state
        {
            return Err(CoreError::WrongSuccessor);
        }
        if self.source_id != prior.source_id || self.epoch_hash != prior.epoch_hash {
            return Err(CoreError::IdentityChanged);
        }
        Ok(())
    }
}

pub struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}
impl<'a> Reader<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, at: 0 }
    }
    pub fn take(&mut self, count: usize) -> Result<&'a [u8], CoreError> {
        let end = self.at.checked_add(count).ok_or(CoreError::Truncated)?;
        let value = self.bytes.get(self.at..end).ok_or(CoreError::Truncated)?;
        self.at = end;
        Ok(value)
    }
    pub fn u16(&mut self) -> Result<u16, CoreError> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }
    pub fn u32(&mut self) -> Result<u32, CoreError> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }
    pub fn u64(&mut self) -> Result<u64, CoreError> {
        let b = self.take(8)?;
        Ok(u64::from_be_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }
    pub fn end(self) -> Result<(), CoreError> {
        if self.at == self.bytes.len() {
            Ok(())
        } else {
            Err(CoreError::Trailing)
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn sample() -> Seal {
        Seal {
            segment_id: 0,
            logical_start: 0,
            logical_end: 10,
            source_from: 100,
            source_to_exclusive: 110,
            input_count: 2,
            source_id: [1; 32],
            source_anchor: [2; 32],
            rules_hash: [3; 32],
            config_hash: [4; 32],
            schema_hash: [5; 32],
            previous_state: [6; 32],
            previous_manifest: [7; 32],
            input_root: [8; 32],
            epoch_hash: None,
        }
    }
    #[test]
    fn fixed_encoding_length() {
        assert_eq!(sample().encode().unwrap().len(), 308);
    }
    #[test]
    fn shared_encoding_fixture() {
        let hex: String = sample()
            .encode()
            .unwrap()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(hex, include_str!("../../../tests/fixtures/seal.hex").trim());
    }
    #[test]
    fn accepts_empty_source_interval() {
        let mut s = sample();
        s.source_to_exclusive = s.source_from;
        s.input_count = 0;
        assert!(s.validate().is_ok());
    }
    #[test]
    fn rejects_count_outside_range() {
        let mut s = sample();
        s.input_count = 11;
        assert_eq!(s.validate(), Err(CoreError::InvalidRange));
    }
    #[test]
    fn rejects_time_inversion() {
        let mut s = sample();
        s.logical_end = 0;
        assert_eq!(s.validate(), Err(CoreError::InvalidInterval));
    }
    #[test]
    fn successor_checks_hash_links() {
        let p = sample();
        let mut n = p.clone();
        n.segment_id = 1;
        n.logical_start = 10;
        n.logical_end = 20;
        n.source_from = 110;
        n.source_to_exclusive = 120;
        n.previous_manifest = [9; 32];
        n.previous_state = [10; 32];
        assert!(n.follows(&p, [9; 32], [10; 32]).is_ok());
        assert_eq!(
            n.follows(&p, [0; 32], [10; 32]),
            Err(CoreError::WrongSuccessor)
        );
    }
    #[test]
    fn reader_rejects_truncation_and_trailing() {
        let mut r = Reader::new(&[0, 1]);
        assert_eq!(r.u32(), Err(CoreError::Truncated));
        assert_eq!(r.u16(), Ok(1));
        assert!(r.end().is_ok());
        assert_eq!(Reader::new(&[1]).end(), Err(CoreError::Trailing));
    }
}
