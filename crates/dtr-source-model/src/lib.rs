//! Pure models of host ingestion and wake-up fencing. No network calls or authenticity claims.
#![forbid(unsafe_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceError {
    WrongStart,
    Bounds,
    Overflow,
}
pub fn advance_prefix(
    cursor: u64,
    start: u64,
    count: u32,
    chain_length: u64,
    max_page: u32,
) -> Result<u64, SourceError> {
    if start != cursor {
        return Err(SourceError::WrongStart);
    }
    if max_page == 0 || max_page > 256 || count > max_page {
        return Err(SourceError::Bounds);
    }
    let end = start
        .checked_add(u64::from(count))
        .ok_or(SourceError::Overflow)?;
    if end > chain_length {
        return Err(SourceError::Bounds);
    }
    Ok(end)
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Lease {
    pub generation: u64,
    pub until: u64,
}
#[derive(Debug, Clone)]
pub struct Wakeup {
    dirty: bool,
    generation: u64,
    active: Option<Lease>,
    last_attempt: Option<u64>,
    not_before: u64,
    min_gap: u64,
    fallback: u64,
    lease: u64,
}
impl Wakeup {
    pub fn new(min_gap: u64, fallback: u64, lease: u64) -> Result<Self, SourceError> {
        if fallback == 0 || lease == 0 {
            return Err(SourceError::Bounds);
        }
        Ok(Self {
            dirty: false,
            generation: 0,
            active: None,
            last_attempt: None,
            not_before: 0,
            min_gap,
            fallback,
            lease,
        })
    }
    pub fn hint(&mut self, authorised: bool) {
        if authorised {
            self.dirty = true;
        }
    }
    pub fn acquire(&mut self, now: u64) -> Result<Option<Lease>, SourceError> {
        if self.active.is_some_and(|a| now < a.until) {
            return Ok(None);
        }
        let due = self
            .last_attempt
            .is_none_or(|t| now.saturating_sub(t) >= self.fallback);
        if now < self.not_before || (!self.dirty && !due && self.active.is_none()) {
            return Ok(None);
        }
        let generation = self
            .generation
            .checked_add(1)
            .ok_or(SourceError::Overflow)?;
        let until = now.checked_add(self.lease).ok_or(SourceError::Overflow)?;
        let next = now.checked_add(self.min_gap).ok_or(SourceError::Overflow)?;
        let token = Lease { generation, until };
        self.generation = generation;
        self.active = Some(token);
        self.last_attempt = Some(now);
        self.not_before = next;
        self.dirty = false;
        Ok(Some(token))
    }
    pub fn complete(&mut self, token: Lease, now: u64, success: bool) -> bool {
        if self.active != Some(token) || now >= token.until {
            return false;
        }
        self.active = None;
        if !success {
            self.dirty = true;
        }
        true
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn short_pages_do_not_skip_to_tip() {
        assert_eq!(advance_prefix(10, 10, 2, 100, 256), Ok(12));
    }
    #[test]
    fn gaps_and_replays_rejected() {
        assert_eq!(
            advance_prefix(10, 11, 1, 100, 256),
            Err(SourceError::WrongStart)
        );
        assert_eq!(
            advance_prefix(10, 9, 1, 100, 256),
            Err(SourceError::WrongStart)
        );
    }
    #[test]
    fn empty_page_does_not_advance() {
        assert_eq!(advance_prefix(10, 10, 0, 100, 256), Ok(10));
    }
    #[test]
    fn overflow_is_error() {
        assert_eq!(
            advance_prefix(u64::MAX, u64::MAX, 1, u64::MAX, 256),
            Err(SourceError::Overflow)
        );
    }
    #[test]
    fn stale_callback_cannot_release_new_lease() {
        let mut w = Wakeup::new(2, 60, 10).unwrap();
        let old = w.acquire(0).unwrap().unwrap();
        let new = w.acquire(10).unwrap().unwrap();
        assert!(!w.complete(old, 11, true));
        assert!(w.complete(new, 11, true));
    }
    #[test]
    fn late_hint_is_preserved() {
        let mut w = Wakeup::new(2, 60, 10).unwrap();
        let a = w.acquire(0).unwrap().unwrap();
        w.hint(true);
        assert!(w.complete(a, 1, true));
        assert!(w.acquire(2).unwrap().is_some());
    }
    #[test]
    fn no_hint_still_polls() {
        let mut w = Wakeup::new(2, 60, 10).unwrap();
        let a = w.acquire(0).unwrap().unwrap();
        w.complete(a, 1, true);
        assert!(w.acquire(59).unwrap().is_none());
        assert!(w.acquire(60).unwrap().is_some());
    }
    #[test]
    fn hints_coalesce_and_respect_gap() {
        let mut w = Wakeup::new(2, 60, 10).unwrap();
        let a = w.acquire(0).unwrap().unwrap();
        for _ in 0..1000 {
            w.hint(true);
        }
        w.complete(a, 1, true);
        assert!(w.acquire(1).unwrap().is_none());
        assert!(w.acquire(2).unwrap().is_some());
    }
}
