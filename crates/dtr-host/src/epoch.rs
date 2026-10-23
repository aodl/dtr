//! Generic authenticated, zero-time epoch checkpoints. No application migration logic.
use crate::observation::{Publication, CHUNK, MAX_ARTIFACT};
use crate::{digest, manifest_root, number, Head, Identity, Output};
use dtr_wire::{decode, encode, hash, hex, unhex, Int, Result};
use serde::{Deserialize, Serialize};

pub const MAX_PREDECESSOR: usize = 16 * 1024;

/// Bounded exact predecessor summary used after the original v6→v7 crossing.
/// The publication hash permits direct retained-history verification without
/// recursively embedding the predecessor's own epoch proof.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EpochPredecessor {
    pub publication_hash: String,
    pub version: u32,
    pub identity: Identity,
    pub segment_id: Int,
    pub logical_end: Int,
    pub source_cursor: Int,
    pub manifest_hash: String,
    pub state_hash: String,
    pub epoch_hash: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Epoch {
    pub version: u32,
    pub previous_publication_hex: String,
    pub new_identity: Identity,
    pub segment_id: Int,
    pub logical_boundary: Int,
    pub source_cursor: Int,
    pub source_anchor: String,
    pub state_hash: String,
    pub event_hash: String,
    pub score_hash: String,
    pub metadata_hash: String,
    pub transition_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transition_index: Option<Int>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_chain_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub predecessor: Option<EpochPredecessor>,
}

impl Epoch {
    pub fn commitment(&self) -> Result<String> {
        let mut value = serde_json::to_value(self).map_err(|e| e.to_string())?;
        value
            .as_object_mut()
            .ok_or("epoch object")?
            .remove("transition_hash");
        let mut bytes = match self.version {
            1 => b"DTREPOCH1".to_vec(),
            2 => b"DTREPOCH2".to_vec(),
            _ => return Err("epoch version".into()),
        };
        bytes.extend(encode(&value)?);
        Ok(hash(&bytes))
    }

    pub fn index(&self) -> Result<u64> {
        match self.version {
            1 if self.transition_index.is_none()
                && self.previous_chain_hash.is_none()
                && self.predecessor.is_none() =>
            {
                Ok(1)
            }
            2 => {
                let n = number(
                    self.transition_index
                        .as_ref()
                        .ok_or("epoch transition index")?,
                )?;
                if n < 2 {
                    return Err("epoch transition index".into());
                }
                Ok(n)
            }
            _ => Err("epoch version".into()),
        }
    }

    /// Constant-size authenticator for the ordered chain of epoch transitions.
    pub fn chain_hash(&self) -> Result<String> {
        self.validate()?;
        let mut bytes = b"DTREPOCHCHAIN1".to_vec();
        if let Some(previous) = &self.previous_chain_hash {
            bytes.extend(digest(previous)?);
        }
        bytes.extend(digest(&self.transition_hash)?);
        Ok(hash(&bytes))
    }

    fn validate_common(&self) -> Result<()> {
        if self.commitment()? != self.transition_hash {
            return Err("epoch commitment".into());
        }
        for d in [
            &self.source_anchor,
            &self.state_hash,
            &self.event_hash,
            &self.score_hash,
            &self.metadata_hash,
            &self.transition_hash,
            &self.new_identity.source_id,
            &self.new_identity.rules_hash,
            &self.new_identity.config_hash,
            &self.new_identity.schema_hash,
        ] {
            digest(d)?;
        }
        number(&self.segment_id)?;
        number(&self.logical_boundary)?;
        number(&self.source_cursor)?;
        Ok(())
    }

    /// The original v1 proof and its canonical bytes remain unchanged.
    fn validate_v1(&self) -> Result<Publication> {
        if self.index()? != 1 {
            return Err("epoch v1 extension fields".into());
        }
        let bytes = unhex(&self.previous_publication_hex)?;
        if bytes.len() > MAX_PREDECESSOR {
            return Err("epoch predecessor capacity".into());
        }
        let p: Publication = decode(&bytes)?;
        if encode(&p)? != bytes {
            return Err("epoch predecessor schema".into());
        }
        if p.version != 6
            || p.epoch.is_some()
            || p.render_format.is_some()
            || p.chunk_bytes != CHUNK
            || p.artifacts.len() != 3
        {
            return Err("epoch requires committed v6 predecessor".into());
        }
        validate_catalog(&p)?;
        let h = &p.head;
        let s = h
            .seal
            .as_ref()
            .ok_or("epoch predecessor must be committed")?;
        if s.epoch_hash.is_some()
            || !s.matches(&p.identity)
            || h.segment_id.as_ref() != Some(&s.segment_id)
            || h.logical_end != s.logical_end
            || h.source_to_exclusive != s.source_to_exclusive
            || h.state_hash != p.artifacts[0].sha256
            || manifest_root(
                s,
                [
                    &p.artifacts[0].sha256,
                    &p.artifacts[1].sha256,
                    &p.artifacts[2].sha256,
                ],
            )? != h.manifest_hash
        {
            return Err("epoch predecessor manifest".into());
        }
        if self.new_identity == p.identity
            || self.new_identity.source_id != p.identity.source_id
            || number(&self.segment_id)?
                != number(&s.segment_id)?
                    .checked_add(1)
                    .ok_or("epoch segment overflow")?
            || self.logical_boundary != h.logical_end
            || self.source_cursor != h.source_to_exclusive
            || self.source_anchor != s.source_anchor
        {
            return Err("epoch predecessor boundary/identity".into());
        }
        Ok(p)
    }

    fn validate_v2(&self) -> Result<()> {
        if !self.previous_publication_hex.is_empty() {
            return Err("epoch v2 recursively embeds predecessor".into());
        }
        let predecessor = self
            .predecessor
            .as_ref()
            .ok_or("epoch predecessor summary")?;
        let previous_chain = self
            .previous_chain_hash
            .as_ref()
            .ok_or("epoch previous chain")?;
        digest(previous_chain)?;
        for d in [
            &predecessor.publication_hash,
            &predecessor.identity.source_id,
            &predecessor.identity.rules_hash,
            &predecessor.identity.config_hash,
            &predecessor.identity.schema_hash,
            &predecessor.manifest_hash,
            &predecessor.state_hash,
            &predecessor.epoch_hash,
        ] {
            digest(d)?;
        }
        if !matches!(predecessor.version, 7 | 8)
            || self.new_identity == predecessor.identity
            || self.new_identity.source_id != predecessor.identity.source_id
            || number(&self.segment_id)?
                != number(&predecessor.segment_id)?
                    .checked_add(1)
                    .ok_or("epoch segment overflow")?
            || self.logical_boundary != predecessor.logical_end
            || self.source_cursor != predecessor.source_cursor
        {
            return Err("epoch predecessor boundary/identity".into());
        }
        number(&predecessor.segment_id)?;
        number(&predecessor.logical_end)?;
        number(&predecessor.source_cursor)?;
        self.index()?;
        Ok(())
    }

    pub fn validate(&self) -> Result<()> {
        self.validate_common()?;
        match self.version {
            1 => {
                self.validate_v1()?;
            }
            2 => self.validate_v2()?,
            _ => return Err("epoch version".into()),
        }
        Ok(())
    }

    pub fn expected_predecessor(&self, bytes: &[u8]) -> Result<()> {
        self.validate()?;
        let p: Publication = decode(bytes)?;
        if encode(&p)? != bytes {
            return Err("epoch predecessor schema".into());
        }
        match self.version {
            1 => {
                if self.previous_publication_hex != hex(bytes) {
                    return Err("epoch expected predecessor".into());
                }
            }
            2 => {
                let summary = self.predecessor.as_ref().unwrap();
                validate_catalog(&p)?;
                let prior_epoch = p.epoch.as_ref().ok_or("epoch predecessor epoch")?;
                let seal = p
                    .head
                    .seal
                    .as_ref()
                    .ok_or("epoch predecessor must be committed")?;
                if hash(bytes) != summary.publication_hash
                    || p.version != summary.version
                    || p.identity != summary.identity
                    || p.head.segment_id.as_ref() != Some(&summary.segment_id)
                    || p.head.logical_end != summary.logical_end
                    || p.head.source_to_exclusive != summary.source_cursor
                    || p.head.manifest_hash != summary.manifest_hash
                    || p.head.state_hash != summary.state_hash
                    || prior_epoch.transition_hash != summary.epoch_hash
                    || prior_epoch.chain_hash()? != *self.previous_chain_hash.as_ref().unwrap()
                    || prior_epoch
                        .index()?
                        .checked_add(1)
                        .ok_or("epoch transition index overflow")?
                        != self.index()?
                    || seal.source_anchor != self.source_anchor
                {
                    return Err("epoch expected predecessor".into());
                }
            }
            _ => return Err("epoch version".into()),
        }
        Ok(())
    }

    pub fn output_matches(&self, out: &Output) -> Result<()> {
        if [&out.state, &out.events, &out.scores]
            .iter()
            .any(|b| b.len() > MAX_ARTIFACT)
            || hash(&out.state) != self.state_hash
            || hash(&out.events) != self.event_hash
            || hash(&out.scores) != self.score_hash
        {
            return Err("epoch output commitment".into());
        }
        Ok(())
    }

    pub fn validate_head(&self, h: &Head, identity: &Identity) -> Result<()> {
        self.validate()?;
        if identity != &self.new_identity
            || number(h.segment_id.as_ref().ok_or("epoch head")?)? < number(&self.segment_id)?
            || h.logical_end < self.logical_boundary
            || h.source_to_exclusive < self.source_cursor
        {
            return Err("epoch current boundary/identity".into());
        }
        if h.segment_id.as_ref() == Some(&self.segment_id) {
            if h.seal.is_some()
                || h.manifest_hash != self.transition_hash
                || h.logical_end != self.logical_boundary
                || h.source_to_exclusive != self.source_cursor
            {
                return Err("epoch checkpoint head".into());
            }
            self.output_matches(&Output {
                state: unhex(&h.state_hex)?,
                events: unhex(&h.event_hex)?,
                scores: unhex(&h.score_hex)?,
            })?;
        } else {
            let s = h.seal.as_ref().ok_or("epoch successor seal")?;
            if s.epoch_hash.as_ref() != Some(&self.transition_hash)
                || s.logical_start < self.logical_boundary
                || s.source_from < self.source_cursor
            {
                return Err("epoch successor commitment".into());
            }
            if number(&s.segment_id)? == number(&self.segment_id)? + 1
                && (s.previous_manifest != self.transition_hash
                    || s.previous_state != self.state_hash
                    || s.logical_start != self.logical_boundary
                    || s.source_from != self.source_cursor)
            {
                return Err("epoch first successor".into());
            }
        }
        Ok(())
    }

    pub(crate) fn make(
        previous: &[u8],
        identity: Identity,
        out: &Output,
        source_anchor: String,
        metadata_hash: String,
    ) -> Result<Self> {
        let p: Publication = decode(previous)?;
        let id = number(
            p.head
                .segment_id
                .as_ref()
                .ok_or("epoch requires committed predecessor")?,
        )?
        .checked_add(1)
        .ok_or("epoch segment overflow")?;
        let (version, previous_publication_hex, transition_index, previous_chain_hash, predecessor) =
            if p.version == 6 && p.epoch.is_none() {
                (1, hex(previous), None, None, None)
            } else if matches!(p.version, 7 | 8) {
                let prior = p.epoch.as_ref().ok_or("epoch predecessor epoch")?;
                (
                    2,
                    String::new(),
                    Some(Int(prior
                        .index()?
                        .checked_add(1)
                        .ok_or("epoch transition index overflow")?
                        .into())),
                    Some(prior.chain_hash()?),
                    Some(EpochPredecessor {
                        publication_hash: hash(previous),
                        version: p.version,
                        identity: p.identity.clone(),
                        segment_id: p
                            .head
                            .segment_id
                            .clone()
                            .ok_or("epoch requires committed predecessor")?,
                        logical_end: p.head.logical_end.clone(),
                        source_cursor: p.head.source_to_exclusive.clone(),
                        manifest_hash: p.head.manifest_hash.clone(),
                        state_hash: p.head.state_hash.clone(),
                        epoch_hash: prior.transition_hash.clone(),
                    }),
                )
            } else {
                return Err("epoch predecessor publication version".into());
            };
        let mut e = Self {
            version,
            previous_publication_hex,
            new_identity: identity,
            segment_id: Int(id.into()),
            logical_boundary: p.head.logical_end,
            source_cursor: p.head.source_to_exclusive,
            source_anchor,
            state_hash: hash(&out.state),
            event_hash: hash(&out.events),
            score_hash: hash(&out.scores),
            metadata_hash,
            transition_hash: String::new(),
            transition_index,
            previous_chain_hash,
            predecessor,
        };
        e.transition_hash = e.commitment()?;
        e.validate()?;
        e.expected_predecessor(previous)?;
        e.output_matches(out)?;
        Ok(e)
    }
}

fn validate_catalog(p: &Publication) -> Result<()> {
    if p.render_format.is_some() || p.chunk_bytes != CHUNK || p.artifacts.len() != 3 {
        return Err("epoch predecessor catalog".into());
    }
    for (kind, a) in ["state", "events", "scores"].iter().zip(&p.artifacts) {
        digest(&a.sha256)?;
        if a.kind != *kind || a.length > MAX_ARTIFACT || a.chunks.len() != a.length.div_ceil(CHUNK)
        {
            return Err("epoch predecessor catalog".into());
        }
        for c in &a.chunks {
            digest(c)?;
        }
    }
    Ok(())
}
