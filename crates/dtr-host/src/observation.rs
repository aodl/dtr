//! Flat catalog covered by one certified-data root. No certificate or signature generation here.
use crate::{manifest, Head, Identity, Output, Record, Seal};
use dtr_wire::{encode, hash, unhex, Int, Result};
use serde::{Deserialize, Serialize};
pub const CHUNK: usize = 16384;
pub const MAX_ARTIFACT: usize = 1024 * 1024;
pub const MAX_PUBLICATION: usize = 65536;
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Descriptor {
    pub kind: String,
    pub length: usize,
    pub sha256: String,
    pub chunks: Vec<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicHead {
    pub segment_id: Option<Int>,
    pub logical_end: Int,
    pub source_to_exclusive: Int,
    pub manifest_hash: String,
    pub state_hash: String,
    pub seal: Option<Seal>,
}
impl From<&Head> for PublicHead {
    fn from(h: &Head) -> Self {
        Self {
            segment_id: h.segment_id.clone(),
            logical_end: h.logical_end.clone(),
            source_to_exclusive: h.source_to_exclusive.clone(),
            manifest_hash: h.manifest_hash.clone(),
            state_hash: h.state_hash.clone(),
            seal: h.seal.clone(),
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Publication {
    pub version: u32,
    pub identity: Identity,
    pub render_format: Option<String>,
    pub head: PublicHead,
    pub chunk_bytes: usize,
    pub artifacts: Vec<Descriptor>,
}
pub struct Published {
    pub data: Publication,
    pub bytes: Vec<u8>,
    pub sha256: String,
    pub artifacts: Vec<Vec<u8>>,
}
pub fn describe(kind: &str, bytes: &[u8]) -> Result<Descriptor> {
    if !matches!(kind, "state" | "events" | "scores") || bytes.len() > MAX_ARTIFACT {
        return Err("observation artifact bounds".into());
    }
    Ok(Descriptor {
        kind: kind.into(),
        length: bytes.len(),
        sha256: hash(bytes),
        chunks: bytes.chunks(CHUNK).map(hash).collect(),
    })
}
pub fn publication(r: &Record) -> Result<Published> {
    if r.version != 5 {
        return Err("observation coordinator version".into());
    }
    let h = &r.journal.head;
    let artifacts = vec![
        unhex(&h.state_hex)?,
        unhex(&h.event_hex)?,
        unhex(&h.score_hex)?,
    ];
    if hash(&artifacts[0]) != h.state_hash {
        return Err("observation state root".into());
    }
    if let Some(s) = &h.seal {
        let out = Output {
            state: artifacts[0].clone(),
            events: artifacts[1].clone(),
            scores: artifacts[2].clone(),
        };
        if manifest(s, &out)?.manifest_hash != h.manifest_hash {
            return Err("observation manifest root".into());
        }
    }
    let kinds = ["state", "events", "scores"];
    let descriptions = kinds
        .iter()
        .zip(&artifacts)
        .map(|(k, b)| describe(k, b))
        .collect::<Result<Vec<_>>>()?;
    let data = Publication {
        version: 6,
        identity: r.journal.identity.clone(),
        render_format: None,
        head: PublicHead::from(h),
        chunk_bytes: CHUNK,
        artifacts: descriptions,
    };
    let bytes = encode(&data)?;
    if bytes.len() > MAX_PUBLICATION {
        return Err("observation publication capacity".into());
    }
    Ok(Published {
        sha256: hash(&bytes),
        data,
        bytes,
        artifacts,
    })
}

/// Historical v5 fixture codec only. Not used by the current IC lab or observer.
pub fn publication_v5_bytes(r: &Record) -> Result<Vec<u8>> {
    let v = publication(r)?;
    let old = serde_json::json!({"version":5,"revision":r.revision,"identity":r.journal.identity,
        "ingest_head":r.inbox.cursor,"head":v.data.head,"chunk_bytes":CHUNK,"artifacts":v.data.artifacts});
    encode(&old)
}
