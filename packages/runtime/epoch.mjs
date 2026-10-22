/** Trusted coordinator epoch preparation/validation; no application migration. */
import {decodeCanonical} from './canonical.mjs';
import {epochStructure,epochPayload,checkEpochHead} from '../protocol/epoch-codec.mjs';
import {ascii,concat,hex,unhex} from '../protocol/bytes.mjs';
import {encodeSeal,sha256} from './seal.mjs';
export function validateEpoch(e){
 const {previous:p}=epochStructure(e);
 const old=sha256(concat(ascii('DTRMANI1'),unhex(sha256(encodeSeal(p.head.seal)),32),...p.artifacts.map(a=>unhex(a.sha256,32))));
 if(old!==p.head.manifest_hash||sha256(epochPayload(e))!==e.transition_hash)throw new Error('epoch commitment/previous manifest');
 return p;
}
export function epochOutput(e,out){
 if(['state','events','scores'].some(k=>!(out[k] instanceof Uint8Array)||out[k].length>1048576)
   ||sha256(out.state)!==e.state_hash||sha256(out.events)!==e.event_hash||sha256(out.scores)!==e.score_hash)throw new Error('epoch output commitment');
}
export function makeEpoch(previousBytes,identity,out,sourceAnchor,metadataHash){
 const p=decodeCanonical(previousBytes);
 if(p.head.segment_id===null)throw new Error('epoch requires committed predecessor');
 const e={version:1,previous_publication_hex:hex(previousBytes),new_identity:structuredClone(identity),segment_id:p.head.segment_id+1n,
  logical_boundary:p.head.logical_end,source_cursor:p.head.source_to_exclusive,source_anchor:sourceAnchor,
  state_hash:sha256(out.state),event_hash:sha256(out.events),score_hash:sha256(out.scores),metadata_hash:metadataHash,transition_hash:''};
 e.transition_hash=sha256(epochPayload(e));validateEpoch(e);epochOutput(e,out);return e;
}
export function validateEpochHead(e,h,identity){validateEpoch(e);checkEpochHead(e,h,identity,[sha256(unhex(h.state_hex)),sha256(unhex(h.event_hex)),sha256(unhex(h.score_hex))]);}
