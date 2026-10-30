/** Trusted coordinator epoch preparation/validation; no application migration. */
import {decodeCanonical} from './canonical.mjs';
import {epochStructure,epochPayload,epochChainPayload,checkEpochHead,validateEpochPredecessorShape} from '../protocol/epoch-codec.mjs';
import {ascii,concat,hex,unhex} from '../protocol/bytes.mjs';
import {encodeSeal,sha256} from './seal.mjs';
const identityKeys=['source_id','rules_hash','config_hash','schema_hash'];
const sameIdentity=(a,b)=>identityKeys.every(k=>a[k]===b[k]);
function manifest(p){
 if(!p.head.seal){checkEpochHead(p.epoch,p.head,p.identity,p.artifacts.map(a=>a.sha256));return;}
 const old=sha256(concat(ascii('DTRMANI1'),unhex(sha256(encodeSeal(p.head.seal)),32),...p.artifacts.map(a=>unhex(a.sha256,32))));
 if(old!==p.head.manifest_hash)throw new Error('epoch previous manifest');
}
export function validateEpoch(e){
 const shape=epochStructure(e);
 if(sha256(epochPayload(e))!==e.transition_hash)throw new Error('epoch commitment');
 if(e.version===1)manifest(shape.previous);
 return shape;
}
export function epochChainHash(e){validateEpoch(e);return sha256(epochChainPayload(e));}
export function validateEpochPredecessor(e,previousBytes){
 const shape=validateEpoch(e),p=decodeCanonical(previousBytes);
 if(e.version===1){
  if(hex(previousBytes)!==e.previous_publication_hex)throw new Error('epoch expected predecessor');
  return p;
 }
 validateEpochPredecessorShape(p,e.version===3||p.version===9);manifest(p);validateEpoch(p.epoch);
 const q=shape.predecessor,h=p.head,s=h.seal;
 if(sha256(previousBytes)!==q.publication_hash||p.version!==q.version||!sameIdentity(p.identity,q.identity)
   ||h.segment_id!==q.segment_id||h.logical_end!==q.logical_end||h.source_to_exclusive!==q.source_cursor
   ||h.manifest_hash!==q.manifest_hash||h.state_hash!==q.state_hash||p.epoch.transition_hash!==q.epoch_hash
   ||epochChainHash(p.epoch)!==e.previous_chain_hash||(p.epoch.transition_index??1n)+1n!==e.transition_index
   ||(e.version===3?q.source_anchor!==(s?.source_anchor??p.epoch.source_anchor):(s?.source_anchor??p.epoch.source_anchor)!==e.source_anchor))throw new Error('epoch expected predecessor');
 return p;
}
export function epochOutput(e,out){
 if(['state','events','scores'].some(k=>!(out[k] instanceof Uint8Array)||out[k].length>1048576)
   ||sha256(out.state)!==e.state_hash||sha256(out.events)!==e.event_hash||sha256(out.scores)!==e.score_hash)throw new Error('epoch output commitment');
}
export function makeEpoch(previousBytes,identity,out,sourceAnchor,metadataHash){return makeEpochKind(previousBytes,identity,out,sourceAnchor,metadataHash,false);}
/** Explicit same-identity application context checkpoint, without logical advance; it can acknowledge only an already verified empty source prefix. */
export function makeCheckpoint(previousBytes,out,sourceAnchor,metadataHash,sourceCursor){return makeEpochKind(previousBytes,decodeCanonical(previousBytes).identity,out,sourceAnchor,metadataHash,true,sourceCursor);}
function makeEpochKind(previousBytes,identity,out,sourceAnchor,metadataHash,checkpoint,sourceCursor){
 const p=decodeCanonical(previousBytes);
 if(p.head.segment_id===null)throw new Error('epoch requires committed predecessor');
 let extension={};
 if(p.version===6&&!p.epoch){
  if(checkpoint)throw new Error('checkpoint requires an authenticated epoch');
  extension={version:1,previous_publication_hex:hex(previousBytes)};
 }else if([7,8,9].includes(p.version)&&p.epoch){
  validateEpoch(p.epoch);
  extension={version:checkpoint?3:2,previous_publication_hex:'',transition_index:(p.epoch.transition_index??1n)+1n,
   previous_chain_hash:epochChainHash(p.epoch),predecessor:{publication_hash:sha256(previousBytes),version:p.version,
    identity:structuredClone(p.identity),segment_id:p.head.segment_id,logical_end:p.head.logical_end,
    source_cursor:p.head.source_to_exclusive,manifest_hash:p.head.manifest_hash,state_hash:p.head.state_hash,
    epoch_hash:p.epoch.transition_hash,...(checkpoint?{source_anchor:p.head.seal?.source_anchor??p.epoch.source_anchor}:{})}};
 }else throw new Error('epoch predecessor publication version');
 const e={...extension,new_identity:structuredClone(identity),segment_id:p.head.segment_id+1n,
  logical_boundary:p.head.logical_end,source_cursor:checkpoint&&sourceCursor!==undefined?sourceCursor:p.head.source_to_exclusive,source_anchor:sourceAnchor,
  state_hash:sha256(out.state),event_hash:sha256(out.events),score_hash:sha256(out.scores),metadata_hash:metadataHash,transition_hash:''};
 e.transition_hash=sha256(epochPayload(e));validateEpoch(e);validateEpochPredecessor(e,previousBytes);epochOutput(e,out);return e;
}
export function validateEpochHead(e,h,identity){validateEpoch(e);checkEpochHead(e,h,identity,[sha256(unhex(h.state_hex)),sha256(unhex(h.event_hex)),sha256(unhex(h.score_hex))]);}
