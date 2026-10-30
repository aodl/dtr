/** Bounded epoch wire shapes. Browser safe: hashing is supplied by verifiers. */
import {encodeCanonical,decodeCanonical} from '../runtime/canonical.mjs';
import {ascii,concat,unhex,uint} from './bytes.mjs';
import {encodeSeal} from './seal-codec.mjs';
const V1_FIELDS=['version','previous_publication_hex','new_identity','segment_id','logical_boundary','source_cursor','source_anchor','state_hash','event_hash','score_hash','metadata_hash','transition_hash'];
const V2_FIELDS=[...V1_FIELDS,'transition_index','previous_chain_hash','predecessor'];
const IDENTITY_FIELDS=['source_id','rules_hash','config_hash','schema_hash'];
const PREDECESSOR_FIELDS=['publication_hash','version','identity','segment_id','logical_end','source_cursor','manifest_hash','state_hash','epoch_hash'];
export const MAX_EPOCH_PREDECESSOR=16384;
export function exactKeys(v,keys){if(!v||Object.keys(v).sort().join(',')!==keys.slice().sort().join(','))throw new Error('epoch schema');}
function identity(v){exactKeys(v,IDENTITY_FIELDS);Object.values(v).forEach(d=>unhex(d,32));}
function sameIdentity(a,b){return IDENTITY_FIELDS.every(k=>a[k]===b[k]);}
function catalog(p,allowCheckpoint=false){
 exactKeys(p,['version','identity','head','chunk_bytes','artifacts','render_format',...(p.version>=7?['epoch']:[])]);
 if(p.render_format!==null||p.chunk_bytes!==16384)throw new Error('epoch predecessor catalog');
 identity(p.identity);exactKeys(p.head,['segment_id','logical_end','source_to_exclusive','manifest_hash','state_hash','seal']);
 const h=p.head,s=h.seal;
 if(s){
  exactKeys(s,['segment_id','logical_start','logical_end','source_from','source_to_exclusive','input_count','source_id','source_anchor','rules_hash','config_hash','schema_hash','previous_state','previous_manifest','input_root',...(p.version>=7?['epoch_hash']:[])]);
  encodeSeal(s);
  for(const k of ['segment_id','logical_start','logical_end','source_from','source_to_exclusive'])if(typeof s[k]!=='bigint')throw new Error('epoch predecessor integer tags');
  if(!Number.isSafeInteger(s.input_count)||h.segment_id!==s.segment_id||h.logical_end!==s.logical_end||h.source_to_exclusive!==s.source_to_exclusive||IDENTITY_FIELDS.some(k=>p.identity[k]!==s[k]))throw new Error('epoch predecessor head/identity');
 }else if(!allowCheckpoint||!p.epoch||p.version<7)throw new Error('epoch predecessor must be committed');
 unhex(h.manifest_hash,32);unhex(h.state_hash,32);
 if(!Array.isArray(p.artifacts)||p.artifacts.length!==3)throw new Error('epoch predecessor catalog');
 for(const [i,a] of p.artifacts.entries()){
  exactKeys(a,['kind','length','sha256','chunks']);unhex(a.sha256,32);
  if(a.kind!==['state','events','scores'][i]||!Number.isSafeInteger(a.length)||a.length<0||a.length>1048576||!Array.isArray(a.chunks)||a.chunks.length!==Math.ceil(a.length/16384))throw new Error('epoch predecessor catalog');
  a.chunks.forEach(c=>unhex(c,32));
 }
 if(h.state_hash!==p.artifacts[0].sha256)throw new Error('epoch predecessor state');
 if(p.epoch){
  if(p.epoch.version!==({7:1,8:2,9:3})[p.version])throw new Error('epoch predecessor version');
  checkEpochHead(p.epoch,h,p.identity,p.artifacts.map(a=>a.sha256));
 }
 return {h,s};
}
export function epochStructure(e){
 exactKeys(e,e?.version>=2?V2_FIELDS:V1_FIELDS);
 if(![1,2,3].includes(e.version))throw new Error('epoch version');
 identity(e.new_identity);
 for(const d of [e.source_anchor,e.state_hash,e.event_hash,e.score_hash,e.metadata_hash,e.transition_hash])unhex(d,32);
 for(const n of [e.segment_id,e.logical_boundary,e.source_cursor])if(typeof n!=='bigint')throw new Error('epoch integer tags');else uint(n);
 if(e.version===1){
  const bytes=unhex(e.previous_publication_hex);if(bytes.length>MAX_EPOCH_PREDECESSOR)throw new Error('epoch predecessor capacity');
  const p=decodeCanonical(bytes);
  if(p.version!==6)throw new Error('epoch requires committed v6 predecessor');
  const {h,s}=catalog(p);
  if(Object.hasOwn(s,'epoch_hash')||sameIdentity(p.identity,e.new_identity)||e.new_identity.source_id!==p.identity.source_id
    ||e.segment_id!==uint(s.segment_id+1n)||e.logical_boundary!==h.logical_end||e.source_cursor!==h.source_to_exclusive||e.source_anchor!==s.source_anchor)throw new Error('epoch predecessor boundary/identity');
  return {previous:p,predecessor:null,bytes};
 }
 if(e.previous_publication_hex!=='')throw new Error('epoch v2 recursively embeds predecessor');
 if(typeof e.transition_index!=='bigint'||uint(e.transition_index)<2n)throw new Error('epoch transition index');
 unhex(e.previous_chain_hash,32);const p=e.predecessor;exactKeys(p,e.version===3?[...PREDECESSOR_FIELDS,'source_anchor']:PREDECESSOR_FIELDS);identity(p.identity);
 for(const d of [p.publication_hash,p.manifest_hash,p.state_hash,p.epoch_hash])unhex(d,32);
 for(const n of [p.segment_id,p.logical_end,p.source_cursor])if(typeof n!=='bigint')throw new Error('epoch predecessor integer tags');else uint(n);
 if(![7,8,9].includes(p.version)||(sameIdentity(p.identity,e.new_identity)!==(e.version===3))||e.new_identity.source_id!==p.identity.source_id
   ||e.segment_id!==uint(p.segment_id+1n)||e.logical_boundary!==p.logical_end||(e.version===3?e.source_cursor<p.source_cursor:e.source_cursor!==p.source_cursor))throw new Error('epoch predecessor boundary/identity');
 if(e.version===3){unhex(p.source_anchor,32);if(e.source_cursor===p.source_cursor&&e.source_anchor!==p.source_anchor)throw new Error('checkpoint empty source anchor');}
 return {previous:null,predecessor:p,bytes:null};
}
export function epochPayload(e){const body={...e};delete body.transition_hash;return concat(ascii(e.version===1?'DTREPOCH1':e.version===2?'DTREPOCH2':e.version===3?'DTREPOCH3':(()=>{throw new Error('epoch version');})()),encodeCanonical(body));}
export function epochChainPayload(e){epochStructure(e);return concat(ascii('DTREPOCHCHAIN1'),...(e.version>=2?[unhex(e.previous_chain_hash,32)]:[]),unhex(e.transition_hash,32));}
/** Hash checks precede this shared current-head relation. No game interpretation. */
export function checkEpochHead(e,h,identityValue,hashes){
 if(!sameIdentity(identityValue,e.new_identity)||h.segment_id===null||h.segment_id<e.segment_id||h.logical_end<e.logical_boundary||h.source_to_exclusive<e.source_cursor)throw new Error('epoch current boundary/identity');
 if(h.segment_id===e.segment_id){
  if(h.seal!==null||h.manifest_hash!==e.transition_hash||h.logical_end!==e.logical_boundary||h.source_to_exclusive!==e.source_cursor
    ||hashes.some((v,i)=>v!==[e.state_hash,e.event_hash,e.score_hash][i]))throw new Error('epoch checkpoint head');
 }else{
  const s=h.seal;
  if(!s||s.epoch_hash!==e.transition_hash||s.logical_start<e.logical_boundary||s.source_from<e.source_cursor)throw new Error('epoch successor commitment');
  if(s.segment_id===e.segment_id+1n&&(s.previous_manifest!==e.transition_hash||s.previous_state!==e.state_hash||s.logical_start!==e.logical_boundary||s.source_from!==e.source_cursor))throw new Error('epoch first successor');
 }
}
export function validateEpochPredecessorShape(p,allowCheckpoint=false){return catalog(p,allowCheckpoint);}
