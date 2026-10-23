/** Bounded epoch wire shape. Browser safe: hashing is supplied by its verifier. */
import {encodeCanonical,decodeCanonical} from '../runtime/canonical.mjs';
import {ascii,concat,unhex,uint} from './bytes.mjs';
import {encodeSeal} from './seal-codec.mjs';
const FIELDS=['version','previous_publication_hex','new_identity','segment_id','logical_boundary','source_cursor','source_anchor','state_hash','event_hash','score_hash','metadata_hash','transition_hash'];
export const MAX_EPOCH_PREDECESSOR=16384;
export function exactKeys(v,keys){if(!v||Object.keys(v).sort().join(',')!==keys.slice().sort().join(','))throw new Error('epoch schema');}
export function epochStructure(e){
 exactKeys(e,FIELDS);
 if(e.version!==1)throw new Error('epoch version');
 exactKeys(e.new_identity,['source_id','rules_hash','config_hash','schema_hash']);
 for(const d of [...Object.values(e.new_identity),e.source_anchor,e.state_hash,e.event_hash,e.score_hash,e.metadata_hash,e.transition_hash])unhex(d,32);
 for(const n of [e.segment_id,e.logical_boundary,e.source_cursor])if(typeof n!=='bigint')throw new Error('epoch integer tags');else uint(n);
 const bytes=unhex(e.previous_publication_hex);if(bytes.length>MAX_EPOCH_PREDECESSOR)throw new Error('epoch predecessor capacity');
 const p=decodeCanonical(bytes);
 exactKeys(p,['version','identity','head','chunk_bytes','artifacts','render_format']);
 if(p.version!==6||p.render_format!==null||p.chunk_bytes!==16384)throw new Error('epoch requires committed v6 predecessor');
 exactKeys(p.identity,['source_id','rules_hash','config_hash','schema_hash']);Object.values(p.identity).forEach(d=>unhex(d,32));
 exactKeys(p.head,['segment_id','logical_end','source_to_exclusive','manifest_hash','state_hash','seal']);
 const h=p.head,s=h.seal;
 if(!s)throw new Error('epoch predecessor must be committed');
 exactKeys(s,['segment_id','logical_start','logical_end','source_from','source_to_exclusive','input_count','source_id','source_anchor','rules_hash','config_hash','schema_hash','previous_state','previous_manifest','input_root']);
 encodeSeal(s);
 for(const k of ['segment_id','logical_start','logical_end','source_from','source_to_exclusive'])if(typeof s[k]!=='bigint')throw new Error('epoch predecessor integer tags');
 if(!Number.isSafeInteger(s.input_count)||h.segment_id!==s.segment_id||h.logical_end!==s.logical_end||h.source_to_exclusive!==s.source_to_exclusive
   ||Object.keys(p.identity).some(k=>p.identity[k]!==s[k]))throw new Error('epoch predecessor head/identity');
 unhex(h.manifest_hash,32);unhex(h.state_hash,32);
 if(!Array.isArray(p.artifacts)||p.artifacts.length!==3)throw new Error('epoch predecessor catalog');
 for(const [i,a] of p.artifacts.entries()){
  exactKeys(a,['kind','length','sha256','chunks']);unhex(a.sha256,32);
  if(a.kind!==['state','events','scores'][i]||!Number.isSafeInteger(a.length)||a.length<0||a.length>1048576||!Array.isArray(a.chunks)||a.chunks.length!==Math.ceil(a.length/16384))throw new Error('epoch predecessor catalog');
  a.chunks.forEach(c=>unhex(c,32));
 }
 if(h.state_hash!==p.artifacts[0].sha256)throw new Error('epoch predecessor state');
 if(Object.keys(p.identity).every(k=>p.identity[k]===e.new_identity[k])||e.new_identity.source_id!==p.identity.source_id
   ||e.segment_id!==uint(s.segment_id+1n)||e.logical_boundary!==h.logical_end||e.source_cursor!==h.source_to_exclusive||e.source_anchor!==s.source_anchor)throw new Error('epoch predecessor boundary/identity');
 return {previous:p,bytes};
}
export function epochPayload(e){const body={...e};delete body.transition_hash;return concat(ascii('DTREPOCH1'),encodeCanonical(body));}
/** Hash checks precede this shared current-head relation. No game interpretation. */
export function checkEpochHead(e,h,identity,hashes){
 if(Object.keys(identity).some(k=>identity[k]!==e.new_identity[k])||h.segment_id===null||h.segment_id<e.segment_id||h.logical_end<e.logical_boundary||h.source_to_exclusive<e.source_cursor)throw new Error('epoch current boundary/identity');
 if(h.segment_id===e.segment_id){
  if(h.seal!==null||h.manifest_hash!==e.transition_hash||h.logical_end!==e.logical_boundary||h.source_to_exclusive!==e.source_cursor
    ||hashes.some((v,i)=>v!==[e.state_hash,e.event_hash,e.score_hash][i]))throw new Error('epoch checkpoint head');
 }else{
  const s=h.seal;
  if(!s||s.epoch_hash!==e.transition_hash||s.logical_start<e.logical_boundary||s.source_from<e.source_cursor)throw new Error('epoch successor commitment');
  if(s.segment_id===e.segment_id+1n&&(s.previous_manifest!==e.transition_hash||s.previous_state!==e.state_hash||s.logical_start!==e.logical_boundary||s.source_from!==e.source_cursor))throw new Error('epoch first successor');
 }
}
