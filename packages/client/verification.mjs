/** Browser-compatible content verification; IC signature verification is an explicit dependency.
 * No root key is fetched from a replica. A missing certificate verifier is a hard failure.
 */
import {epochStructure,epochPayload,epochChainPayload,checkEpochHead} from '../protocol/epoch-codec.mjs';
import {decodeCanonical,encodeCanonical} from '../runtime/canonical.mjs';
import {encodeSeal} from '../protocol/seal-codec.mjs';
import {ascii,concat,hex,unhex,uint} from '../protocol/bytes.mjs';
const CHUNK=16384,MAX_BYTES=1048576,MAX_ENVELOPE=65536,KINDS=['state','events','scores'];
const authentic=new WeakSet();
const epochChains=new WeakMap();
export const sha256Web=async bytes=>hex(new Uint8Array(await globalThis.crypto.subtle.digest('SHA-256',bytes)));
function keys(v,wanted){if(!v||Object.keys(v).sort().join(',')!==wanted.slice().sort().join(','))throw new Error('publication schema');}
function digest(s){unhex(s,32);return s;}
async function content(bytes,expectedRoot){
  if(!(bytes instanceof Uint8Array)||bytes.length>MAX_ENVELOPE)throw new Error('publication bounds');
  bytes=Uint8Array.from(bytes); // Snapshot mutable transport memory before any await.
  digest(expectedRoot);if(await sha256Web(bytes)!==expectedRoot)throw new Error('publication root mismatch');
  const p=decodeCanonical(bytes);
  if(![5,6,7,8].includes(p.version))throw new Error('publication version');
  keys(p,p.version===5?['version','revision','identity','ingest_head','head','chunk_bytes','artifacts']
    :[ 'version','identity','head','chunk_bytes','artifacts','render_format',...(p.version>=7?['epoch']:[])]);
  if(p.chunk_bytes!==CHUNK||(p.version===5&&(!Number.isSafeInteger(p.revision)||p.revision<0)))throw new Error('publication version/revision');
  if(p.version>=6&&p.render_format!==null&&(typeof p.render_format!=='string'||!/^[-a-z0-9]{1,64}$/.test(p.render_format)))throw new Error('render format');
  keys(p.identity,['source_id','rules_hash','config_hash','schema_hash']);Object.values(p.identity).forEach(digest);
  keys(p.head,['segment_id','logical_end','source_to_exclusive','manifest_hash','state_hash','seal']);
  const h=p.head;
  if([...(p.version===5?[p.ingest_head]:[]),h.logical_end,h.source_to_exclusive].some(n=>typeof n!=='bigint')
    ||(h.segment_id!==null&&typeof h.segment_id!=='bigint'))throw new Error('publication integer tags');
  uint(h.logical_end);uint(h.source_to_exclusive);
  if(p.version===5&&uint(p.ingest_head)<uint(h.source_to_exclusive))throw new Error('publication source bounds');
  digest(h.manifest_hash);digest(h.state_hash);
  const kinds=p.version>=6&&p.render_format!==null?[...KINDS,'render']:KINDS;
  if(!Array.isArray(p.artifacts)||p.artifacts.length!==kinds.length)throw new Error('artifact catalog');
  for(let i=0;i<kinds.length;i++){
    const a=p.artifacts[i];keys(a,['kind','length','sha256','chunks']);digest(a.sha256);
    if(a.kind!==kinds[i]||!Number.isSafeInteger(a.length)||a.length<0||a.length>MAX_BYTES
       ||!Array.isArray(a.chunks)||a.chunks.length!==Math.ceil(a.length/CHUNK))throw new Error('artifact descriptor');
    a.chunks.forEach(digest);
  }
  if(h.state_hash!==p.artifacts[0].sha256)throw new Error('publication state identity');
  if(p.version>=7){
    const {bytes:previous}=epochStructure(p.epoch);
    if(await sha256Web(epochPayload(p.epoch))!==p.epoch.transition_hash)throw new Error('epoch commitment');
    if(p.version===7){
      if(p.epoch.version!==1)throw new Error('epoch publication version');
      await content(previous,await sha256Web(previous));
    }else if(p.epoch.version!==2)throw new Error('epoch publication version');
    epochChains.set(p,await sha256Web(epochChainPayload(p.epoch)));
    checkEpochHead(p.epoch,h,p.identity,p.artifacts.slice(0,3).map(a=>a.sha256));
  }
  if(h.seal===null){
    if(p.version<7&&(h.segment_id!==null||h.manifest_hash!=='00'.repeat(32)||p.artifacts[1].length!==0||p.artifacts[2].length!==0))throw new Error('publication genesis');
  }else{
    const s=h.seal;
    keys(s,['segment_id','logical_start','logical_end','source_from','source_to_exclusive','input_count','source_id','source_anchor','rules_hash','config_hash','schema_hash','previous_state','previous_manifest','input_root',...(p.version>=7?['epoch_hash']:[])]);
    if(['segment_id','logical_start','logical_end','source_from','source_to_exclusive'].some(k=>typeof s[k]!=='bigint')
      ||!Number.isSafeInteger(s.input_count))throw new Error('publication seal integer tags');
    for(const key of Object.keys(p.identity))if(s[key]!==p.identity[key])throw new Error('publication seal identity');
    if(uint(h.segment_id)!==uint(s.segment_id)||uint(h.logical_end)!==uint(s.logical_end)
      ||uint(h.source_to_exclusive)!==uint(s.source_to_exclusive))throw new Error('publication head/seal');
    const sealHash=await sha256Web(encodeSeal(s));
    const actual=await sha256Web(concat(ascii('DTRMANI1'),unhex(sealHash,32),...p.artifacts.slice(0,3).map(a=>unhex(a.sha256,32))));
    if(actual!==h.manifest_hash)throw new Error('publication manifest');
  }
  return p;
}
function freeze(value){if(value&&typeof value==='object'){Object.values(value).forEach(freeze);Object.freeze(value);}return value;}
function ticket(p,root,mode,extra={}){
  const out=freeze({publication:p,root_hash:root,mode,...extra});authentic.add(out);return out;
}
/** Offline trust means the caller independently obtained the pinned root, not that a canister signed it. */
export async function verifyPinnedPublication(bytes,expectedRoot){return ticket(await content(bytes,expectedRoot),expectedRoot,'offline-pinned-content');}
/** Verifier must use an audited IC certificate library: BLS, delegations, canister path and root key.
 * This checkpoint supplies the dependency contract, not a homegrown cryptographic substitute.
 */
export async function verifyCertificatePublication(bytes,certificate,policy,verifyCertificate){
  if(!(bytes instanceof Uint8Array)||bytes.length>MAX_ENVELOPE)throw new Error('publication bounds');
  bytes=Uint8Array.from(bytes);
  if(typeof verifyCertificate!=='function')throw new Error('IC certificate verifier unavailable');
  if(!(certificate instanceof Uint8Array)||certificate.length===0||certificate.length>262144)throw new Error('certificate bounds');
  if(typeof policy?.canister_id!=='string'||!policy.canister_id||typeof policy.network!=='string'||!policy.network)throw new Error('certificate policy');
  const now=uint(policy.now_ns),age=uint(policy.max_age_ns),future=uint(policy.max_future_ns);
  const deployment={canister_id:policy.canister_id,network:policy.network};
  const result=await verifyCertificate(Uint8Array.from(certificate),{...deployment});
  if(result.canister_id!==deployment.canister_id||result.network!==deployment.network)throw new Error('certificate deployment mismatch');
  const when=uint(result.certificate_time_ns);
  if(when>now+future||when+age<now)throw new Error('certificate freshness');
  const p=await content(bytes,result.certified_data_hex);
  return ticket(p,result.certified_data_hex,'certificate-verifier',{canister_id:deployment.canister_id,network:deployment.network,certificate_time_ns:when});
}
/** Authenticate an immediately preceding publication through a newer authentic
 * publication's seal. The predecessor manifest binds its seal and three
 * authoritative artifacts; the successor seal binds that manifest, state,
 * logical time and source watermark. Directory metadata is only a locator.
 */
export async function verifyRetainedPredecessor(bytes,successor){
  if(!authentic.has(successor))throw new Error('verified successor required');
  if(!(bytes instanceof Uint8Array)||bytes.length>MAX_ENVELOPE)throw new Error('publication bounds');
  bytes=Uint8Array.from(bytes);const root=await sha256Web(bytes),p=await content(bytes,root),next=successor.publication;
  if(![6,7,8].includes(p.version)||![6,7,8].includes(next.version))throw new Error('retained publication identity');
  // A successor seal authenticates only the predecessor's authoritative
  // manifest (state, events and scores). Optional render bytes require their
  // own directly authenticated catalog and cannot inherit predecessor trust.
  if(p.render_format!==null||next.render_format!==null)throw new Error('retained render requires direct authentication');
  if(next.version>=7&&next.head.seal===null&&p.epoch?.transition_hash!==next.epoch.transition_hash){
    const shape=epochStructure(next.epoch);
    if(next.epoch.version===1){
      if(p.version!==6||hex(bytes)!==next.epoch.previous_publication_hex)throw new Error('retained epoch predecessor');
    }else{
      const q=shape.predecessor;
      if(root!==q.publication_hash||p.version!==q.version||Object.keys(p.identity).some(k=>p.identity[k]!==q.identity[k])
        ||p.head.segment_id!==q.segment_id||p.head.logical_end!==q.logical_end||p.head.source_to_exclusive!==q.source_cursor
        ||p.head.manifest_hash!==q.manifest_hash||p.head.state_hash!==q.state_hash||p.epoch?.transition_hash!==q.epoch_hash
        ||epochChains.get(p)!==next.epoch.previous_chain_hash||(p.epoch.transition_index??1n)+1n!==next.epoch.transition_index)throw new Error('retained epoch predecessor');
    }
    const extra=successor.mode==='certificate-verifier'?{canister_id:successor.canister_id,network:successor.network,certificate_time_ns:successor.certificate_time_ns}:{};
    return ticket(p,root,successor.mode,extra);
  }
  if(p.version!==next.version||(p.version>=7&&p.epoch.transition_hash!==next.epoch.transition_hash))throw new Error('retained epoch mismatch');
  if(p.render_format!==next.render_format
    ||Object.keys(p.identity).some(k=>p.identity[k]!==next.identity[k]))throw new Error('retained publication identity');
  const a=p.head,b=next.head,s=b.seal;
  const expected=a.segment_id===null?0n:a.segment_id+1n;
  if(!s||b.segment_id!==expected||s.previous_manifest!==a.manifest_hash||s.previous_state!==a.state_hash
    ||s.logical_start!==a.logical_end||s.source_from!==a.source_to_exclusive)throw new Error('retained publication is not certified predecessor');
  const extra=successor.mode==='certificate-verifier'?{canister_id:successor.canister_id,network:successor.network,
    certificate_time_ns:successor.certificate_time_ns}:{};
  return ticket(p,root,successor.mode,extra);
}
export class ArtifactAssembler {
  constructor(verified,kind){
    if(!authentic.has(verified))throw new Error('verified publication required');
    const desc=verified.publication.artifacts.find(a=>a.kind===kind);if(!desc)throw new Error('artifact kind');
    this.descriptor=desc;this.parts=new Map();this.root=verified.root_hash;
  }
  async accept(index,bytes){
    const d=this.descriptor;
    if(!Number.isSafeInteger(index)||index<0||index>=d.chunks.length||!(bytes instanceof Uint8Array)
      ||bytes.length!==Math.min(CHUNK,d.length-index*CHUNK))throw new Error('chunk shape');
    // Copy before awaiting: a caller must not alter bytes after hashing and before retention.
    const copy=Uint8Array.from(bytes);if(await sha256Web(copy)!==d.chunks[index])throw new Error('chunk integrity');
    this.parts.set(index,copy);return this.parts.size===d.chunks.length;
  }
  async finish(){
    const d=this.descriptor;if(this.parts.size!==d.chunks.length)throw new Error('incomplete artifact');
    const bytes=new Uint8Array(d.length);
    for(let i=0;i<d.chunks.length;i++)bytes.set(this.parts.get(i),i*CHUNK);
    if(await sha256Web(bytes)!==d.sha256)throw new Error('artifact integrity');return bytes;
  }
}

/** A client must not accept an older/same-height conflicting head just because a signature is valid. */
function deployment(a,b){
 if(a.mode!==b.mode||a.canister_id!==b.canister_id||a.network!==b.network)throw new Error('observation deployment/rules changed');
}
function crossing(a,b,resync){
 if(![7,8].includes(b.version))throw new Error('observation deployment/rules changed');
 const e=b.epoch,shape=epochStructure(e),summary=e.version===1?shape.previous:{identity:shape.predecessor.identity,head:{segment_id:shape.predecessor.segment_id,logical_end:shape.predecessor.logical_end,source_to_exclusive:shape.predecessor.source_cursor}};
 if(Object.keys(a.identity).some(k=>a.identity[k]!==summary.identity[k])||a.render_format!==b.render_format)throw new Error('observation epoch identity');
 if(e.version===1){if(a.version!==6)throw new Error('observation epoch identity');}
 else if(a.version!==shape.predecessor.version||a.epoch?.transition_hash!==shape.predecessor.epoch_hash||epochChains.get(a)!==e.previous_chain_hash||(a.epoch.transition_index??1n)+1n!==e.transition_index)throw new Error('observation epoch chain');
 const old=a.head.segment_id===null?-1n:a.head.segment_id,cut=summary.head.segment_id;
 if(old>cut||a.head.logical_end>e.logical_boundary||a.head.source_to_exclusive>e.source_cursor)throw new Error('observation epoch rollback');
 if(old===cut){
  if(e.version===1&&hex(encodeCanonical(a))!==e.previous_publication_hex)throw new Error('observation epoch predecessor mismatch');
  if(e.version===2&&(a.head.manifest_hash!==shape.predecessor.manifest_hash||a.head.state_hash!==shape.predecessor.state_hash))throw new Error('observation epoch predecessor mismatch');
 }
 if(!resync&&(old!==cut||b.head.segment_id!==e.segment_id))throw new Error('epoch snapshot resync required');
}
function sameEpoch(a,b){
 if(b.version!==a.version||Object.keys(b.identity).some(k=>b.identity[k]!==a.identity[k]))return false;
 if(a.version>=7&&a.epoch.transition_hash!==b.epoch.transition_hash)throw new Error('observation epoch changed');
 return true;
}
export class PublicationSequence {
 constructor(){this.last=null;}
 accept(verified){
  if(!authentic.has(verified))throw new Error('verified publication required');
  const p=verified.publication,prior=this.last?.publication;
  if(prior){
   deployment(this.last,verified);
   if(!sameEpoch(prior,p)){crossing(prior,p,false);this.last=verified;return verified;}
   if(p.version===5){
    if(p.revision<prior.revision||p.ingest_head<prior.ingest_head)throw new Error('observation rollback');
    if(p.revision===prior.revision&&verified.root_hash!==this.last.root_hash)throw new Error('same-revision conflicting observation');
   }else if(p.render_format!==prior.render_format)throw new Error('render format changed: explicit resync required');
   const a=prior.head,b=p.head;
   if(a.segment_id===b.segment_id){
    if(p.version>=6&&verified.root_hash!==this.last.root_hash)throw new Error('same-height conflicting observation');
    if(a.manifest_hash!==b.manifest_hash||a.state_hash!==b.state_hash||a.logical_end!==b.logical_end||a.source_to_exclusive!==b.source_to_exclusive)throw new Error('same-height conflicting observation');
   }else{
    const next=a.segment_id===null?0n:a.segment_id+1n;
    if(b.segment_id===null||b.segment_id<next)throw new Error('observation rollback');
    if(b.segment_id!==next)throw new Error('snapshot resync required');
    if(!b.seal||b.seal.previous_manifest!==a.manifest_hash||b.seal.previous_state!==a.state_hash||b.seal.logical_start!==a.logical_end||b.seal.source_from!==a.source_to_exclusive)throw new Error('observation chain mismatch');
   }
  }
  this.last=verified;return verified;
 }
 /** Explicit snapshot anchor retains the session floor, including across epochs. */
 resync(verified){
  if(!authentic.has(verified))throw new Error('verified publication required');
  if(!this.last)return this.accept(verified);
  deployment(this.last,verified);
  const a=this.last.publication,b=verified.publication;
  if(!sameEpoch(a,b))crossing(a,b,true);
  else if(b.render_format!==a.render_format)throw new Error('observation deployment/rules changed');
  const old=a.head.segment_id===null?-1n:a.head.segment_id,next=b.head.segment_id===null?-1n:b.head.segment_id;
  if(next<=old||b.head.logical_end<a.head.logical_end||b.head.source_to_exclusive<a.head.source_to_exclusive)throw new Error('observation rollback');
  this.last=verified;return verified;
 }
}
