/** Bounded flat hash catalog. This producer does not sign or certify anything. */
import {validateEpochHead} from '../runtime/epoch.mjs';
import {encodeCanonical,cloneCanonical} from '../runtime/canonical.mjs';
import {sha256,manifest} from '../runtime/seal.mjs';
import {hex,unhex} from '../protocol/bytes.mjs';
export const PUBLICATION_VERSION=7,CHUNK_BYTES=16384,MAX_ARTIFACT_BYTES=1024*1024,MAX_PUBLICATION_BYTES=65536;
export const KINDS=['state','events','scores'];
export function describeArtifact(kind,bytes){
  if(![...KINDS,'render'].includes(kind)||!(bytes instanceof Uint8Array)||bytes.length>MAX_ARTIFACT_BYTES)throw new Error('observation artifact bounds');
  const chunks=[];for(let at=0;at<bytes.length;at+=CHUNK_BYTES)chunks.push(sha256(bytes.subarray(at,at+CHUNK_BYTES)));
  return {kind,length:bytes.length,sha256:sha256(bytes),chunks};
}
/** v6 identity depends only on the committed head, never ingestion or private work.
 * render is a bounded, game-specific projection; it does NOT replace consensus events.
 */
export function publication(record,{version=record.journal.epoch?7:6,render=null}={}){
  if(![5,6,7].includes(version)||Boolean(record.journal.epoch)!==(version===7))throw new Error('observation publication version');
  if(version===5&&render!==null)throw new Error('legacy projection unsupported');
  if(![5,6].includes(record.version)||(record.version===6)!==Boolean(record.journal.epoch))throw new Error('observation coordinator version');
  const h=record.journal.head,artifacts=[unhex(h.state_hex),unhex(h.event_hex),unhex(h.score_hex)];
  if(sha256(artifacts[0])!==h.state_hash)throw new Error('observation state root');
  if(record.journal.epoch)validateEpochHead(record.journal.epoch,h,record.journal.identity);
  if(h.seal&&manifest(h.seal,...artifacts).manifest_hash!==h.manifest_hash)throw new Error('observation manifest root');
  const data={version,...(version===5?{revision:record.revision,ingest_head:record.inbox.cursor}:{}),identity:cloneCanonical(record.journal.identity),head:{segment_id:h.segment_id,logical_end:h.logical_end,
      source_to_exclusive:h.source_to_exclusive,manifest_hash:h.manifest_hash,state_hash:h.state_hash,seal:cloneCanonical(h.seal)},
    chunk_bytes:CHUNK_BYTES,artifacts:KINDS.map((k,i)=>describeArtifact(k,artifacts[i]))};
  if(version>=6){
    if(version===7)data.epoch=cloneCanonical(record.journal.epoch);
    data.render_format=null;
    if(render!==null){
      if(!render||Object.keys(render).sort().join(',')!=='bytes,format'
        ||!(render.bytes instanceof Uint8Array)||typeof render.format!=='string'||!/^[-a-z0-9]{1,64}$/.test(render.format))throw new Error('render projection schema');
      const bytes=Uint8Array.from(render.bytes); // publication owns all projected bytes
      data.artifacts.push(describeArtifact('render',bytes));artifacts.push(bytes);data.render_format=render.format;
    }
  }
  const bytes=encodeCanonical(data);if(bytes.length>MAX_PUBLICATION_BYTES)throw new Error('observation publication capacity');
  return {data,bytes,sha256:sha256(bytes),artifacts};
}
export function publishedChunk(record,expectedPublicationHash,kind,index,options={}){
  const p=publication(record,options);
  if(p.sha256!==expectedPublicationHash)throw new Error('stale observation publication');
  if(!p.data.artifacts.some(a=>a.kind===kind)||!Number.isSafeInteger(index)||index<0)throw new Error('observation chunk bounds');
  const at=p.data.artifacts.findIndex(a=>a.kind===kind),b=p.artifacts[at];
  if(index>=p.data.artifacts[at].chunks.length)throw new Error('observation chunk bounds');
  return b.slice(index*CHUNK_BYTES,(index+1)*CHUNK_BYTES);
}

/** Explicit historical fixture adapters; not the active protocol. */
export const publicationV5=record=>publication(record,{version:5});
export const publishedChunkV5=(record,hash,kind,index)=>publishedChunk(record,hash,kind,index,{version:5});

/** Small bounded committed-publication cache. Eviction requires client snapshot resync.
 * No uploads, generic CAS store, orphan collector, or availability promise across restart.
 * A production host persists retained committed segments in its own stable structures.
 */
export class PublicationWindow {
  #items=new Map(); #bytes=0; #last=null;
  constructor({maxSegments=3,maxBytes=8*1024*1024}={}){
    if(!Number.isSafeInteger(maxSegments)||maxSegments<1||maxSegments>32
      ||!Number.isSafeInteger(maxBytes)||maxBytes<1||maxBytes>128*1024*1024)throw new Error('retention bounds');
    this.maxSegments=maxSegments;this.maxBytes=maxBytes;
  }
  retain(record,options={}){
    const p=publication(record,options);if(![6,7].includes(p.data.version))throw new Error('retention requires publication v6/v7');
    if(this.#items.has(p.sha256))return p.sha256;
    const size=p.bytes.length+p.artifacts.reduce((n,b)=>n+b.length,0);
    if(size>this.maxBytes)throw new Error('publication exceeds retention byte capacity');
    if(this.#last){
      const a=this.#last.data,b=p.data,x=a.head,y=b.head;
      const crossing=a.version===6&&b.version===7&&b.head.seal===null&&b.epoch.previous_publication_hex===hex(this.#last.bytes);
      if(!crossing&&(Object.keys(a.identity).some(k=>a.identity[k]!==b.identity[k])||a.version!==b.version||a.epoch?.transition_hash!==b.epoch?.transition_hash)||a.render_format!==b.render_format)throw new Error('retention identity changed');
      const next=x.segment_id===null?0n:x.segment_id+1n;
      if(y.segment_id===null||y.segment_id<next)throw new Error('retention rollback/conflicting segment');
      if(!crossing&&(y.segment_id!==next||y.seal.previous_manifest!==x.manifest_hash||y.seal.previous_state!==x.state_hash
        ||y.seal.logical_start!==x.logical_end||y.seal.source_from!==x.source_to_exclusive))throw new Error('retention requires consecutive committed segments');
    }
    while(this.#items.size>=this.maxSegments||this.#bytes+size>this.maxBytes){
      const key=this.#items.keys().next().value,old=this.#items.get(key);this.#bytes-=old.size;this.#items.delete(key);
    }
    this.#items.set(p.sha256,{p,size});this.#bytes+=size;this.#last=p;
    return p.sha256;
  }
  catalog(hash){const x=this.#items.get(hash);if(!x)throw new Error('publication unavailable: snapshot resync required');return x.p.bytes.slice();}
  chunk(hash,kind,index){
    const x=this.#items.get(hash);if(!x)throw new Error('publication unavailable: snapshot resync required');
    const at=x.p.data.artifacts.findIndex(a=>a.kind===kind),d=x.p.data.artifacts[at];
    if(at<0||!Number.isSafeInteger(index)||index<0||index>=d.chunks.length)throw new Error('observation chunk bounds');
    return x.p.artifacts[at].slice(index*CHUNK_BYTES,(index+1)*CHUNK_BYTES);
  }
  status(){return {segments:this.#items.size,bytes:this.#bytes,hashes:[...this.#items.keys()]};}
}
