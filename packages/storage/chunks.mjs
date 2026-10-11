/** Bounded, content-addressed persistence model. NOT IC certification or a disk driver. */
import {encodeCanonical,decodeCanonical,cloneCanonical} from '../runtime/canonical.mjs';
import {sha256} from '../runtime/seal.mjs';
import {ascii,be,concat,hex,unhex} from '../protocol/bytes.mjs';
export const STORAGE_LIMITS=Object.freeze({max_blob:16*1024*1024,max_chunk:65536,max_chunks:4096,max_objects:8192,max_stored_bytes:64*1024*1024});
const integer=(n,min,max)=>{if(!Number.isSafeInteger(n)||n<min||n>max)throw new Error('storage integer bounds');return n;};
export function chunkHash(index,bytes){
 integer(index,0,STORAGE_LIMITS.max_chunks-1);
 if(!(bytes instanceof Uint8Array)||bytes.length>STORAGE_LIMITS.max_chunk)throw new Error('chunk bytes');
 return sha256(concat(ascii('DTRCHUNK4'),be(index,4),be(bytes.length,4),bytes));
}
export function descriptor(bytes,revision,chunkSize=4096){
 integer(revision,0,Number.MAX_SAFE_INTEGER);integer(chunkSize,1,STORAGE_LIMITS.max_chunk);
 if(!(bytes instanceof Uint8Array)||bytes.length>STORAGE_LIMITS.max_blob)throw new Error('blob bounds');
 const chunks=[];for(let p=0;p<bytes.length;p+=chunkSize)chunks.push(chunkHash(chunks.length,bytes.slice(p,p+chunkSize)));
 if(chunks.length>STORAGE_LIMITS.max_chunks)throw new Error('chunk count');
 return {version:4,revision,length:bytes.length,chunk_size:chunkSize,payload_hash:sha256(bytes),chunks};
}
function validateDescriptor(d){
 if(d?.version!==4)throw new Error('descriptor version');
 integer(d.revision,0,Number.MAX_SAFE_INTEGER);integer(d.length,0,STORAGE_LIMITS.max_blob);integer(d.chunk_size,1,STORAGE_LIMITS.max_chunk);
 if(!Array.isArray(d.chunks)||d.chunks.length!==Math.ceil(d.length/d.chunk_size)||d.chunks.length>STORAGE_LIMITS.max_chunks)throw new Error('descriptor chunk count');
 for(const h of [d.payload_hash,...d.chunks])unhex(h,32);
 if(Object.keys(d).sort().join(',')!=='chunk_size,chunks,length,payload_hash,revision,version')throw new Error('descriptor fields');
 return d;
}
/** One trusted writer generation; stale callers cannot alter the currently reserved upload. */
export class ChunkStore{
 constructor({maxBytes=STORAGE_LIMITS.max_stored_bytes,maxObjects=STORAGE_LIMITS.max_objects}={}){
  integer(maxBytes,1,STORAGE_LIMITS.max_stored_bytes);integer(maxObjects,1,STORAGE_LIMITS.max_objects);
  this.maxBytes=maxBytes;this.maxObjects=maxObjects;this.generation=0;this.root=null;this.pending=null;this.objects=new Map();this.gcAfter=null;
 }
 revision(){return this.root?.descriptor.revision??-1;}
 begin(expectedRevision,d){
  validateDescriptor(d);
  if(expectedRevision!==this.revision()||d.revision!==expectedRevision+1)throw new Error('stale root revision');
  if(this.pending)throw new Error('unpublished upload requires explicit recovery');
  integer(this.generation+1,1,Number.MAX_SAFE_INTEGER);
  const generation=++this.generation;
  this.pending={generation,base_revision:expectedRevision,descriptor:cloneCanonical(d),descriptor_hash:sha256(encodeCanonical(d)),next_chunk:0};
  return generation;
 }
 owned(generation){
  const p=this.pending;if(!p||p.generation!==generation||p.base_revision!==this.revision())throw new Error('stale upload generation');return p;
 }
 put(generation,index,bytes){
  const p=this.owned(generation),d=p.descriptor;integer(index,0,d.chunks.length-1);
  if(index>p.next_chunk)throw new Error('out-of-order chunk');
  const length=Math.min(d.chunk_size,d.length-index*d.chunk_size);
  if(bytes.length!==length||chunkHash(index,bytes)!==d.chunks[index])throw new Error('chunk commitment mismatch');
  const existing=this.objects.get(d.chunks[index]);
  if(existing&&(existing.length!==bytes.length||existing.some((v,i)=>v!==bytes[i])))throw new Error('immutable chunk corruption');
  if(!existing){
   const used=[...this.objects.values()].reduce((n,b)=>n+b.length,0);
   if(this.objects.size>=this.maxObjects||used+bytes.length>this.maxBytes)throw new Error('storage capacity');
   this.objects.set(d.chunks[index],bytes.slice());
  }
  if(index===p.next_chunk)p.next_chunk++;
 }
 assemble(d){
  validateDescriptor(d);const parts=[];
  for(let i=0;i<d.chunks.length;i++){
   const b=this.objects.get(d.chunks[i]);
   if(!b||b.length!==Math.min(d.chunk_size,d.length-i*d.chunk_size)||chunkHash(i,b)!==d.chunks[i])throw new Error('missing/corrupt committed chunk');parts.push(b);
  }
  const bytes=concat(...parts);if(sha256(bytes)!==d.payload_hash)throw new Error('payload commitment mismatch');return bytes;
 }
 commit(generation){
  if(!this.pending){if(this.root?.generation===generation)return cloneCanonical(this.root);throw new Error('stale commit');}
  const p=this.owned(generation);
  if(p.next_chunk!==p.descriptor.chunks.length)throw new Error('upload incomplete');
  if(sha256(encodeCanonical(p.descriptor))!==p.descriptor_hash)throw new Error('descriptor corruption');
  this.assemble(p.descriptor); // Bounded full verification, not an instruction quota.
  this.root={generation,descriptor:cloneCanonical(p.descriptor),descriptor_hash:p.descriptor_hash};this.pending=null;
  return cloneCanonical(this.root);
 }
 abort(generation){this.owned(generation);this.pending=null;}
 read(){if(!this.root)throw new Error('store not initialized');return this.assemble(this.root.descriptor);}
 collect(budget){
  integer(budget,1,8192);const keep=new Set([...(this.root?.descriptor.chunks??[]),...(this.pending?.descriptor.chunks??[])]);
  const keys=[...this.objects.keys()].sort().filter(k=>this.gcAfter===null||k>this.gcAfter);let visited=0,deleted=0;
  for(const key of keys){if(visited===budget)break;this.gcAfter=key;visited++;if(!keep.has(key)){this.objects.delete(key);deleted++;}}
  if(visited===keys.length)this.gcAfter=null;return {visited,deleted,complete:this.gcAfter===null};
 }
 snapshot(){return encodeCanonical({version:4,maxBytes:this.maxBytes,maxObjects:this.maxObjects,generation:this.generation,root:this.root,pending:this.pending,gcAfter:this.gcAfter,
  objects:[...this.objects].sort(([a],[b])=>a<b?-1:a>b?1:0).map(([h,b])=>[h,hex(b)])});}
 static restore(bytes,trustedHash){
  if(sha256(bytes)!==trustedHash)throw new Error('storage image hash');const p=decodeCanonical(bytes);
  if(p.version!==4)throw new Error('storage image version');const s=new ChunkStore(p);s.generation=integer(p.generation,0,Number.MAX_SAFE_INTEGER);s.root=p.root;s.pending=p.pending;s.gcAfter=p.gcAfter;
  let prior='';let used=0;if(!Array.isArray(p.objects)||p.objects.length>s.maxObjects)throw new Error('storage image objects');
  for(const [h,text]of p.objects){unhex(h,32);if(h<=prior)throw new Error('object order/duplicate');prior=h;const b=unhex(text);if(b.length>STORAGE_LIMITS.max_chunk)throw new Error('oversize stored chunk');used+=b.length;s.objects.set(h,b);}
  if(used>s.maxBytes)throw new Error('storage image capacity');
  if(s.gcAfter!==null)unhex(s.gcAfter,32);
  if(s.root){validateDescriptor(s.root.descriptor);integer(s.root.generation,1,s.generation);
   if(sha256(encodeCanonical(s.root.descriptor))!==s.root.descriptor_hash)throw new Error('root descriptor corruption');s.read();}
  if(s.pending){const d=validateDescriptor(s.pending.descriptor);s.owned(s.pending.generation);integer(s.pending.generation,1,s.generation);
   if(s.pending.generation!==s.generation||(s.root&&s.root.generation>=s.pending.generation)||d.revision!==s.revision()+1||sha256(encodeCanonical(d))!==s.pending.descriptor_hash)throw new Error('pending descriptor corruption');
   integer(s.pending.next_chunk,0,d.chunks.length);
   for(let i=0;i<s.pending.next_chunk;i++){const b=s.objects.get(d.chunks[i]);if(!b||b.length!==Math.min(d.chunk_size,d.length-i*d.chunk_size)||chunkHash(i,b)!==d.chunks[i])throw new Error('persisted upload corruption');}
  }
  if(s.snapshot().length!==bytes.length||s.snapshot().some((v,i)=>v!==bytes[i]))throw new Error('storage schema roundtrip');return s;
 }
}
/** Adapter for SegmentJournal's atomic-document contract. Partial chunks are never published. */
export class ChunkedJournalStore{
 constructor(pages,chunkSize=4096){this.pages=pages;this.chunkSize=integer(chunkSize,1,STORAGE_LIMITS.max_chunk);}
 static create(record,chunkSize=4096){
  if(record.revision!==0)throw new Error('initial journal revision');const p=new ChunkStore(),b=encodeCanonical(record),d=descriptor(b,0,chunkSize),g=p.begin(-1,d);
  for(let i=0;i<d.chunks.length;i++)p.put(g,i,b.slice(i*chunkSize,(i+1)*chunkSize));p.commit(g);return new ChunkedJournalStore(p,chunkSize);
 }
 read(){const r=decodeCanonical(this.pages.read());if(r.revision!==this.pages.revision())throw new Error('journal/root revision mismatch');return r;}
 compareSwap(revision,replacement,fault=null){
  if(revision!==this.read().revision||replacement.revision!==revision+1)throw new Error('stale journal revision');
  if(fault==='before')throw new Error('injected pre-write failure');
  const bytes=encodeCanonical(replacement),d=descriptor(bytes,replacement.revision,this.chunkSize),g=this.pages.begin(revision,d);
  for(let i=0;i<d.chunks.length;i++){this.pages.put(g,i,bytes.slice(i*this.chunkSize,(i+1)*this.chunkSize));if(fault===`chunk:${i}`)throw new Error('injected partial chunk write');}
  if(fault==='before_root')throw new Error('injected pre-root interruption');this.pages.commit(g);
  if(fault==='after')throw new Error('injected lost root acknowledgement');
 }
 discardUnpublished(){if(this.pages.pending)this.pages.abort(this.pages.pending.generation);}
 snapshot(){return this.pages.snapshot();}
 static restore(bytes,trustedHash,chunkSize=4096){return new ChunkedJournalStore(ChunkStore.restore(bytes,trustedHash),chunkSize);}
}
