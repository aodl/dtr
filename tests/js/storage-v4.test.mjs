import test from 'node:test';import assert from 'node:assert/strict';
import {ChunkStore,ChunkedJournalStore,descriptor,chunkHash} from '../../packages/storage/chunks.mjs';
import {encodeCanonical,decodeCanonical} from '../../packages/runtime/canonical.mjs';import {sha256,makeSeal} from '../../packages/runtime/seal.mjs';
import {SegmentJournal} from '../../packages/runtime/journal.mjs';
import {LifeInputKernel} from '../../packages/kernels/life-input.mjs';import {board,encodeBoard} from '../../packages/kernels/life.mjs';
const bytes=n=>Uint8Array.from({length:n},(_,i)=>i%251);
function upload(s,b,revision,chunk=16){const d=descriptor(b,revision,chunk),g=s.begin(s.revision(),d);for(let i=0;i<d.chunks.length;i++)s.put(g,i,b.slice(i*chunk,(i+1)*chunk));s.commit(g);return g;}
const restore=s=>{const b=s.snapshot();return ChunkStore.restore(b,sha256(b));};
for(const length of [0,1,15,16,17,255,4096,4097])test(`chunk upload exact boundaries ${length}`,()=>{
 const s=new ChunkStore(),b=bytes(length);upload(s,b,0);assert.deepEqual(s.read(),b);assert.deepEqual(restore(s).read(),b);
});
for(const failure of ['before_root','after','chunk:0','chunk:1','chunk:2'])test(`durable chunk failure ${failure}`,()=>{
 const initial={revision:0,payload:'old'.repeat(20)},next={revision:1,payload:'new'.repeat(40)};let s=ChunkedJournalStore.create(initial,16);
 assert.throws(()=>s.compareSwap(0,next,failure),/injected/);const b=s.snapshot();s=ChunkedJournalStore.restore(b,sha256(b),16);
 assert.deepEqual(s.read(),failure==='after'?next:initial);s.discardUnpublished();if(failure!=='after')s.compareSwap(0,next);
 assert.deepEqual(s.read(),next);
});
test('out-of-order, corrupted and stale uploads cannot publish',()=>{
 const s=new ChunkStore();upload(s,bytes(20),0);const original=s.read(),d=descriptor(bytes(50),1,16),g=s.begin(0,d);
 assert.throws(()=>s.put(g,1,bytes(16)),/out-of-order/);assert.throws(()=>s.commit(g),/incomplete/);
 assert.throws(()=>s.put(g,0,bytes(15)),/commitment/);s.put(g,0,bytes(16));s.put(g,0,bytes(16));assert.equal(s.pending.next_chunk,1);
 s.abort(g);const next=s.begin(0,d);assert.throws(()=>s.put(g,0,bytes(16)),/stale/);assert.throws(()=>s.commit(g),/stale/);assert.deepEqual(s.read(),original);assert(next>g);
});
test('committed corruption fails closed, never falls back to older game state',()=>{
 const s=new ChunkStore();upload(s,bytes(35),0);const key=s.root.descriptor.chunks[0];s.objects.get(key)[0]^=1;
 assert.throws(()=>s.read(),/corrupt/);const b=s.snapshot();assert.throws(()=>ChunkStore.restore(b,sha256(b)),/corrupt/);
});
test('bounded garbage collection retains both current and pending chunks',()=>{
 const s=new ChunkStore();upload(s,bytes(32),0);upload(s,Uint8Array.from(bytes(48),v=>v+1),1);
 const d=descriptor(Uint8Array.from(bytes(48),v=>v+2),2,16),g=s.begin(1,d);s.put(g,0,Uint8Array.from(bytes(16),v=>v+2));
 let steps=0;while(!s.collect(1).complete)assert(++steps<100);
 assert(s.objects.has(d.chunks[0]));assert.deepEqual(s.read(),Uint8Array.from(bytes(48),v=>v+1));
 s.abort(g);while(!s.collect(1).complete){}assert(!s.objects.has(d.chunks[0]));
});
test('storage capacity rejects before consuming the pending chunk position',()=>{
 const s=new ChunkStore({maxBytes:32,maxObjects:2});upload(s,bytes(32),0);
 const b=Uint8Array.from(bytes(16),v=>v+1),g=s.begin(0,descriptor(b,1,16));
 assert.throws(()=>s.put(g,0,b),/capacity/);assert.equal(s.pending.next_chunk,0);assert.deepEqual(s.read(),bytes(32));
});
test('domain and index bind chunks',()=>{assert.notEqual(chunkHash(0,bytes(5)),chunkHash(1,bytes(5)));});
function fresh(){
 const state=encodeBoard(board(5,5,Array.from({length:25},(_,i)=>[11,12,13].includes(i)?1:0))),kernel=LifeInputKernel;
 const id={rules_hash:'02'.repeat(32),config_hash:'03'.repeat(32),schema_hash:'04'.repeat(32)},ticks=3n,inputs=[];
 const identity={...id,source_id:'01'.repeat(32)},h=SegmentJournal.create(state,identity,{logical_start:0n,source_from:0n},kernel);
 const seal=makeSeal({...identity,segment_id:0n,logical_start:0n,logical_end:ticks,source_from:0n,source_to_exclusive:BigInt(inputs.length),source_anchor:'00'.repeat(32),previous_state:sha256(state),previous_manifest:'00'.repeat(32)},inputs,BigInt(inputs.length));
 return {h,kernel,seal,inputs};
}
for(const operation of ['prepare','advance','publish'])for(const fault of ['chunk:0','before_root','after'])test(`shared store recovery life/${operation}/${fault}`,()=>{
 const f=fresh();let s=ChunkedJournalStore.create(f.h.store.read(),4096),h=new SegmentJournal(s,f.kernel);
 const finish=()=>{let n=0;while(h.store.read().stage?.phase==='running'){h.advance(h.store.read().stage.fence,127);s.pages.collect(8192);assert(++n<100000);}};
 if(operation!=='prepare')h.prepare(f.seal,f.inputs);if(operation==='publish')finish();
 const before=h.committed();const ready=h.store.read().stage?.ready_hash;
 assert.throws(()=>operation==='prepare'?h.prepare(f.seal,f.inputs,fault):operation==='advance'?h.advance(1,7,fault):h.publish(ready,fault),/injected/);
 const image=s.snapshot();s=ChunkedJournalStore.restore(image,sha256(image));s.discardUnpublished();h=new SegmentJournal(s,f.kernel);
 if(operation!=='publish'||fault!=='after')assert.deepEqual(h.committed(),before);
 if(!s.read().stage&&h.committed().segment_id===null)h.prepare(f.seal,f.inputs);finish();if(s.read().stage)h.publish(s.read().stage.ready_hash);
 const reference=f.h;reference.prepare(f.seal,f.inputs);while(reference.store.read().stage.phase==='running')reference.advance(1,127);reference.publish(reference.store.read().stage.ready_hash);
 assert.deepEqual(h.committed(),reference.committed());
});
