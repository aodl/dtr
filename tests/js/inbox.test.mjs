import test from 'node:test';
import assert from 'node:assert/strict';
import {VerifiedInbox} from '../../packages/source/inbox.mjs';
import {AtomicJournalStore} from '../../packages/runtime/journal.mjs';
import {makeSeal,manifest,sha256} from '../../packages/runtime/seal.mjs';
import {hex} from '../../packages/protocol/bytes.mjs';
const source='12'.repeat(32),anchor='34'.repeat(32);
function seal(inbox,cutoff=inbox.store.read().cursor){
  const r=inbox.store.read(),inputs=inbox.selection(cutoff);
  return makeSeal({source_id:source,source_anchor:anchor,segment_id:0n,logical_start:0n,logical_end:1n,
    source_from:r.retired_to,source_to_exclusive:cutoff,rules_hash:anchor,config_hash:anchor,schema_hash:anchor,
    previous_state:anchor,previous_manifest:anchor},inputs,r.cursor);
}
function head(s){const bytes=Uint8Array.of(1);return {seal:s,manifest_hash:manifest(s,bytes,bytes,bytes).manifest_hash,state_hex:hex(bytes),event_hex:hex(bytes),score_hex:hex(bytes)};}
test('cursor and relevant inbox rows advance atomically; ignored records still occupy positions',()=>{
  const i=VerifiedInbox.create(source,100n);i.ingest(100n,[null,'aa',null,'bb'],anchor);
  assert.equal(i.store.read().cursor,104n);assert.deepEqual(i.selection(104n).map(i=>i.position),[101n,103n]);
});
test('failed classify/page, gap, replay and unverified cutoff cannot advance cursor',()=>{
  const i=VerifiedInbox.create(source,100n);for(const [start,rows] of [[101n,['aa']],[99n,['aa']],[100n,['aa','invalid']]])assert.throws(()=>i.ingest(start,rows,anchor));
  assert.equal(i.store.read().cursor,100n);assert.throws(()=>i.selection(101n));
});
test('stale source callback is fenced by revision',()=>{
  const i=VerifiedInbox.create(source,0n),a=i.proposePage(0n,['aa'],anchor),b=i.proposePage(0n,['bb'],anchor);
  i.commitPage(a);assert.throws(()=>i.commitPage(b),/stale/);assert.equal(i.selection(1n)[0].payload_hex,'aa');
});
test('reserved inputs remain durable until publication acknowledgement, later input remains pending',()=>{
  let i=VerifiedInbox.create(source,0n);i.ingest(0n,['aa',null,'bb'],anchor);const s=seal(i,3n),selected=i.reserve(s);
  i.ingest(3n,['cc'],anchor);assert.equal(selected.length,2);assert.equal(i.store.read().pending.length,3);
  const bytes=i.store.snapshot();i=new VerifiedInbox(AtomicJournalStore.restore(bytes,sha256(bytes)));
  assert(i.acknowledge(head(s)));assert.equal(i.store.read().retired_to,3n);assert.deepEqual(i.selection(4n),[{position:3n,payload_hex:'cc'}]);
  assert.equal(i.acknowledge(head(s)),false);
});
for(const operation of ['ingest','reserve','ack'])for(const fault of ['before','after'])test(`inbox crash ${operation}/${fault}`,()=>{
  let i=VerifiedInbox.create(source,0n),s;
  if(operation!=='ingest')i.ingest(0n,['aa'],anchor);
  if(operation==='ack'){s=seal(i);i.reserve(s);}
  const before=i.store.snapshot();
  assert.throws(()=>operation==='ingest'?i.ingest(0n,['aa'],anchor,fault):operation==='reserve'?i.reserve(seal(i),fault):i.acknowledge(head(s),fault),/injected/);
  if(fault==='before')assert.deepEqual(i.store.snapshot(),before);
  const bytes=i.store.snapshot();i=new VerifiedInbox(AtomicJournalStore.restore(bytes,sha256(bytes)));
  if(operation==='ack'&&fault==='after'){assert.equal(i.store.read().pending.length,0);assert.equal(i.acknowledge(head(s)),false);}
});
test('backpressure refuses whole page rather than silently discarding commands',()=>{
  const i=VerifiedInbox.create(source,0n);for(let n=0;n<16;n++)i.ingest(BigInt(n*256),Array(256).fill('aa'),anchor);
  assert.throws(()=>i.ingest(4096n,['bb'],anchor),/backpressure/);assert.equal(i.store.read().cursor,4096n);assert.equal(i.store.read().pending.length,4096);
});
test('wrong boundary anchor, double reservation and forged ack rejected',()=>{
  const i=VerifiedInbox.create(source,0n);i.ingest(0n,['aa'],anchor);const s=seal(i);
  assert.throws(()=>i.reserve({...s,source_anchor:'ff'.repeat(32)}),/anchor/);i.reserve(s);assert.throws(()=>i.reserve(s),/reserved/);
  assert.throws(()=>i.acknowledge({...head(s),manifest_hash:'ff'.repeat(32)}),/invalid/);assert.equal(i.store.read().pending.length,1);
});
test('empty ledger pages cannot invent a new boundary anchor',()=>{
  const i=VerifiedInbox.create(source,0n);assert.throws(()=>i.ingest(0n,[],anchor),/anchor/);i.ingest(0n,[],'00'.repeat(32));assert.equal(i.store.read().cursor,0n);
});
