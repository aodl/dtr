import test from 'node:test';
import assert from 'node:assert/strict';
import {AtomicJournalStore, SegmentJournal} from '../../packages/runtime/journal.mjs';
import {decodeCanonical, encodeCanonical} from '../../packages/runtime/canonical.mjs';
import {LifeInputKernel, encodeLifeSet} from '../../packages/kernels/life-input.mjs';
import {board, encodeBoard, decodeBoard} from '../../packages/kernels/life.mjs';
import {makeSeal, sha256} from '../../packages/runtime/seal.mjs';
import {hex, unhex} from '../../packages/protocol/bytes.mjs';
const identity = {source_id:'01'.repeat(32),rules_hash:'02'.repeat(32),config_hash:'03'.repeat(32),schema_hash:'04'.repeat(32)};
function fresh() {
  return SegmentJournal.create(encodeBoard(board(4,4,Array(16).fill(0))), identity,
    {logical_start:0n,source_from:10n},LifeInputKernel);
}
function seal(host,inputs=[],ticks=2n) {
  const h=host.committed(),from=h.source_to_exclusive,to=inputs.length?BigInt(inputs.at(-1).position)+1n:from;
  return makeSeal({...identity,segment_id:h.segment_id===null?0n:h.segment_id+1n,logical_start:h.logical_end,
    logical_end:h.logical_end+ticks,source_from:from,source_to_exclusive:to,source_anchor:'05'.repeat(32),
    previous_state:h.state_hash,previous_manifest:h.manifest_hash},inputs,to);
}
function restored(host) {const b=host.store.snapshot();return new SegmentJournal(AtomicJournalStore.restore(b,sha256(b)),LifeInputKernel);}
function finish(host,budget=7,roundtrip=false) {
  let h=host;
  for(let i=0;i<10000;i++){
    const r=h.store.read();if(r.stage.phase==='ready')return h;
    h.advance(r.stage.fence,budget);if(roundtrip)h=restored(h);
  }throw new Error('test loop cap');
}
const commands = [
  {position:10n,payload_hex:hex(encodeLifeSet(1,5))},
  {position:11n,payload_hex:hex(encodeLifeSet(2,6))},
  {position:12n,payload_hex:hex(encodeLifeSet(1,9))},
  {position:13n,payload_hex:hex(encodeLifeSet(1,10))},
  {position:14n,payload_hex:'00'},
  {position:15n,payload_hex:hex(encodeLifeSet(1,999))},
];
test('host stages command application without exposing intermediate state',()=>{
  let h=fresh();const before=h.committed();h.prepare(seal(h,commands),commands);h.advance(1,2);
  assert.deepEqual(h.committed(),before);h=finish(h,1,true);
  assert.deepEqual(h.committed(),before);const ready=h.store.read().stage.ready_hash;
  const committed=h.publish(ready);const final=decodeBoard(unhex(committed.state_hex));
  assert.equal(final.generation,2n);assert.equal(final.cells[6],2);
  const events=decodeCanonical(unhex(committed.event_hex));
  assert.deepEqual(events.receipts.map(x=>x.reason),['ACCEPTED','ACCEPTED','ACCEPTED','ACCEPTED','MALFORMED','CELL_RANGE']);
  assert.deepEqual(h.publish(ready),committed);
});
test('changing budgets and restarting every safe point preserves manifest',()=>{
  const hashes=[];for(const b of [1,2,7,100000]){let h=fresh();h.prepare(seal(h,commands),commands);h=finish(h,b,true);hashes.push(h.store.read().stage.ready_hash);}
  assert.equal(new Set(hashes).size,1);
});
test('stale step cannot overwrite newer progress',()=>{
  const h=fresh();h.prepare(seal(h),[]);const a=h.proposeStep(1,1),b=h.proposeStep(1,2);
  h.commitProposal(a);const snapshot=h.store.snapshot();assert.throws(()=>h.commitProposal(b),/stale/);assert.deepEqual(h.store.snapshot(),snapshot);
});
for(const operation of ['prepare','advance','publish']) for(const point of ['before','after'])
  test(`crash matrix ${operation}/${point}: restart reconciles atomic state`,()=>{
    let h=fresh();let ready;
    if(operation!=='prepare')h.prepare(seal(h,commands),commands);
    if(operation==='publish'){h=finish(h);ready=h.store.read().stage.ready_hash;}
    const before=h.store.snapshot();
    assert.throws(()=>operation==='prepare'?h.prepare(seal(h,commands),commands,point):operation==='advance'?h.advance(1,2,point):h.publish(ready,point),/injected/);
    if(point==='before')assert.deepEqual(h.store.snapshot(),before);else assert.notDeepEqual(h.store.snapshot(),before);
    h=restored(h);
    if(!h.store.read().stage&&h.committed().segment_id===null)h.prepare(seal(h,commands),commands);
    if(h.store.read().stage){h=finish(h,1,true);ready=h.store.read().stage.ready_hash;h.publish(ready);}
    const state=h.committed();assert.equal(state.segment_id,0n);assert.equal(decodeBoard(unhex(state.state_hex)).generation,2n);
    assert.deepEqual(h.publish(state.manifest_hash),state);
  });
test('successor sequence rejects source replay and accepts contiguous empty intervals',()=>{
  let h=fresh();const first=seal(h,commands);h.prepare(first,commands);h=finish(h);h.publish(h.store.read().stage.ready_hash);
  assert.throws(()=>h.prepare(first,commands));const next=seal(h,[],3n);h.prepare(next,[]);h=finish(h,3,true);h.publish(h.store.read().stage.ready_hash);
  assert.equal(h.committed().logical_end,5n);assert.equal(h.committed().source_to_exclusive,16n);
});
for(const key of ['source_id','rules_hash','config_hash','schema_hash','previous_state','previous_manifest'])
  test(`reject seal identity/link ${key}`,()=>{const h=fresh();const s={...seal(h),[key]:'ff'.repeat(32)};assert.throws(()=>h.prepare(s,[]));assert.equal(h.store.read().stage,null);});
test('reject unsealed inputs without changing durable record',()=>{const h=fresh(),s=seal(h,commands),bad=[...commands.slice(1)],prior=h.store.snapshot();assert.throws(()=>h.prepare(s,bad));assert.deepEqual(h.store.snapshot(),prior);});
test('reject concurrent stage and premature publication',()=>{const h=fresh();h.prepare(seal(h),[]);assert.throws(()=>h.prepare(seal(h),[]),/staged/);assert.throws(()=>h.publish('ff'.repeat(32)),/ready/);});
test('ready hash is verified, corrupt journal and unknown schema fail closed',()=>{
  let h=fresh();h.prepare(seal(h),[]);h=finish(h);
  assert.throws(()=>h.publish('ee'.repeat(32)),/ready/);
  const p=h.store.read();p.stage.cursor_hex='00';assert.throws(()=>new SegmentJournal(new AtomicJournalStore(p),LifeInputKernel),/mismatch/);
  const q=h.store.read();q.version=999;assert.throws(()=>new SegmentJournal(new AtomicJournalStore(q),LifeInputKernel),/schema/);
  const s=h.store.snapshot();s[0]^=1;assert.throws(()=>AtomicJournalStore.restore(s,'00'.repeat(32)),/integrity/);
});
test('kernel traps and invalid progress never persist a proposal',()=>{
  const h=fresh();h.prepare(seal(h),[]);const before=h.store.snapshot();
  for(const progress of [{used:0,complete:false},{used:9,complete:false},{used:1,complete:1}]){
    const bad={...LifeInputKernel,restore:()=>({step:()=>progress})};h.kernel=bad;assert.throws(()=>h.advance(1,2),/progress/);
    assert.deepEqual(h.store.snapshot(),before);
  }
  h.kernel={...LifeInputKernel,restore:()=>({step:()=>{throw new Error('kernel trap');}})};
  assert.throws(()=>h.advance(1,2),/trap/);assert.deepEqual(h.store.snapshot(),before);
});
test('restoring a head verifies output commitments',()=>{
  let h=fresh();h.prepare(seal(h),[]);h=finish(h);h.publish(h.store.read().stage.ready_hash);
  const p=h.store.read();p.head.event_hex='00';assert.throws(()=>new SegmentJournal(new AtomicJournalStore(p),LifeInputKernel),/manifest/);
});
test('overwriting input cells respects source order',()=>{
  const h=fresh();const cmds=[{position:10n,payload_hex:hex(encodeLifeSet(1,5))},{position:11n,payload_hex:hex(encodeLifeSet(2,5))}];
  h.prepare(seal(h,cmds),cmds);h.advance(1,2);
  const cur=LifeInputKernel.restore(unhex(h.store.read().stage.cursor_hex),h.store.read().stage.cursor_hash);
  assert.equal(cur.state.cells[5],2);
});
test('journal normalizes only committed input fields before durable staging',()=>{
  const h=fresh(),cmd={position:'10',payload_hex:hex(encodeLifeSet(1,5)),transport_hint:'untrusted'};
  h.prepare(seal(h,[cmd]),[cmd]);
  assert.deepEqual(h.store.read().stage.inputs,[{position:10n,payload_hex:cmd.payload_hex}]);
  h.advance(1,1);
  const stage=h.store.read().stage,cur=LifeInputKernel.restore(unhex(stage.cursor_hex),stage.cursor_hash);
  assert.equal(cur.state.cells[5],1);
});
