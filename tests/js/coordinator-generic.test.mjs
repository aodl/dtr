import test from 'node:test';
import assert from 'node:assert/strict';
import {TimelineCoordinator} from '../../packages/runtime/coordinator.mjs';
import {sha256} from '../../packages/runtime/seal.mjs';
import {board,encodeBoard} from '../../packages/kernels/life.mjs';
import {LifeInputKernel,encodeLifeSet} from '../../packages/kernels/life-input.mjs';
import {hex} from '../../packages/protocol/bytes.mjs';

const identity={source_id:'01'.repeat(32),rules_hash:'02'.repeat(32),config_hash:'03'.repeat(32),schema_hash:'04'.repeat(32)};
function fresh(){return TimelineCoordinator.create(encodeBoard(board(4,4,Array(16).fill(0))),identity,{logical_start:0n,source_from:0n},LifeInputKernel);}
function restore(host){const bytes=host.snapshot();return TimelineCoordinator.restore(bytes,sha256(bytes),LifeInputKernel);}
function finish(host,budget){while(host.status().phase==='running'){host.advance(budget);host=restore(host);}return host;}

test('generic coordinator is interruption and work-budget invariant',()=>{
  const outputs=[];
  for(const budget of [1,7,100000]){
    let host=fresh(),records=[hex(encodeLifeSet(1,5)),null,hex(encodeLifeSet(2,6))];
    host.ingestPrefix(0n,records,'aa'.repeat(32));host.seal(2n);host=finish(host,budget);host.publish(host.status().ready_hash);
    outputs.push(host.committed());
  }
  assert.deepEqual(outputs[0],outputs[1]);assert.deepEqual(outputs[1],outputs[2]);
});

test('later inputs remain pending and stale proposals cannot overwrite a seal',()=>{
  let host=fresh();host.ingestPrefix(0n,[null],'aa'.repeat(32));
  const stale=host.propose({kind:'ingest',start:1n,records:[hex(encodeLifeSet(1,5))],anchor:'bb'.repeat(32)});
  host.seal(1n);const sealed=host.snapshot();assert.throws(()=>host.commit(stale),/stale/);assert.deepEqual(host.snapshot(),sealed);
  host=finish(host,1);host.publish(host.status().ready_hash);assert.equal(host.status().pending_inputs,0);
});

test('ordered sparse ranges preserve original IDs and interrupted admission fences',()=>{
  let h=fresh();const inputs=[100n,109n,800n].map(position=>({position,payload_hex:hex(encodeLifeSet(1,5))}));
  assert.throws(()=>h.ingestOrdered(0n,801n,inputs,'aa'.repeat(32),'after'),/lost commit/);
  h=restore(h);assert.equal(h.status().ingest_head,801n);assert.equal(h.status().pending_inputs,3);
  assert.throws(()=>h.ingestOrdered(0n,801n,inputs,'aa'.repeat(32)),/prefix/);
  h.seal(2n);h=finish(h,1);h.publish(h.status().ready_hash);
  assert.deepEqual(h.committed().seal.input_count,3);
  h.ingestOrdered(801n,1000000000n,[],'bb'.repeat(32));h=restore(h);
  assert.equal(h.status().pending_inputs,0);
});
test('ordered validation rejects gaps in the contract, not gaps in IDs, without progress',()=>{
 const h=fresh(),saved=h.snapshot(),row=position=>({position,payload_hex:'aa'});
 for(const [start,end,inputs] of [[1n,2n,[row(1n)]],[0n,2n,[row(1n),row(1n)]],[0n,3n,[row(2n),row(1n)]],
   [0n,2n,[row(2n)]],[0n,0n,[]],[0n,1n,[{position:0n,payload_hex:'aa'.repeat(1025)}]],
   [0n,1n<<64n,[]],[0n,1n,Array(257).fill(row(0n))]]) {
   assert.throws(()=>h.ingestOrdered(start,end,inputs,'aa'.repeat(32)));assert.deepEqual(h.snapshot(),saved);
 }
 for(let n=0;n<16;n++){const start=BigInt(n*256);h.ingestOrdered(start,start+256n,Array.from({length:256},(_,i)=>row(start+BigInt(i))),'aa'.repeat(32));}
 const full=h.snapshot();assert.throws(()=>h.ingestOrdered(4096n,4097n,[row(4096n)],'aa'.repeat(32)),/backpressure/);assert.deepEqual(h.snapshot(),full);
});
