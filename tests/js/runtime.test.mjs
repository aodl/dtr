import test from'node:test';import assert from'node:assert/strict';import{readFileSync}from'node:fs';
import{runSegment}from'../../packages/runtime/runner.mjs';import{makeSeal,sha256,HASH_FIELDS}from'../../packages/runtime/seal.mjs';import{board,encodeBoard,decodeBoard,LifeCursor}from'../../packages/kernels/life.mjs';
const v=JSON.parse(readFileSync(new URL('../fixtures/life.json',import.meta.url),'utf8')).cases.find(c=>c.name==='mixed');
const state=encodeBoard(board(v.width,v.height,v.cells,v.generation));
const seal=makeSeal({segment_id:'0',logical_start:v.generation,logical_end:(BigInt(v.generation)+BigInt(v.steps)).toString(),source_from:'100',source_to_exclusive:'100',...Object.fromEntries(HASH_FIELDS.map(k=>[k,'00'.repeat(32)])),previous_state:sha256(state)},[],'100');
const args={seal,inputs:[],initialState:state,createCursor:(bytes,_inputs,context)=>new LifeCursor(decodeBoard(bytes),Number(BigInt(context.logical_end)-BigInt(context.logical_start)))};
test('generic host commits identical manifest across work partitions',()=>{const a=runSegment({...args,budgets:[1000000]}),b=runSegment({...args,budgets:[1,7,31],restoreCursor:LifeCursor.restore});assert.deepEqual(a.manifest,b.manifest);assert.deepEqual(a.result,b.result);assert(b.slices>a.slices);});
test('wrong previous state fails before invoking kernel',()=>assert.throws(()=>runSegment({...args,initialState:Uint8Array.of(0)}),/initial state/));
test('unsealed command cannot be injected',()=>assert.throws(()=>runSegment({...args,inputs:[{position:'100',payload_hex:'00'}]}),/sealed inputs/));
test('budget exhaustion publishes no partial manifest',()=>assert.throws(()=>runSegment({...args,budgets:[1],maxSlices:1}),/no commit/));
test('zero-work malicious kernel cannot spin forever',()=>assert.throws(()=>runSegment({...args,createCursor:()=>({step:()=>({complete:false,used:0})})}),/progress/));
test('excess-work report rejected',()=>assert.throws(()=>runSegment({...args,budgets:[1],createCursor:()=>({step:()=>({complete:false,used:2})})}),/progress/));
test('offline host strips uncommitted metadata and normalizes source positions',()=>{
  const inputs=[{position:'100',payload_hex:'00',hint:'not sealed'}];
  const s=makeSeal({...seal,source_to_exclusive:101n},inputs,101n);
  let called=false;
  runSegment({...args,seal:s,inputs,createCursor:(bytes,normalized,context)=>{
    called=true;assert.deepEqual(normalized,[{position:100n,payload_hex:'00'}]);
    return args.createCursor(bytes,normalized,context);
  }});
  assert(called);
});
