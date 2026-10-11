import test from'node:test';import assert from'node:assert/strict';import{readFileSync}from'node:fs';
import{board,encodeBoard,decodeBoard,LifeCursor}from'../../packages/kernels/life.mjs';import{sha256}from'../../packages/runtime/seal.mjs';import{hex,concat}from'../../packages/protocol/bytes.mjs';
const cases=JSON.parse(readFileSync(new URL('../fixtures/life.json',import.meta.url),'utf8')).cases;
for(const v of cases)for(const budget of[1,7,1000000])test(`Life Python reference ${v.name} budget=${budget}`,()=>{
 let c=new LifeCursor(board(v.width,v.height,v.cells,v.generation),v.steps);
 while(c.remaining){const p=c.step(budget);assert(p.used>0);const bytes=c.snapshot();c=LifeCursor.restore(bytes,sha256(bytes));assert.deepEqual(c.snapshot(),bytes);}
 const result=c.result();assert.equal(hex(result.state),v.state_hex);assert.equal(hex(result.events),v.events_hex);assert.equal(hex(result.scores),v.scores_hex);
 assert.equal(sha256(result.state),v.state_hash);assert.equal(sha256(result.events),v.events_hash);assert.equal(sha256(result.scores),v.scores_hash);
});
test('zero work leaves cursor byte-identical',()=>{const c=new LifeCursor(board(2,2,[1,1,1,1]),2);const before=c.snapshot();assert.deepEqual(c.step(0),{complete:false,used:0});assert.deepEqual(c.snapshot(),before);assert.throws(()=>c.result(),/incomplete/);});
test('all safe-point interrupts replay identically',()=>{
 const v=cases.find(x=>x.name==='mixed');let c=new LifeCursor(board(v.width,v.height,v.cells,v.generation),v.steps),interrupts=0;
 while(c.remaining){c.step(1);const raw=c.snapshot();c=LifeCursor.restore(raw,sha256(raw));interrupts++;}
 assert.equal(interrupts,v.cells.length*v.steps);assert.equal(hex(c.result().state),v.state_hex);
});
test('snapshots reject tampering against trusted digest',()=>{const c=new LifeCursor(board(2,2,[1,1,1,1]),2);const s=c.snapshot(),h=sha256(s);s[s.length-1]^=1;assert.throws(()=>LifeCursor.restore(s,h),/hash/);});
test('snapshots reject unsupported version even with matching local hash',()=>{const c=new LifeCursor(board(2,2,[1,1,1,1]),2);const s=c.snapshot();s[7]=99;assert.throws(()=>LifeCursor.restore(s,sha256(s)),/version/);});
test('state codec rejects trailing and truncated bytes',()=>{const s=encodeBoard(board(2,2,[1,2,3,0],7));assert.equal(decodeBoard(s).generation,7n);assert.throws(()=>decodeBoard(s.slice(0,-1)));assert.throws(()=>decodeBoard(concat(s,Uint8Array.of(0))));});
test('generation overflow detected before simulation',()=>assert.throws(()=>new LifeCursor(board(1,1,[1],(1n<<64n)-1n),1)));
test('bounds reject zero, huge boards and too many generations',()=>{assert.throws(()=>board(0,3,[]));assert.throws(()=>board(64,64,Array(4096).fill(0)));assert.throws(()=>new LifeCursor(board(1,1,[1]),33));});
test('completed step idempotent and consumes no work',()=>{const c=new LifeCursor(board(1,1,[1]),1);c.step(1);const before=c.snapshot();assert.deepEqual(c.step(99),{complete:true,used:0});assert.deepEqual(c.snapshot(),before);});
test('50 reproducible mixed work schedules agree',()=>{
 let seed=73221;const next=()=>{seed=(Math.imul(seed,1664525)+1013904223)>>>0;return seed;};
 for(let trial=0;trial<50;++trial){const initial=board(5,5,Array.from({length:25},()=>next()%4));const a=new LifeCursor(initial,4);a.step(1000);let b=new LifeCursor(initial,4);
  while(b.remaining){b.step(next()%17);const s=b.snapshot();b=LifeCursor.restore(s,sha256(s));}assert.deepEqual(b.result(),a.result());
 }
});
