import test from 'node:test';
import assert from 'node:assert/strict';
import {PlayoutClock} from '../../packages/client/playout.mjs';
test('does not start before headroom is verified and available',()=>{
  const p=new PlayoutClock();p.append(0,4);assert.equal(p.sample(0.1).phase,'BUFFERING');assert.equal(p.playhead,0);
  p.append(4,8);assert.equal(p.sample(0.1).phase,'PLAYING');assert(p.playhead>0);
});
test('shrinking buffer smoothly slows playback without changing any timeline data',()=>{
  const p=new PlayoutClock();p.append(0,8);let previous=0,slow=false;
  for(let i=0;i<100;i++){const s=p.sample(0.05);assert(s.playhead>=previous);previous=s.playhead;if(s.rate<0.999)slow=true;assert(s.rate>=0.97&&s.rate<=1.03);}
  assert(slow);assert.equal(p.available,8);
});
test('exhaustion never extrapolates; recovery uses fresh verified headroom',()=>{
  const p=new PlayoutClock({target:2,low:1});p.append(0,2);
  for(let i=0;i<100;i++)p.sample(0.1);
  assert.equal(p.playhead,2);assert.equal(p.phase,'STALLED');
  p.append(2,2.5);p.sample(0.1);assert.equal(p.playhead,2);
  p.append(2.5,4);p.sample(0.1);assert(p.playhead>2);
});
test('long tab suspension cannot jump unboundedly ahead',()=>{
  const p=new PlayoutClock();p.append(0,100);p.sample(3600);assert(p.playhead<=0.25*1.03);
});
for(const [start,end] of [[1,3],[0,0],[-1,2],[NaN,2],[0,Infinity]])test(`rejects gap/nonfinite range ${start}/${end}`,()=>{
  assert.throws(()=>new PlayoutClock().append(start,end));
});
for(const dt of [-1,NaN,Infinity])test(`rejects invalid frame delta ${dt}`,()=>assert.throws(()=>new PlayoutClock().sample(dt)));
test('very large buffer speeds up within the configured smooth envelope',()=>{
  const p=new PlayoutClock();p.append(0,100);
  for(let i=0;i<100;i++)p.sample(0.1);
  assert(p.rate>1);assert(p.rate<=1.03);
});
