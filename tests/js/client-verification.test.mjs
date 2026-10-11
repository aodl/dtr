import test from 'node:test';
import assert from 'node:assert/strict';
import {TimelineCoordinator} from '../../packages/runtime/coordinator.mjs';
import {decodeCanonical,encodeCanonical} from '../../packages/runtime/canonical.mjs';
import {sha256} from '../../packages/runtime/seal.mjs';
import {board,encodeBoard} from '../../packages/kernels/life.mjs';
import {LifeInputKernel} from '../../packages/kernels/life-input.mjs';
import {publication} from '../../packages/observation/publication.mjs';
import {ArtifactAssembler,PublicationSequence,verifyCertificatePublication,verifyPinnedPublication,verifyRetainedPredecessor} from '../../packages/client/verification.mjs';

const identity={source_id:'01'.repeat(32),rules_hash:'02'.repeat(32),config_hash:'03'.repeat(32),schema_hash:'04'.repeat(32)};
function fresh(){return TimelineCoordinator.create(encodeBoard(board(4,4,Array(16).fill(0))),identity,{logical_start:0n,source_from:0n},LifeInputKernel);}
function complete(host,end){host.seal(end);while(host.status().phase==='running')host.advance(7);host.publish(host.status().ready_hash);}

test('null-render retained predecessors authenticate backward and admit forward',async()=>{
  const host=fresh(),pubs=[publication(host.publicationRecord())];
  for(let end=1n;end<=3n;end++){complete(host,end);pubs.push(publication(host.publicationRecord()));}
  const three=await verifyPinnedPublication(pubs[3].bytes,pubs[3].sha256);
  const two=await verifyRetainedPredecessor(pubs[2].bytes,three);
  const one=await verifyRetainedPredecessor(pubs[1].bytes,two);
  const sequence=new PublicationSequence();sequence.accept(await verifyPinnedPublication(pubs[0].bytes,pubs[0].sha256));
  sequence.accept(one);sequence.accept(two);sequence.accept(three);
  assert.equal(sequence.last.publication.head.segment_id,2n);
});

test('authoritative predecessor commitment changes fail closed',async()=>{
  const host=fresh();complete(host,1n);const prior=publication(host.publicationRecord());complete(host,2n);
  const next=publication(host.publicationRecord());
  const successor=await verifyPinnedPublication(next.bytes,next.sha256);
  for(const kind of ['state','events','scores']){
    const changed=decodeCanonical(prior.bytes),artifact=changed.artifacts.find(a=>a.kind===kind);
    artifact.sha256='ff'.repeat(32);if(artifact.chunks.length)artifact.chunks[0]='ff'.repeat(32);
    await assert.rejects(verifyRetainedPredecessor(encodeCanonical(changed),successor));
  }
});

test('optional render requires a directly authenticated catalog',async()=>{
  const host=fresh();complete(host,1n);const prior=host.publicationRecord();complete(host,2n);
  const next=publication(host.publicationRecord(),{render:{format:'life-view-1',bytes:Uint8Array.of(1)}});
  const successor=await verifyPinnedPublication(next.bytes,next.sha256);
  const altered=publication(prior,{render:{format:'life-view-1',bytes:Uint8Array.of(99)}});
  await assert.rejects(verifyRetainedPredecessor(altered.bytes,successor),/render.*direct/i);

  const policy={canister_id:'test-canister',network:'test',now_ns:1000n,max_age_ns:100n,max_future_ns:10n};
  const direct=await verifyCertificatePublication(altered.bytes,Uint8Array.of(1),policy,async()=>({
    canister_id:policy.canister_id,network:policy.network,certificate_time_ns:1000n,certified_data_hex:altered.sha256,
  }));
  const render=new ArtifactAssembler(direct,'render');await render.accept(0,altered.artifacts[3]);
  assert.deepEqual(await render.finish(),Uint8Array.of(99));
});

test('snapshot resync preserves the session anti-rollback floor',async()=>{
  const host=fresh(),genesis=publication(host.publicationRecord());complete(host,1n);complete(host,2n);
  const latest=publication(host.publicationRecord()),sequence=new PublicationSequence();
  sequence.accept(await verifyPinnedPublication(genesis.bytes,genesis.sha256));
  sequence.resync(await verifyPinnedPublication(latest.bytes,latest.sha256));
  assert.throws(()=>sequence.resync(sequence.last),/rollback/);
});
