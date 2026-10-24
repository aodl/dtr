import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {TimelineCoordinator} from '../../packages/runtime/coordinator.mjs';
import {encodeCanonical,decodeCanonical} from '../../packages/runtime/canonical.mjs';
import {encodeSeal,sha256} from '../../packages/runtime/seal.mjs';
import {epochPayload} from '../../packages/protocol/epoch-codec.mjs';
import {publication,PublicationWindow} from '../../packages/observation/publication.mjs';
import {verifyPinnedPublication,verifyRetainedPredecessor,verifyCertificatePublication,PublicationSequence,ArtifactAssembler} from '../../packages/client/verification.mjs';
import {hex,unhex} from '../../packages/protocol/bytes.mjs';
import {LifeInputKernel} from '../../packages/kernels/life-input.mjs';
import {board,encodeBoard} from '../../packages/kernels/life.mjs';
const identity={source_id:'01'.repeat(32),rules_hash:'02'.repeat(32),config_hash:'03'.repeat(32),schema_hash:'04'.repeat(32)};
const next={...identity,rules_hash:'05'.repeat(32),schema_hash:'06'.repeat(32)};
const out={state:Uint8Array.of(4),events:Uint8Array.of(7),scores:Uint8Array.of(9)};
class Cursor{
 constructor(done=0){this.done=done;}
 step(budget){const used=Math.min(budget,3-this.done);this.done+=used;return {used,complete:this.done===3};}
 snapshot(){return encodeCanonical({done:this.done});}
 result(){assert.equal(this.done,3);return {state:Uint8Array.of(3),events:Uint8Array.of(6),scores:Uint8Array.of(9)};}
}
const toy={begin:()=>new Cursor(),restore:(b,h)=>{assert.equal(sha256(b),h);return new Cursor(decodeCanonical(b).done);}};
function fresh(){return TimelineCoordinator.create(Uint8Array.of(0),identity,{logical_start:0n,source_from:0n,source_anchor:'00'.repeat(32)},toy);}
function finish(h,end){h.seal(end);while(h.status().phase==='running')h.advance(3);h.publish(h.status().ready_hash);}
function committed(){const h=fresh();h.ingestPrefix(0n,['aa',null],'ab'.repeat(32));finish(h,1n);return h;}
const action=e=>({kind:'transition',epoch:e,state_hex:hex(out.state),event_hex:hex(out.events),score_hex:hex(out.scores)});
const ticket=p=>verifyPinnedPublication(p.bytes,p.sha256);
const rehash=e=>{e.transition_hash=sha256(epochPayload(e));return e;};

test('shared Rust/JS epoch commitments and both seal encodings are byte identical',()=>{
 const f=JSON.parse(readFileSync(new URL('../fixtures/epoch-v1.json',import.meta.url)));
 const h=committed(),old=publication(h.publicationRecord());
 assert.equal(hex(old.bytes),f.previous_publication_hex);
 const e=h.prepareTransition(next,out,'cd'.repeat(32));
 assert.equal(hex(encodeCanonical(e)),f.epoch_hex);
 h.apply(action(e));assert.equal(h.status().version,6);
 assert.equal(hex(publication(h.publicationRecord()).bytes),f.checkpoint_publication_hex);
 finish(h,2n);
 assert.equal(hex(encodeSeal(h.committed().seal)),f.successor_seal_hex);
 assert.equal(hex(publication(h.publicationRecord()).bytes),f.successor_publication_hex);
 assert.equal(encodeSeal(old.data.head.seal).length,308);assert.equal(encodeSeal(h.committed().seal).length,340);
});

test('transition is atomic before/after persistence, idempotent after restore and later seals',()=>{
 for(const fault of ['before','after']){
  let h=committed();const old=h.snapshot(),e=h.prepareTransition(next,out,'cd'.repeat(32));
  assert.throws(()=>h.apply(action(e),fault),/commit/);
  if(fault==='before')assert.deepEqual(h.snapshot(),old);
  h=TimelineCoordinator.restore(h.snapshot(),sha256(h.snapshot()),toy);h.apply(action(e));
  const saved=h.snapshot();h.apply(action(e));assert.deepEqual(h.snapshot(),saved);
  finish(h,2n);h=TimelineCoordinator.restore(h.snapshot(),sha256(h.snapshot()),toy);
  const later=h.snapshot();h.apply(action(e));assert.deepEqual(h.snapshot(),later);
  const second=h.prepareTransition({...next,config_hash:'ff'.repeat(32)},out,'cd'.repeat(32));
  assert.equal(second.version,2);assert.equal(second.transition_index,2n);assert.equal(second.previous_publication_hex,'');
 }
});

test('uncommitted, unfinished, reserved or unretired work cannot change epoch',()=>{
 const states=[fresh(),committed(),committed(),committed()];
 states[1].ingestPrefix(2n,['aa'],'bc'.repeat(32));states[2].seal(2n);states[3].ingestOrdered(2n,10n,[],'bc'.repeat(32));
 for(const h of states){const saved=h.snapshot();assert.throws(()=>h.prepareTransition(next,out,'cd'.repeat(32)),/boundary/);assert.deepEqual(h.snapshot(),saved);}
});

test('wrong predecessor, source, corrupted output and metadata fail without mutation',()=>{
 const h=committed(),e=h.prepareTransition(next,out,'cd'.repeat(32)),saved=h.snapshot();
 for(const mutate of [
  a=>a.epoch.metadata_hash='ee'.repeat(32),a=>a.state_hex='00',
  a=>rehash(Object.assign(a.epoch,{source_cursor:3n})),a=>rehash(Object.assign(a.epoch,{source_anchor:'00'.repeat(32)})),
  a=>{const p=decodeCanonical(unhex(a.epoch.previous_publication_hex));p.head.state_hash='ff'.repeat(32);a.epoch.previous_publication_hex=hex(encodeCanonical(p));rehash(a.epoch);},
  a=>{a.epoch.new_identity.source_id='ff'.repeat(32);rehash(a.epoch);},
  a=>{const p=decodeCanonical(unhex(a.epoch.previous_publication_hex));p.head.seal.previous_manifest='ff'.repeat(32);a.epoch.previous_publication_hex=hex(encodeCanonical(p));rehash(a.epoch);},
 ]){const a=structuredClone(action(e));mutate(a);assert.throws(()=>h.apply(a));assert.deepEqual(h.snapshot(),saved);}
 const other=committed();finish(other,2n);const later=other.prepareTransition(next,out,'cd'.repeat(32));assert.throws(()=>h.apply(action(later)),/predecessor/);
 assert.throws(()=>h.prepareTransition(identity,out,'cd'.repeat(32)),/identity/);
});

test('certified-content chain crosses once, retains predecessor and survives eviction/fresh startup',async()=>{
 const h=committed(),window=new PublicationWindow({maxSegments:2}),old=publication(h.publicationRecord());window.retain(h.publicationRecord());
 const oldCopy=old.bytes.slice(),e=h.prepareTransition(next,out,'cd'.repeat(32));h.apply(action(e));
 const checkpoint=publication(h.publicationRecord());window.retain(h.publicationRecord());
 const seq=new PublicationSequence(),oldTicket=await ticket(old),checkpointTicket=await ticket(checkpoint);
 seq.accept(oldTicket);seq.accept(checkpointTicket);
 const retained=await verifyRetainedPredecessor(old.bytes,checkpointTicket);assert.equal(retained.root_hash,old.sha256);
 const assembler=new ArtifactAssembler(checkpointTicket,'state');await assembler.accept(0,out.state);assert.deepEqual(await assembler.finish(),out.state);
 finish(h,2n);const successor=publication(h.publicationRecord());window.retain(h.publicationRecord());
 seq.accept(await ticket(successor));await verifyRetainedPredecessor(checkpoint.bytes,await ticket(successor));
 assert.throws(()=>window.catalog(old.sha256),/resync/);assert.deepEqual(old.bytes,oldCopy);
 finish(h,3n);const latest=publication(h.publicationRecord());window.retain(h.publicationRecord());
 const freshClient=new PublicationSequence();freshClient.accept(await ticket(latest));
 const behind=new PublicationSequence();behind.accept(oldTicket);const latestTicket=await ticket(latest);assert.throws(()=>behind.accept(latestTicket),/resync/);
 behind.resync(await ticket(latest));assert.equal(behind.last.publication.head.segment_id,3n);
 assert.throws(()=>seq.resync(oldTicket),/changed/);
 // Restore validates the embedded predecessor even when no old publication is retained.
 let record=decodeCanonical(h.snapshot());record.journal.epoch.previous_publication_hex='00';
 const damaged=encodeCanonical(record);assert.throws(()=>TimelineCoordinator.restore(damaged,sha256(damaged),toy));
});

test('client rejects altered epoch commitments, current identity and epoch seal binding',async()=>{
 const h=committed(),e=h.prepareTransition(next,out,'cd'.repeat(32));h.apply(action(e));finish(h,2n);
 const p=publication(h.publicationRecord());
 for(const mutate of [v=>v.epoch.metadata_hash='ff'.repeat(32),v=>v.identity.rules_hash='ff'.repeat(32),v=>v.head.seal.epoch_hash='ff'.repeat(32),v=>v.epoch.previous_publication_hex='00']){
  const v=decodeCanonical(p.bytes);mutate(v);const bytes=encodeCanonical(v);await assert.rejects(verifyPinnedPublication(bytes,sha256(bytes)));
 }
});

test('independent Life kernel runs unchanged before and after an application-supplied epoch',()=>{
 const h=TimelineCoordinator.create(encodeBoard(board(4,4,Array(16).fill(0))),identity,{logical_start:0n,source_from:0n},LifeInputKernel);
 finish(h,1n);const before=unhex(h.committed().state_hex),o={state:before,events:new Uint8Array(),scores:new Uint8Array()};
 const e=h.prepareTransition(next,o,'cd'.repeat(32));h.apply({kind:'transition',epoch:e,state_hex:hex(o.state),event_hex:'',score_hex:''});
 assert.deepEqual(unhex(h.committed().state_hex),before);finish(h,2n);
 assert.equal(h.committed().seal.epoch_hash,e.transition_hash);
 TimelineCoordinator.restore(h.snapshot(),sha256(h.snapshot()),LifeInputKernel);
});

test('second and subsequent generic epochs are bounded, replayable and client-verifiable',async()=>{
 const h=TimelineCoordinator.create(encodeBoard(board(4,4,Array(16).fill(0))),identity,{logical_start:0n,source_from:0n},LifeInputKernel);
 finish(h,1n);let state=unhex(h.committed().state_hex),o={state,events:new Uint8Array(),scores:new Uint8Array()};
 const first=h.prepareTransition(next,o,'a1'.repeat(32));h.apply({kind:'transition',epoch:first,state_hex:hex(state),event_hex:'',score_hex:''});finish(h,2n);
 const beforeSecond=publication(h.publicationRecord()),secondIdentity={...next,config_hash:'07'.repeat(32)};
 state=unhex(h.committed().state_hex);o={state,events:new Uint8Array(),scores:new Uint8Array()};
 const second=h.prepareTransition(secondIdentity,o,'a2'.repeat(32));
 assert.equal(second.version,2);assert.equal(second.transition_index,2n);assert.equal(second.previous_publication_hex,'');
 assert.equal(second.predecessor.publication_hash,beforeSecond.sha256);
 const secondAction={kind:'transition',epoch:second,state_hex:hex(state),event_hex:'',score_hex:''},savedBefore=h.snapshot();
 assert.throws(()=>h.apply(secondAction,'before'),/commit/);assert.deepEqual(h.snapshot(),savedBefore);
 for(const mutate of [e=>e.predecessor.publication_hash='ff'.repeat(32),e=>e.previous_chain_hash='ff'.repeat(32),e=>e.transition_index=3n]){
  const wrong=structuredClone(secondAction);mutate(wrong.epoch);rehash(wrong.epoch);assert.throws(()=>h.apply(wrong),/predecessor|index/);assert.deepEqual(h.snapshot(),savedBefore);
 }
 h.apply(secondAction);
 const secondCheckpoint=publication(h.publicationRecord());assert.equal(secondCheckpoint.data.version,8);
 const sequence=new PublicationSequence(),beforeTicket=await ticket(beforeSecond),secondTicket=await ticket(secondCheckpoint);
 sequence.accept(beforeTicket);sequence.accept(secondTicket);
 assert.equal((await verifyRetainedPredecessor(beforeSecond.bytes,secondTicket)).root_hash,beforeSecond.sha256);
 const fresh=new PublicationSequence();fresh.accept(await ticket(secondCheckpoint));
 finish(h,3n);const beforeThird=publication(h.publicationRecord());sequence.accept(await ticket(beforeThird));
 const thirdIdentity={...secondIdentity,schema_hash:'08'.repeat(32)};state=unhex(h.committed().state_hex);o={state,events:new Uint8Array(),scores:new Uint8Array()};
 const third=h.prepareTransition(thirdIdentity,o,'a3'.repeat(32));
 assert.equal(third.version,2);assert.equal(third.transition_index,3n);
 assert.ok(Math.abs(encodeCanonical(third).length-encodeCanonical(second).length)<512,'epoch proof must not recursively grow');
 h.apply({kind:'transition',epoch:third,state_hex:hex(state),event_hex:'',score_hex:''});
 const thirdCheckpoint=publication(h.publicationRecord()),thirdTicket=await ticket(thirdCheckpoint);
 sequence.accept(thirdTicket);await verifyRetainedPredecessor(beforeThird.bytes,thirdTicket);
 const saved=h.snapshot();h.apply({kind:'transition',epoch:third,state_hex:hex(state),event_hex:'',score_hex:''});assert.deepEqual(h.snapshot(),saved);
});


test('v7 certificate binding is required before cross-epoch sequencing',async()=>{
 const h=committed(),old=publication(h.publicationRecord()),e=h.prepareTransition(next,out,'cd'.repeat(32));h.apply(action(e));
 const p=publication(h.publicationRecord()),policy={canister_id:'toy-canister',network:'pocketic-local',now_ns:1000n,max_age_ns:100n,max_future_ns:10n};
 const verify=root=>async()=>({canister_id:policy.canister_id,network:policy.network,certificate_time_ns:1000n,certified_data_hex:root});
 const before=await verifyCertificatePublication(old.bytes,Uint8Array.of(1),policy,verify(old.sha256));
 const after=await verifyCertificatePublication(p.bytes,Uint8Array.of(2),policy,verify(p.sha256));
 const sequence=new PublicationSequence();sequence.accept(before);sequence.accept(after);
 await assert.rejects(verifyCertificatePublication(p.bytes,Uint8Array.of(2),policy,verify(old.sha256)),/root mismatch/);
 assert.throws(()=>sequence.resync(before),/changed/);
 await assert.rejects(verifyCertificatePublication(p.bytes,Uint8Array.of(2),policy,null),/unavailable/);
});
