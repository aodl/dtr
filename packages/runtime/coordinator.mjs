/** S05 atomic, game-independent input/seal/simulation coordinator.
 * Trusted host API: ingestPrefix is NOT a ledger verifier or a public user method.
 * The backing store must atomically commit the whole replacement, or retain the old one.
 */
import {AtomicJournalStore, SegmentJournal} from './journal.mjs';
import {VerifiedInbox} from '../source/inbox.mjs';
import {decodeCanonical, encodeCanonical} from './canonical.mjs';
import {canonicalInputs, encodeSeal, makeSeal, manifest, sha256, inputRoot} from './seal.mjs';
import {hex, unhex, uint} from '../protocol/bytes.mjs';

export const COORDINATOR_VERSION = 5;
export const MAX_COORDINATOR_BYTES = 8 * 1024 * 1024;
const MAX_REVISION = Number.MAX_SAFE_INTEGER;
const ACTION_KEYS={ingest:['kind','start','records','anchor'],ingest_ordered:['kind','start','end','inputs','anchor'],seal:['kind','logical_end'],step:['kind','budget'],publish:['kind','manifest_hash']};
function admit(i,start,end,inputs,anchor) {
  unhex(anchor,32);
  if(start!==i.cursor||!Array.isArray(inputs)||inputs.length>256)throw new Error('source prefix/page');
  for(const input of inputs)if(!input||Object.keys(input).sort().join(',')!=='payload_hex,position')throw new Error('input schema');
  inputs=canonicalInputs(inputs);
  inputRoot(inputs,start,end);
  if(i.pending.length+inputs.length>4096)throw new Error('inbox backpressure');
  if(start===end&&anchor!==i.source_anchor)throw new Error('empty prefix anchor change');
  i.pending.push(...inputs);i.cursor=end;i.source_anchor=anchor;i.revision++;
}
function checkRevision(n) {
  if (!Number.isSafeInteger(n) || n < 0 || n > MAX_REVISION) throw new Error('coordinator revision');
}
function same(a, b) { return sha256(encodeCanonical(a)) === sha256(encodeCanonical(b)); }
function stores(record, kernel) {
  const journal = new SegmentJournal(new AtomicJournalStore(record.journal), kernel);
  const inbox = new VerifiedInbox(new AtomicJournalStore(record.inbox));
  return {journal, inbox};
}
function validate(record, kernel) {
  if (!record || Object.keys(record).sort().join(',') !== 'inbox,journal,revision,version'
      || record.version !== COORDINATOR_VERSION) throw new Error('coordinator schema');
  checkRevision(record.revision);
  checkRevision(record.journal.revision); checkRevision(record.journal.fence); checkRevision(record.inbox.revision);
  const pair = stores(record, kernel), j = record.journal, i = record.inbox;
  if (j.identity.source_id !== i.source_id || uint(j.head.source_to_exclusive) !== uint(i.retired_to))
    throw new Error('coordinator source/head divergence');
  if (i.last_ack !== (j.head.seal === null ? null : j.head.manifest_hash)) throw new Error('coordinator acknowledgement divergence');
  if (Boolean(j.stage) !== Boolean(i.reservation)) throw new Error('coordinator reservation divergence');
  if (j.stage) {
    if (sha256(encodeSeal(j.stage.seal)) !== i.reservation.seal_hash
        || !same(j.stage.inputs, pair.inbox.selection(j.stage.seal.source_to_exclusive)))
      throw new Error('coordinator reserved inputs divergence');
  }
  if (encodeCanonical(record).length > MAX_COORDINATOR_BYTES) throw new Error('coordinator byte capacity');
  return pair;
}

/** Typed, single-document reference store. No JSON round trips on reads.
 * Persistence/export still validates canonical bounds. This is NOT IC stable storage.
 */
class CoordinatorStore {
  #record;
  constructor(record) { this.#record = structuredClone(record); }
  read() { return structuredClone(this.#record); }
  get revision() { return this.#record.revision; }
  committed() {return structuredClone(this.#record.journal.head);}
  publicRecord() {return structuredClone({version:5,journal:{identity:this.#record.journal.identity,head:this.#record.journal.head}});}
  status() {
    const r=this.#record;
    return {version:5,revision:r.revision,phase:r.journal.stage?.phase??'idle',ingest_head:r.inbox.cursor,
      retired_to:r.inbox.retired_to,pending_inputs:r.inbox.pending.length,segment_id:r.journal.head.segment_id,
      logical_end:r.journal.head.logical_end,manifest_hash:r.journal.head.manifest_hash,ready_hash:r.journal.stage?.ready_hash??null};
  }
  snapshot() { return encodeCanonical(this.#record); }
  compareSwap(expected, next, fault) {
    if (this.#record.revision !== expected) throw new Error('stale coordinator revision');
    if (next.revision !== expected + 1) throw new Error('revision progression');
    // Exactly one host-size check per replacement, not at every nested accessor.
    if (encodeCanonical(next).length > MAX_COORDINATOR_BYTES) throw new Error('coordinator byte capacity');
    const owned = structuredClone(next);
    if (fault === 'before') throw new Error('injected pre-commit failure');
    this.#record = owned;
    if (fault === 'after') throw new Error('injected lost commit acknowledgement');
  }
}

export class TimelineCoordinator {
  #proposals = new WeakMap();
  #cursor = null;
  #cursorHash = null;
  constructor(store, kernel) {
    const r = store.read(); validate(r, kernel); // Full validation at import, not per step.
    this.store = new CoordinatorStore(r); this.kernel = kernel;
  }
  static create(initialState, identity, genesis, kernel) {
    const journal = SegmentJournal.create(initialState, identity, genesis, kernel).store.read();
    const inbox = VerifiedInbox.create(identity.source_id, genesis.source_from, genesis.source_anchor ?? '00'.repeat(32)).store.read();
    return new TimelineCoordinator(new CoordinatorStore({version:5, revision:0, journal, inbox}), kernel);
  }
  static restore(bytes, trustedHash, kernel) {
    if (!(bytes instanceof Uint8Array) || bytes.length > MAX_COORDINATOR_BYTES || sha256(bytes) !== trustedHash)
      throw new Error('coordinator integrity');
    return new TimelineCoordinator(new CoordinatorStore(decodeCanonical(bytes)), kernel);
  }
  snapshot() { return this.store.snapshot(); }
  committed() { return this.store.committed(); }
  /** Public producer input without private cursor/inbox payload copies. */
  publicationRecord() {return this.store.publicRecord();}
  status() {return this.store.status();}
  /** Trusted synchronous orchestration; one outer fence, no nested store transactions. */
  propose(action) {
    const allowed=ACTION_KEYS[action?.kind];
    if (!allowed || Object.keys(action).sort().join(',')!==allowed.slice().sort().join(','))
      throw new Error('coordinator action schema');
    const r=this.store.read(), j=r.journal, i=r.inbox, expected=r.revision;
    if ([r.revision,j.revision,j.fence,i.revision].some(n=>n===MAX_REVISION)) throw new Error('coordinator revision exhausted');
    let progress=null, unchanged=false, cursor=null;
    switch(action.kind) {
      case 'ingest': {
        const start=uint(action.start), records=action.records; unhex(action.anchor,32);
        if (start!==i.cursor || !Array.isArray(records) || records.length>256) throw new Error('source prefix/page');
        const end=uint(start+BigInt(records.length)), pending=[];
        for (let n=0;n<records.length;n++) {
          if (records[n]===null) continue;
          if (unhex(records[n]).length>1024) throw new Error('input payload size');
          pending.push({position:start+BigInt(n),payload_hex:records[n]});
        }
        admit(i,start,end,pending,action.anchor);
        break;
      }
      case 'ingest_ordered': {
        admit(i,uint(action.start),uint(action.end),action.inputs,action.anchor);
        break;
      }
      case 'seal': {
        if (j.stage || i.reservation) throw new Error('coordinator already sealed');
        const h=j.head, inputs=canonicalInputs(i.pending);
        const seal=makeSeal({...j.identity, segment_id:h.segment_id===null?0n:h.segment_id+1n,
          logical_start:h.logical_end,logical_end:uint(action.logical_end),source_from:h.source_to_exclusive,
          source_to_exclusive:i.cursor,source_anchor:i.source_anchor,previous_state:h.state_hash,
          previous_manifest:h.manifest_hash},inputs,i.cursor);
        // A thrown begin/snapshot leaves the authoritative input reservation untouched.
        cursor=this.kernel.begin(unhex(h.state_hex), inputs, seal);
        const saved=cursor.snapshot(); j.fence++; j.revision++;
        j.stage={phase:'running',fence:j.fence,seal,inputs,cursor_hex:hex(saved),cursor_hash:sha256(saved),ready_hash:null};
        i.reservation={seal:structuredClone(seal),seal_hash:sha256(encodeSeal(seal))}; i.revision++;
        break;
      }
      case 'step': {
        if (!Number.isSafeInteger(action.budget)||action.budget<1||action.budget>1000000) throw new Error('work budget');
        if (!j.stage || j.stage.phase!=='running') throw new Error('inactive fence');
        // Fork trusted typed state instead of repeatedly decoding/validating the same snapshot.
        if (this.#cursorHash===j.stage.cursor_hash && this.#cursor && typeof this.kernel.fork==='function')
          cursor=this.kernel.fork(this.#cursor);
        else cursor=this.kernel.restore(unhex(j.stage.cursor_hex),j.stage.cursor_hash);
        progress=cursor.step(action.budget);
        if (!Number.isInteger(progress.used)||progress.used<0||progress.used>action.budget
            ||typeof progress.complete!=='boolean'||(!progress.complete&&!progress.used)) throw new Error('kernel progress');
        const saved=cursor.snapshot(); j.stage.cursor_hex=hex(saved); j.stage.cursor_hash=sha256(saved);
        if (progress.complete) {
          const out=cursor.result(); j.stage.phase='ready';
          j.stage.ready_hash=manifest(j.stage.seal,out.state,out.events,out.scores).manifest_hash;
        }
        j.revision++; break;
      }
      case 'publish': {
        unhex(action.manifest_hash,32);
        if (!j.stage) {
          if (j.head.seal===null||j.head.manifest_hash!==action.manifest_hash||i.last_ack!==action.manifest_hash)
            throw new Error('nothing ready to publish');
          unchanged=true; break;
        }
        if (j.stage.phase!=='ready'||j.stage.ready_hash!==action.manifest_hash) throw new Error('wrong/not-ready manifest');
        cursor=this.#cursorHash===j.stage.cursor_hash && this.#cursor ? this.#cursor
          : this.kernel.restore(unhex(j.stage.cursor_hex),j.stage.cursor_hash);
        const out=cursor.result(), m=manifest(j.stage.seal,out.state,out.events,out.scores);
        if (m.manifest_hash!==action.manifest_hash) throw new Error('output changed after ready');
        const seal=j.stage.seal;
        j.head={segment_id:uint(seal.segment_id),logical_end:uint(seal.logical_end),source_to_exclusive:uint(seal.source_to_exclusive),
          seal,state_hex:hex(out.state),state_hash:m.state_hash,manifest_hash:m.manifest_hash,event_hex:hex(out.events),score_hex:hex(out.scores)};
        j.stage=null; j.revision++;
        i.pending=i.pending.filter(row=>row.position>=j.head.source_to_exclusive);
        i.retired_to=j.head.source_to_exclusive; i.reservation=null; i.last_ack=m.manifest_hash; i.revision++;
        cursor=null; break;
      }
    }
    if (!unchanged) r.revision++;
    const proposal=Object.freeze({expected,progress:progress===null?null:Object.freeze({...progress}),unchanged});
    this.#proposals.set(proposal,{record:r,cursor,progress,unchanged});
    return proposal;
  }
  commit(proposal,fault=null) {
    const pending=this.#proposals.get(proposal);
    if (!pending) throw new Error('unknown/consumed coordinator proposal');
    this.#proposals.delete(proposal);
    if (this.store.revision!==proposal.expected) throw new Error('stale coordinator revision');
    try { if (!pending.unchanged) this.store.compareSwap(proposal.expected,pending.record,fault); }
    finally {
      // A lost acknowledgement after the root change must still update the cache coherently.
      if (this.store.revision===pending.record.revision && !pending.unchanged) {
        if (pending.cursor) {this.#cursor=pending.cursor;this.#cursorHash=pending.record.journal.stage?.cursor_hash??null;}
        else if (!pending.record.journal.stage) {this.#cursor=null;this.#cursorHash=null;}
      }
    }
    return pending.progress;
  }
  apply(action,fault=null) {return this.commit(this.propose(action),fault);}
  ingestPrefix(start,records,anchor,fault=null) {return this.apply({kind:'ingest',start,records,anchor},fault);}
  ingestOrdered(start,end,inputs,anchor,fault=null) {return this.apply({kind:'ingest_ordered',start,end,inputs,anchor},fault);}
  seal(logicalEnd,fault=null) {return this.apply({kind:'seal',logical_end:logicalEnd},fault);}
  advance(budget,fault=null) {return this.apply({kind:'step',budget},fault);}
  publish(manifestHash,fault=null) {return this.apply({kind:'publish',manifest_hash:manifestHash},fault);}
}
