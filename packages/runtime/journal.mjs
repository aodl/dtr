import {validateEpochHead} from './epoch.mjs';
import {cloneCanonical, decodeCanonical, encodeCanonical} from './canonical.mjs';
import {hex, unhex, uint} from '../protocol/bytes.mjs';
import {canonicalInputs, checkSuccessor, encodeSeal, inputRoot, manifest, sha256} from './seal.mjs';

/** Atomic-document storage model. Deliberately NOT an IC stable-memory implementation. */
export class AtomicJournalStore {
  constructor(record) { this.record = cloneCanonical(record); }
  read() { return cloneCanonical(this.record); }
  compareSwap(revision, replacement, fault = null) {
    if (this.record.revision !== revision) throw new Error('stale journal revision');
    if (replacement.revision !== revision + 1) throw new Error('revision progression');
    const next = cloneCanonical(replacement);
    if (fault === 'before') throw new Error('injected pre-commit failure');
    this.record = next;
    if (fault === 'after') throw new Error('injected lost commit acknowledgement');
  }
  snapshot() { return encodeCanonical(this.record); }
  static restore(bytes, trustedHash) {
    if (sha256(bytes) !== trustedHash) throw new Error('journal integrity mismatch');
    return new AtomicJournalStore(decodeCanonical(bytes));
  }
}

function validateIdentity(identity) {
  for (const k of ['source_id', 'rules_hash', 'config_hash', 'schema_hash']) unhex(identity[k], 32);
}
function normalizedSeal(seal) {
  encodeSeal(seal);
  const copy = cloneCanonical(seal);
  for (const k of ['segment_id','logical_start','logical_end','source_from','source_to_exclusive']) copy[k] = uint(copy[k]);
  copy.input_count = Number(uint(copy.input_count, 32));
  return copy;
}
function matchIdentity(identity, seal) {
  for (const k of ['source_id', 'rules_hash', 'config_hash', 'schema_hash'])
    if (identity[k] !== seal[k]) throw new Error('unapproved source/rules/config/schema');
}

/**
 * A single in-flight segment, explicit prepare/advance/publish, and revision-fenced proposals.
 * The trusted adapter must persist the whole replacement atomically. Query committed(), never stage.
 */
export class SegmentJournal {
  constructor(store, kernel) {
    this.store = store;
    this.kernel = kernel;
    this.validate();
  }
  static create(initialState, identity, genesis, kernel) {
    validateIdentity(identity);
    const record = {
      version: 2, revision: 0, identity, fence: 0, stage: null,
      head: {segment_id: null, logical_end: uint(genesis.logical_start), source_to_exclusive: uint(genesis.source_from),
        manifest_hash: '00'.repeat(32), state_hash: sha256(initialState), state_hex: hex(initialState), seal: null,
        event_hex: '', score_hex: ''},
    };
    return new SegmentJournal(new AtomicJournalStore(record), kernel);
  }
  validate() {
    const r = this.store.read();
    if (!((r.version===2&&!Object.hasOwn(r,'epoch'))||(r.version===3&&r.epoch)) || !Number.isSafeInteger(r.revision) || r.revision < 0
        || !Number.isSafeInteger(r.fence) || r.fence < 0) throw new Error('journal schema');
    validateIdentity(r.identity);
    if (sha256(unhex(r.head.state_hex)) !== r.head.state_hash) throw new Error('committed state mismatch');
    uint(r.head.logical_end); uint(r.head.source_to_exclusive); unhex(r.head.manifest_hash, 32);
    if(r.epoch)validateEpochHead(r.epoch,r.head,r.identity);
    if (r.head.seal !== null) {
      if(r.head.seal.epoch_hash!==r.epoch?.transition_hash)throw new Error('seal epoch mismatch');
      matchIdentity(r.identity, r.head.seal);
      const m = manifest(r.head.seal, unhex(r.head.state_hex), unhex(r.head.event_hex), unhex(r.head.score_hex));
      if (m.manifest_hash !== r.head.manifest_hash || r.head.segment_id !== uint(r.head.seal.segment_id)
          || r.head.logical_end !== uint(r.head.seal.logical_end)
          || r.head.source_to_exclusive !== uint(r.head.seal.source_to_exclusive)) throw new Error('committed manifest mismatch');
    } else if (!r.epoch && (r.head.segment_id !== null || r.head.manifest_hash !== '00'.repeat(32))) throw new Error('genesis head');
    if (r.stage) {
      this.validateSeal(r, r.stage.seal, r.stage.inputs);
      if (r.stage.fence !== r.fence || !['running','ready'].includes(r.stage.phase)) throw new Error('stage fence/phase');
      if (sha256(unhex(r.stage.cursor_hex)) !== r.stage.cursor_hash) throw new Error('stage cursor mismatch');
      const cursor = this.kernel.restore(unhex(r.stage.cursor_hex), r.stage.cursor_hash);
      if (r.stage.phase === 'ready') {
        const output = cursor.result();
        const m = manifest(r.stage.seal, output.state, output.events, output.scores);
        if (m.manifest_hash !== r.stage.ready_hash) throw new Error('ready manifest mismatch');
      }
    }
  }
  validateSeal(record, seal, inputs) {
    seal = normalizedSeal(seal); matchIdentity(record.identity, seal);
    if(seal.epoch_hash!==record.epoch?.transition_hash)throw new Error('seal epoch mismatch');
    if (seal.previous_state !== record.head.state_hash || seal.previous_manifest !== record.head.manifest_hash)
      throw new Error('seal previous commitment');
    if (record.head.seal) checkSuccessor(record.head.seal, seal, record.head.manifest_hash, record.head.state_hash);
    else if (seal.segment_id !== (record.head.segment_id===null?0n:record.head.segment_id+1n) || seal.logical_start !== record.head.logical_end
      || seal.source_from !== record.head.source_to_exclusive) throw new Error('genesis seal');
    if (seal.input_count !== inputs.length || inputRoot(inputs, seal.source_from, seal.source_to_exclusive) !== seal.input_root)
      throw new Error('sealed input mismatch');
    return seal;
  }
  committed() { return this.store.read().head; }
  prepare(seal, inputs, fault = null) {
    const r = this.store.read();
    if (r.stage) throw new Error('segment already staged');
    seal = this.validateSeal(r, seal, inputs);
    inputs = canonicalInputs(inputs);
    const cursor = this.kernel.begin(unhex(r.head.state_hex), inputs, seal);
    const saved = cursor.snapshot();
    r.fence++;
    r.stage = {phase: 'running', fence: r.fence, seal, inputs: cloneCanonical(inputs),
      cursor_hex: hex(saved), cursor_hash: sha256(saved), ready_hash: null};
    const revision = r.revision; r.revision++;
    this.store.compareSwap(revision, r, fault);
    return r.fence;
  }
  /** Compute against an immutable snapshot; commitProposal may subsequently reject this as stale. */
  proposeStep(fence, budget) {
    if (!Number.isSafeInteger(budget) || budget < 1 || budget > 1000000) throw new Error('work budget');
    const r = this.store.read();
    if (!r.stage || r.stage.phase !== 'running' || r.stage.fence !== fence) throw new Error('inactive fence');
    const cursor = this.kernel.restore(unhex(r.stage.cursor_hex), r.stage.cursor_hash);
    const progress = cursor.step(budget);
    if (!Number.isInteger(progress.used) || progress.used < 0 || progress.used > budget
        || typeof progress.complete !== 'boolean' || (!progress.complete && !progress.used)) throw new Error('kernel progress');
    const saved = cursor.snapshot();
    r.stage.cursor_hex = hex(saved); r.stage.cursor_hash = sha256(saved);
    if (progress.complete) {
      const result = cursor.result();
      r.stage.phase = 'ready';
      r.stage.ready_hash = manifest(r.stage.seal, result.state, result.events, result.scores).manifest_hash;
    }
    const expected = r.revision; r.revision++;
    // Only trusted host code can create/apply proposals: this is not a public untrusted API.
    return {expected, fence, record: r, progress};
  }
  commitProposal(proposal, fault = null) {
    const current = this.store.read();
    if (current.stage?.fence !== proposal.fence) throw new Error('stale operation fence');
    this.store.compareSwap(proposal.expected, proposal.record, fault);
    return proposal.progress;
  }
  advance(fence, budget, fault = null) { return this.commitProposal(this.proposeStep(fence, budget), fault); }
  publish(expectedManifest, fault = null) {
    const r = this.store.read(); unhex(expectedManifest, 32);
    if (!r.stage) {
      if (r.head.manifest_hash === expectedManifest && r.head.seal !== null) return r.head;
      throw new Error('nothing ready to publish');
    }
    if (r.stage.phase !== 'ready' || r.stage.ready_hash !== expectedManifest) throw new Error('wrong/not-ready manifest');
    const cursor = this.kernel.restore(unhex(r.stage.cursor_hex), r.stage.cursor_hash), result = cursor.result();
    const m = manifest(r.stage.seal, result.state, result.events, result.scores);
    if (m.manifest_hash !== expectedManifest) throw new Error('output changed after ready');
    r.head = {segment_id: uint(r.stage.seal.segment_id), logical_end: uint(r.stage.seal.logical_end),
      source_to_exclusive: uint(r.stage.seal.source_to_exclusive), seal: r.stage.seal,
      state_hex: hex(result.state), state_hash: m.state_hash, manifest_hash: m.manifest_hash,
      event_hex: hex(result.events), score_hex: hex(result.scores)};
    r.stage = null; const revision = r.revision; r.revision++;
    this.store.compareSwap(revision, r, fault);
    return r.head;
  }
}
