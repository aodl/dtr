import {cloneCanonical} from '../runtime/canonical.mjs';
import {AtomicJournalStore} from '../runtime/journal.mjs';
import {encodeSeal, inputRoot, manifest, sha256} from '../runtime/seal.mjs';
import {uint, unhex} from '../protocol/bytes.mjs';
/**
 * Durable inbox MODEL fed only by an already-authoritative source adapter.
 * null means an irrelevant source record, never an omitted/gapped source position.
 */
export class VerifiedInbox {
  constructor(store) {
    this.store = store;
    const r = store.read();
    if (r.version !== 2 || r.cursor < r.retired_to || r.pending.length > 4096) throw new Error('inbox schema');
    unhex(r.source_id,32); unhex(r.source_anchor,32);
    inputRoot(r.pending,r.retired_to,r.cursor);
    if (r.reservation) {
      const s=r.reservation.seal;
      if(s.source_id!==r.source_id || uint(s.source_from)!==r.retired_to || uint(s.source_to_exclusive)>r.cursor
          || sha256(encodeSeal(s))!==r.reservation.seal_hash
          || inputRoot(r.pending.filter(i=>uint(i.position)<uint(s.source_to_exclusive)),s.source_from,s.source_to_exclusive)!==s.input_root)
        throw new Error('inbox reservation');
    }
  }
  static create(sourceId, genesisCursor, anchor='00'.repeat(32)) {
    unhex(sourceId,32);unhex(anchor,32);const at=uint(genesisCursor);
    return new VerifiedInbox(new AtomicJournalStore({version:2,revision:0,source_id:sourceId,cursor:at,retired_to:at,
      source_anchor:anchor,pending:[],reservation:null,last_ack:null}));
  }
  proposePage(start, records, verifiedEndAnchor) {
    const r=this.store.read();start=uint(start);unhex(verifiedEndAnchor,32);
    if(start!==r.cursor || !Array.isArray(records) || records.length>256)throw new Error('source prefix/page');
    const end=uint(start+BigInt(records.length));
    const pending=records.flatMap((payload_hex,i)=>{
      if(payload_hex===null)return [];
      if(unhex(payload_hex).length>1024)throw new Error('input payload size');
      return [{position:start+BigInt(i),payload_hex}];
    });
    if(r.pending.length+pending.length>4096)throw new Error('inbox backpressure');
    if(records.length===0 && verifiedEndAnchor!==r.source_anchor)throw new Error('empty prefix anchor change');
    r.pending.push(...pending);r.cursor=end;r.source_anchor=verifiedEndAnchor;
    const expected=r.revision;r.revision++;
    return {expected,record:r};
  }
  commitPage(proposal,fault=null) {this.store.compareSwap(proposal.expected,proposal.record,fault);}
  ingest(start,records,anchor,fault=null) {this.commitPage(this.proposePage(start,records,anchor),fault);}
  selection(cutoff) {
    const r=this.store.read();cutoff=uint(cutoff);
    if(cutoff<r.retired_to||cutoff>r.cursor)throw new Error('unverified cutoff');
    return r.pending.filter(i=>i.position<cutoff);
  }
  reserve(seal,fault=null) {
    const r=this.store.read();encodeSeal(seal);
    if(r.reservation)throw new Error('inbox already reserved');
    const inputs=this.selection(seal.source_to_exclusive);
    if(seal.source_id!==r.source_id||uint(seal.source_from)!==r.retired_to||seal.input_count!==inputs.length
        ||seal.input_root!==inputRoot(inputs,seal.source_from,seal.source_to_exclusive))throw new Error('seal does not cover inbox');
    // For an interior cutoff, the caller must retain/prove its boundary anchor separately.
    if(uint(seal.source_to_exclusive)===r.cursor&&seal.source_anchor!==r.source_anchor)throw new Error('cutoff anchor mismatch');
    r.reservation={seal:cloneCanonical(seal),seal_hash:sha256(encodeSeal(seal))};const rev=r.revision;r.revision++;
    this.store.compareSwap(rev,r,fault);return inputs;
  }
  acknowledge(committedHead,fault=null) {
    const r=this.store.read();
    if(r.last_ack===committedHead.manifest_hash)return false;
    if(!r.reservation||sha256(encodeSeal(committedHead.seal))!==r.reservation.seal_hash)throw new Error('unmatched commit acknowledgement');
    const m=manifest(committedHead.seal,unhex(committedHead.state_hex),unhex(committedHead.event_hex),unhex(committedHead.score_hex));
    if(m.manifest_hash!==committedHead.manifest_hash)throw new Error('invalid commit acknowledgement');
    const cutoff=uint(r.reservation.seal.source_to_exclusive);
    r.pending=r.pending.filter(i=>i.position>=cutoff);r.retired_to=cutoff;r.last_ack=m.manifest_hash;r.reservation=null;
    const rev=r.revision;r.revision++;
    this.store.compareSwap(rev,r,fault);return true;
  }
}
