import { createHash } from 'node:crypto';
import { ascii, be, concat, hex, uint, unhex } from '../protocol/bytes.mjs';
export const sha256 = value => createHash('sha256').update(value).digest('hex');
import {encodeSeal, canonicalInputs} from '../protocol/seal-codec.mjs';
export {encodeSeal, canonicalInputs, HASH_FIELDS} from '../protocol/seal-codec.mjs';
export function inputRoot(inputs, from, to) {
  from=uint(from);to=uint(to);
  if (!Array.isArray(inputs) || inputs.length>4096 || to<from) throw new Error('input bounds');
  let prior=null; const parts=[ascii('DTRINPUT1'),be(inputs.length,4)];
  for (const input of inputs) {
    const pos=uint(input.position); const payload=unhex(input.payload_hex);
    if (payload.length>1024 || pos<from || pos>=to || (prior!==null && pos<=prior)) throw new Error('unordered/out-of-range input');
    prior=pos;parts.push(be(pos,8),be(payload.length,4),payload);
  }
  return sha256(concat(...parts));
}
export function makeSeal(fields, inputs, verifiedCursor) {
  if (uint(verifiedCursor)<uint(fields.source_to_exclusive)) throw new Error('input range not fully ingested');
  const out={...fields,input_count:inputs.length,input_root:inputRoot(inputs,fields.source_from,fields.source_to_exclusive)};
  encodeSeal(out); return Object.freeze(out);
}
export function checkSuccessor(previous, next, previousManifestHash, previousStateHash) {
  encodeSeal(previous);encodeSeal(next);
  if (uint(next.segment_id)!==uint(previous.segment_id)+1n || uint(next.logical_start)!==uint(previous.logical_end)
      || uint(next.source_from)!==uint(previous.source_to_exclusive) || next.source_id!==previous.source_id || next.epoch_hash!==previous.epoch_hash
      || next.previous_manifest!==previousManifestHash || next.previous_state!==previousStateHash) throw new Error('broken seal chain');
}
export function manifest(seal, stateBytes, eventBytes, scoreBytes) {
  const sealHash=sha256(encodeSeal(seal)),stateHash=sha256(stateBytes),eventHash=sha256(eventBytes),scoreHash=sha256(scoreBytes);
  const hash=sha256(concat(ascii('DTRMANI1'),...[sealHash,stateHash,eventHash,scoreHash].map(x=>unhex(x,32))));
  return {version:1,seal_hash:sealHash,state_hash:stateHash,event_hash:eventHash,score_hash:scoreHash,manifest_hash:hash};
}
