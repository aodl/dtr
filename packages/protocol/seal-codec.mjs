/** Pure seal/input codecs shared by authoritative and browser verification code. */
import {ascii,be,concat,hex,uint,unhex} from "./bytes.mjs";
export const HASH_FIELDS = ['source_id','source_anchor','rules_hash','config_hash','schema_hash','previous_state','previous_manifest','input_root'];
export function encodeSeal(seal) {
  const [id,start,end,from,to] = ['segment_id','logical_start','logical_end','source_from','source_to_exclusive'].map(k => uint(seal[k]));
  const count = uint(seal.input_count,32);
  if (end <= start || to < from || count > to-from || count > 4096n) throw new Error('invalid seal bounds');
  return concat(ascii(Object.hasOwn(seal,'epoch_hash')?'DTRSEAL2':'DTRSEAL1'), ...[id,start,end,from,to].map(n=>be(n,8)), be(count,4), ...HASH_FIELDS.map(k=>unhex(seal[k],32)),...(Object.hasOwn(seal,'epoch_hash')?[unhex(seal.epoch_hash,32)]:[]));
}
/** Only committed envelope fields reach a kernel; transport metadata has no authority. */
export function canonicalInputs(inputs) {
  if (!Array.isArray(inputs) || inputs.length > 4096) throw new Error('input bounds');
  let prior = null;
  return inputs.map(input => {
    const position = uint(input.position), payload = unhex(input.payload_hex);
    if (payload.length > 1024 || (prior !== null && position <= prior)) throw new Error('unordered/oversize input');
    prior = position;
    return {position, payload_hex: hex(payload)};
  });
}
