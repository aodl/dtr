/** Bounded canonical typed JSON for the offline conformance journal. Not Candid. */
const MAX_BYTES = 16 * 1024 * 1024;
function wire(value, depth, count) {
  if (depth > 48 || ++count.n > 300000) throw new Error('canonical structural limit');
  if (typeof value === 'bigint') {
    if (value.toString().length > 1000) throw new Error('integer length');
    return { $integer: value.toString() };
  }
  if (value === null || typeof value === 'boolean') return value;
  if (typeof value === 'string') {
    if (!value.isWellFormed()) throw new Error('invalid Unicode');
    return value;
  }
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value) || Object.is(value, -0)) throw new Error('noncanonical number');
    return value;
  }
  if (Array.isArray(value)) {
    if (Object.keys(value).length !== value.length || Object.keys(value).some((k, i) => k !== String(i)))
      throw new Error('sparse/decorated array');
    return value.map(v => wire(v, depth + 1, count));
  }
  if (typeof value !== 'object' || Object.getPrototypeOf(value) !== Object.prototype)
    throw new Error('plain object required');
  const out = {};
  for (const key of Object.keys(value).sort()) {
    if (!/^[a-zA-Z][a-zA-Z0-9_]*$/.test(key) || ['constructor', 'prototype', '__proto__'].includes(key))
      throw new Error('reserved/noncanonical object key');
    out[key] = wire(value[key], depth + 1, count);
  }
  return out;
}
export function encodeCanonical(value) {
  const bytes = new TextEncoder().encode(JSON.stringify(wire(value, 0, {n: 0})));
  if (bytes.length > MAX_BYTES) throw new Error('canonical byte limit');
  return bytes;
}
export function decodeCanonical(bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.length > MAX_BYTES) throw new Error('canonical bytes');
  const text = new TextDecoder('utf-8', {fatal: true}).decode(bytes);
  const value = JSON.parse(text, (_key, v) => {
    if (v && !Array.isArray(v) && typeof v === 'object' && Object.hasOwn(v, '$integer')) {
      if (Object.keys(v).length !== 1 || typeof v.$integer !== 'string' || v.$integer.length > 1000
          || !/^(0|-?[1-9][0-9]*)$/.test(v.$integer)) throw new Error('invalid integer tag');
      return BigInt(v.$integer);
    }
    return v;
  });
  const again = encodeCanonical(value);
  if (again.length !== bytes.length || again.some((b, i) => b !== bytes[i])) throw new Error('noncanonical encoding');
  return value;
}
export const cloneCanonical = value => decodeCanonical(encodeCanonical(value));
