/** Strict, length-bounded canonical bytes. All multibyte integers are big-endian. */
export const U64_MAX = (1n << 64n) - 1n;
export function uint(value, bits = 64, name = 'integer') {
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value)) throw new RangeError(`${name}: unsafe integer`);
    value = BigInt(value);
  } else if (typeof value === 'string') {
    if (!/^(0|[1-9][0-9]*)$/.test(value)) throw new RangeError(`${name}: noncanonical decimal`);
    value = BigInt(value);
  }
  if (typeof value !== 'bigint' || value < 0n || value >= (1n << BigInt(bits)))
    throw new RangeError(`${name}: out of u${bits} range`);
  return value;
}
export function hex(bytes) { return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join(''); }
export function unhex(text, length) {
  if (typeof text !== 'string' || !/^(?:[0-9a-f]{2})*$/.test(text)) throw new Error('noncanonical hex');
  if (length !== undefined && text.length !== length * 2) throw new Error('wrong hex length');
  return Uint8Array.from(text.match(/../g) ?? [], s => parseInt(s, 16));
}
export function bytes(value, length) {
  if (!(value instanceof Uint8Array) || (length !== undefined && value.length !== length)) throw new Error('invalid bytes');
  return value;
}
export function concat(...parts) {
  const size = parts.reduce((sum, p) => sum + bytes(p).length, 0);
  if (size > 16 * 1024 * 1024) throw new RangeError('canonical output too large');
  const out = new Uint8Array(size); let at = 0;
  for (const part of parts) { out.set(part, at); at += part.length; } return out;
}
export function be(value, size) {
  let n = uint(value, size * 8); const out = new Uint8Array(size);
  for (let i = size - 1; i >= 0; --i) { out[i] = Number(n & 255n); n >>= 8n; } return out;
}
export function readBE(value) { let n = 0n; for (const b of bytes(value)) n = (n << 8n) | BigInt(b); return n; }
export function ascii(text) { return new TextEncoder().encode(text); }
export class Reader {
  constructor(value, maxBytes = 16 * 1024 * 1024) {
    this.value = bytes(value); if (value.length > maxBytes) throw new RangeError('input too large'); this.at = 0;
  }
  take(n) {
    if (!Number.isSafeInteger(n) || n < 0 || n > this.value.length - this.at) throw new Error('truncated input');
    const out = this.value.slice(this.at, this.at + n); this.at += n; return out;
  }
  integer(size) { return readBE(this.take(size)); }
  end() { if (this.at !== this.value.length) throw new Error('trailing bytes'); }
}
