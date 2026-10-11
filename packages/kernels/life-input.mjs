/** Paid-input transport is game-specific; these are synthetic Life mutation commands, not money. */
import {ascii, be, concat, hex, Reader, unhex, uint} from '../protocol/bytes.mjs';
import {decodeBoard, encodeBoard, LifeCursor} from './life.mjs';
import {decodeCanonical, encodeCanonical} from '../runtime/canonical.mjs';
import {sha256} from '../runtime/seal.mjs';
export function encodeLifeSet(owner, cell) { return concat(ascii('LIFESET1'), be(owner, 2), be(cell, 4)); }
function decodeSet(bytes) {
  const r = new Reader(bytes, 14);
  if (hex(r.take(8)) !== hex(ascii('LIFESET1'))) throw new Error('invalid command');
  const owner = Number(r.integer(2)), cell = Number(r.integer(4)); r.end(); return {owner, cell};
}
export class LifeInputCursor {
  constructor(bytes, inputs, seal) {
    this.state = decodeBoard(bytes); this.inputs = inputs; this.index = 0; this.receipts = []; this.inner = null;
    this.steps = Number(uint(seal.logical_end) - uint(seal.logical_start));
    if (this.state.generation !== uint(seal.logical_start) || this.steps < 1 || this.steps > 32 || inputs.length > 4096)
      throw new Error('Life logical context');
  }
  step(budget) {
    if (!Number.isInteger(budget) || budget < 1 || budget > 1000000) throw new Error('work budget');
    let used = 0;
    while (this.index < this.inputs.length && used < budget) {
      const input = this.inputs[this.index]; let reason = 'ACCEPTED';
      try {
        const cmd = decodeSet(unhex(input.payload_hex));
        if (cmd.cell >= this.state.cells.length) reason = 'CELL_RANGE';
        else this.state.cells[cmd.cell] = cmd.owner;
      } catch { reason = 'MALFORMED'; }
      this.receipts.push({position: uint(input.position), reason}); this.index++; used++;
    }
    if (this.index === this.inputs.length) {
      if (!this.inner) this.inner = new LifeCursor(this.state, this.steps);
      if (used < budget) used += this.inner.step(budget - used).used;
    }
    return {used, complete: this.inner?.remaining === 0};
  }
  result() {
    if (!this.inner || this.inner.remaining) throw new Error('incomplete');
    const r = this.inner.result();
    return {...r, events: encodeCanonical({version: 2, receipts: this.receipts, evolution_hex: hex(r.events)})};
  }
  snapshot() {
    return encodeCanonical({version: 2, state_hex: hex(encodeBoard(this.state)), inputs: this.inputs,
      index: this.index, receipts: this.receipts, steps: this.steps,
      inner_hex: this.inner ? hex(this.inner.snapshot()) : null});
  }
  static restore(bytes, trustedHash) {
    if (sha256(bytes) !== trustedHash) throw new Error('Life input snapshot hash');
    const p = decodeCanonical(bytes);
    if (p.version !== 2 || !Number.isInteger(p.index) || p.index < 0 || p.index > p.inputs.length
        || p.receipts.length !== p.index || p.steps < 1 || p.steps > 32
        || (p.inner_hex !== null && p.index !== p.inputs.length)) throw new Error('Life input cursor invariants');
    const c = Object.create(LifeInputCursor.prototype);
    Object.assign(c, {state: decodeBoard(unhex(p.state_hex)), inputs: p.inputs, index: p.index,
      receipts: p.receipts, steps: p.steps, inner: p.inner_hex === null ? null : LifeCursor.restore(unhex(p.inner_hex), sha256(unhex(p.inner_hex)))});
    return c;
  }
}
export const LifeInputKernel = {begin: (s, i, c) => new LifeInputCursor(s, i, c), restore: LifeInputCursor.restore,
  fork: cursor => {
    const next = Object.assign(Object.create(LifeInputCursor.prototype), structuredClone({...cursor}));
    if (next.inner) Object.setPrototypeOf(next.inner, LifeCursor.prototype);
    return next;
  }};
