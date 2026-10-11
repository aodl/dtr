import test from 'node:test';
import assert from 'node:assert/strict';
import {canonicalInputs, inputRoot} from '../../packages/runtime/seal.mjs';

test('equivalent source-position representations have one canonical kernel envelope', () => {
  const expected = [{position: 10n, payload_hex: '01'}];
  for (const position of [10, '10', 10n]) {
    const input = [{position, payload_hex: '01', uncommitted_hint: {arbitrary: true}}];
    assert.deepEqual(canonicalInputs(input), expected);
    assert.equal(inputRoot(input, 10n, 11n), inputRoot(expected, 10n, 11n));
    assert('uncommitted_hint' in input[0], 'normalization does not mutate the adapter record');
  }
});
test('canonical envelopes reject duplicates, oversized payloads and oversized batches', () => {
  assert.throws(() => canonicalInputs([{position: 1n, payload_hex: ''}, {position: '1', payload_hex: ''}]));
  assert.throws(() => canonicalInputs([{position: 0, payload_hex: '00'.repeat(1025)}]));
  assert.throws(() => canonicalInputs(Array(4097).fill({position: 0, payload_hex: ''})));
  assert.throws(() => canonicalInputs([{position: Number.MAX_SAFE_INTEGER + 1, payload_hex: ''}]));
});
