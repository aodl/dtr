import test from 'node:test';
import assert from 'node:assert/strict';
import {encodeCanonical, decodeCanonical} from '../../packages/runtime/canonical.mjs';
const text = s => new TextEncoder().encode(s);
test('typed canonical JSON preserves bigint, sorts fields, distinguishes strings/numbers', () => {
  const v = {z: 12n, a: [true, null, '12', 12]};
  assert.equal(new TextDecoder().decode(encodeCanonical(v)), '{"a":[true,null,"12",12],"z":{"$integer":"12"}}');
  assert.deepEqual(decodeCanonical(encodeCanonical(v)), v);
});
for (const [name,value] of [['fraction',1.5],['nan',NaN],['infinity',Infinity],['negative-zero',-0],['unsafe',2**53],['undefined',undefined],['map',new Map()],['sparse',new Array(2)],['reserved',{$integer:'1'}],['surrogate','\ud800']])
  test(`canonical rejects ${name}`,()=>assert.throws(()=>encodeCanonical(value)));
for (const s of ['{ "a":1}','{"b":1,"a":2}','{"a":1,"a":2}','{"$integer":"01"}','{"$integer":"-0"}','{"$integer":"1","x":2}','-0','1.0','{"__proto__":{}}'])
  test(`canonical rejects wire ${s}`,()=>assert.throws(()=>decodeCanonical(text(s))));
test('canonical limits nesting',()=>{let x=0;for(let i=0;i<60;i++)x=[x];assert.throws(()=>encodeCanonical(x),/limit/);});

test('reject byte-order mark rather than dropping it during canonical decoding',()=>{const bytes=Uint8Array.of(239,187,191,...text('{"a":1}'));assert.throws(()=>decodeCanonical(bytes));});
test('reject sparse array even when a named property disguises key count',()=>{const v=[1,,];v.named=2;assert.throws(()=>encodeCanonical(v),/array/);});
