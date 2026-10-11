import test from'node:test';import assert from'node:assert/strict';import{readFileSync}from'node:fs';
import{encodeSeal,HASH_FIELDS,sha256,inputRoot,makeSeal,checkSuccessor}from'../../packages/runtime/seal.mjs';import{hex}from'../../packages/protocol/bytes.mjs';
function sample(){return {segment_id:'0',logical_start:'0',logical_end:'10',source_from:'100',source_to_exclusive:'110',input_count:2,...Object.fromEntries(HASH_FIELDS.map((k,i)=>[k,(i+1).toString(16).padStart(2,'0').repeat(32)]))};}
test('Python canonical seal golden bytes',()=>assert.equal(hex(encodeSeal(sample())),readFileSync(new URL('../fixtures/seal.hex',import.meta.url),'utf8').trim()));
test('Python seal SHA256 agrees',()=>assert.equal(sha256(encodeSeal(sample())),readFileSync(new URL('../fixtures/seal.sha256',import.meta.url),'utf8').trim()));
test('incomplete cursor cannot seal inputs',()=>assert.throws(()=>makeSeal(sample(),[],'109'),/not fully/));
test('empty epochs still have canonical commitment',()=>{const s=makeSeal({...sample(),source_to_exclusive:'100'},[],'100');assert.equal(s.input_count,0);assert.equal(encodeSeal(s).length,308);});
for(const positions of[['101','101'],['102','101'],['99'],['110']])test(`invalid inputs ${positions}`,()=>assert.throws(()=>inputRoot(positions.map(position=>({position,payload_hex:'00'})),100,110)));
test('payload change changes root',()=>assert.notEqual(inputRoot([{position:'100',payload_hex:'00'}],100,110),inputRoot([{position:'100',payload_hex:'01'}],100,110)));
test('seal cannot move logical time backwards',()=>assert.throws(()=>encodeSeal({...sample(),logical_end:'0'})));
test('successor checks source interval and previous hashes',()=>{const p=sample(),n={...p,segment_id:'1',logical_start:'10',logical_end:'20',source_from:'110',source_to_exclusive:'120',previous_state:'11'.repeat(32),previous_manifest:'22'.repeat(32)};checkSuccessor(p,n,n.previous_manifest,n.previous_state);assert.throws(()=>checkSuccessor(p,{...n,source_from:'111'},n.previous_manifest,n.previous_state));});
