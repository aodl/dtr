import test from 'node:test';
import assert from 'node:assert/strict';
import {IC_ROOT_KEY} from '@icp-sdk/core/agent';
import {certificateRoot,certificateVerifier,liveClient,localCertificateVerifier,localLiveClient} from '../../packages/client/ic-certificate.mjs';

test('mainnet pins SDK root and rejects endpoint-supplied substitutes',async()=>{
 assert.equal(Buffer.from(certificateRoot({network:'ic'})).toString('hex'),IC_ROOT_KEY);
 for(const network of ['ic','other',undefined])assert.throws(()=>certificateRoot({network,rootKey:new Uint8Array(133)}));
 assert.throws(()=>certificateVerifier({network:'ic',maxAgeInMinutes:0}));
 await assert.rejects(liveClient({network:'ic',canister_id:'aaaaa-aa',host:'http://localhost:8000'}),/endpoint/);
 await assert.rejects(liveClient({network:'ic',rootKey:new Uint8Array(133),canister_id:'aaaaa-aa',host:'https://icp-api.io'}),/override/);
});
test('local compatibility cannot select mainnet or mutate pinned roots',async()=>{
 const root=new Uint8Array(133).fill(4),pinned=certificateRoot({network:'pocketic-local',rootKey:root});root.fill(5);assert.equal(pinned[0],4);
 assert.throws(()=>localCertificateVerifier(root,{network:'ic'}),/local/);
 await assert.rejects(localLiveClient(root,{network:'ic'}),/local/);
 assert.throws(()=>certificateRoot({network:'pocketic-local'}),/required/);
 const verify=certificateVerifier({network:'ic'});
 await assert.rejects(verify(Uint8Array.of(1),{network:'pocketic-local',canister_id:'aaaaa-aa'}),/network mismatch/);
 await assert.rejects(verify(Uint8Array.of(1),{network:'ic',canister_id:'aaaaa-aa'}));
});
