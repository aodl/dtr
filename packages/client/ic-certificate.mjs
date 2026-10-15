/** Standard IC certificate verification for an explicitly configured network.
 *
 * The root key is supplied by the deployment harness. This module never asks
 * an endpoint for a replacement root key and never disables time checks.
 */
import {Actor,Certificate,HttpAgent,IC_ROOT_KEY,lookupResultToBuffer} from '@icp-sdk/core/agent';
import {IDL} from '@icp-sdk/core/candid';
import {Principal} from '@icp-sdk/core/principal';
import {hex} from '../protocol/bytes.mjs';

function unsignedLeb128(bytes){
  if(!(bytes instanceof Uint8Array)||bytes.length===0||bytes.length>10)throw new Error('certificate time encoding');
  let value=0n,shift=0n;
  for(let i=0;i<bytes.length;i++){
    const byte=bytes[i];value|=BigInt(byte&0x7f)<<shift;
    if((byte&0x80)===0){if(i!==bytes.length-1||value>=(1n<<64n))throw new Error('certificate time encoding');return value;}
    shift+=7n;
  }
  throw new Error('certificate time encoding');
}

/** Configuration is trusted application input, never URL/query/server policy. */
export function certificateRoot({network,rootKey}={}) {
  if(network==='ic') {
    if(rootKey!==undefined)throw new Error('mainnet root override forbidden');
    return Uint8Array.from(IC_ROOT_KEY.match(/../g),part=>parseInt(part,16));
  }
  if(network!=='pocketic-local'||!(rootKey instanceof Uint8Array)||rootKey.length<32||rootKey.length>1024)
    throw new Error('configured local root required');
  return Uint8Array.from(rootKey);
}
export function certificateVerifier({network,rootKey,maxAgeInMinutes=5}={}){
  const pinnedRoot=certificateRoot({network,rootKey});
  if(!Number.isFinite(maxAgeInMinutes)||maxAgeInMinutes<=0||maxAgeInMinutes>10)
    throw new Error('certificate freshness policy');
  return async (certificateBytes,deployment)=>{
    if(deployment.network!==network)throw new Error('certificate network mismatch');
    const canister=Principal.fromText(deployment.canister_id);
    const certificate=await Certificate.create({
      certificate:certificateBytes,
      rootKey:pinnedRoot,
      principal:{canisterId:canister},
      maxAgeInMinutes,
    });
    const certified=lookupResultToBuffer(certificate.lookup_path(['canister',canister.toUint8Array(),'certified_data']));
    const time=lookupResultToBuffer(certificate.lookup_path(['time']));
    if(!(certified instanceof Uint8Array)||certified.length!==32||!(time instanceof Uint8Array))
      throw new Error('certificate required path missing');
    return {canister_id:canister.toText(),network,certified_data_hex:hex(certified),certificate_time_ns:unsignedLeb128(time)};
  };
}

const observationIdl=IDL.Record({publication:IDL.Vec(IDL.Nat8),certificate:IDL.Opt(IDL.Vec(IDL.Nat8))});
const retainedEntryIdl=IDL.Record({segment_id:IDL.Nat64,publication_hash:IDL.Text,bytes:IDL.Nat64,current:IDL.Bool});
const retentionIdl=IDL.Record({max_segments:IDL.Nat16,max_bytes:IDL.Nat64,retained_bytes:IDL.Nat64,entries:IDL.Vec(retainedEntryIdl)});
const result=ok=>IDL.Variant({Ok:ok,Err:IDL.Text});
const idlFactory=({IDL})=>IDL.Service({
  observation:IDL.Func([],[result(observationIdl)],['query']),
  artifact_chunk:IDL.Func([IDL.Text,IDL.Nat8,IDL.Nat16],[result(IDL.Vec(IDL.Nat8))],['query']),
  retention_status:IDL.Func([],[result(retentionIdl)],['query']),
  retained_publication:IDL.Func([IDL.Nat64],[result(IDL.Vec(IDL.Nat8))],['query']),
  retained_artifact_chunk:IDL.Func([IDL.Nat64,IDL.Text,IDL.Nat8,IDL.Nat16],[result(IDL.Vec(IDL.Nat8))],['query']),
});
function unwrap(value){if(value&&Object.hasOwn(value,'Ok'))return value.Ok;throw new Error(String(value?.Err??'local IC query result'));}
function safe(value,label){const n=Number(value);if(!Number.isSafeInteger(n)||n<0)throw new Error(`local IC ${label}`);return n;}
/** Read-only actor for a specifically configured disposable local network.
 * The SDK receives the already pinned root and is forbidden from fetching a replacement.
 */
export async function liveClient({network,rootKey,canister_id,host=globalThis.location?.origin}={}){
  const pinnedRoot=certificateRoot({network,rootKey});
  if(typeof canister_id!=='string'||!canister_id||typeof host!=='string'||!host)throw new Error('live client configuration');
  const endpoint=new URL(host);
  if(network==='ic'&&(endpoint.protocol!=='https:'||endpoint.username||endpoint.password))throw new Error('mainnet endpoint policy');
  const agent=await HttpAgent.create({host,rootKey:pinnedRoot,shouldFetchRootKey:false,shouldSyncTime:false,
    verifyQuerySignatures:true,retryTimes:1});
  const actor=Actor.createActor(idlFactory,{agent,canisterId:Principal.fromText(canister_id)});
  return Object.freeze({
    async observation(){const value=unwrap(await actor.observation());return {publication:Uint8Array.from(value.publication),
      certificate:value.certificate.length?Uint8Array.from(value.certificate[0]):null};},
    async retention(){const value=unwrap(await actor.retention_status());return {max_segments:safe(value.max_segments,'retention count'),
      max_bytes:safe(value.max_bytes,'retention bytes'),retained_bytes:safe(value.retained_bytes,'retained bytes'),entries:value.entries.map(entry=>({
        segment_id:safe(entry.segment_id,'segment id'),publication_hash:entry.publication_hash,bytes:safe(entry.bytes,'entry bytes'),current:entry.current}))};},
    async publication(segment){return Uint8Array.from(unwrap(await actor.retained_publication(BigInt(safe(segment,'segment id')))));},
    async currentChunk(publication,kind,index){return Uint8Array.from(unwrap(await actor.artifact_chunk(
      publication,safe(kind,'artifact kind'),safe(index,'chunk index'))));},
    async chunk(segment,publication,kind,index){return Uint8Array.from(unwrap(await actor.retained_artifact_chunk(
      BigInt(safe(segment,'segment id')),publication,safe(kind,'artifact kind'),safe(index,'chunk index'))));},
  });
}

// Compatibility wrappers share the implementation; local roots never become mainnet roots.
export function localCertificateVerifier(rootKey,options={}) {
  if(options.network!==undefined&&options.network!=='pocketic-local')throw new Error('local certificate policy');
  return certificateVerifier({...options,network:'pocketic-local',rootKey});
}
export async function localLiveClient(rootKey,options={}) {
  if(options.network!==undefined&&options.network!=='pocketic-local')throw new Error('local live client configuration');
  return liveClient({...options,network:'pocketic-local',rootKey});
}
