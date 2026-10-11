import { uint, unhex } from '../protocol/bytes.mjs';
/** Plan only from a response to the configured ledger, not from a hint/browser. */
export function planQuery(cursor, limit, response) {
  cursor=uint(cursor);limit=uint(limit,32);
  if(limit===0n || limit>256n) throw new Error('page limit');
  const chain=uint(response.chain_length);
  if(chain<cursor) throw new Error('regressed/stale chain length');
  if(chain===cursor) return {kind:'at_tip'};
  const requestEnd=cursor+limit<chain?cursor+limit:chain;
  const ranges=[];
  if(!Array.isArray(response.blocks)||response.blocks.length>256||!Array.isArray(response.archived_blocks)||response.archived_blocks.length>256) throw new Error('oversized/malformed response');
  if(response.blocks.length) {
    const start=uint(response.first_block_index),end=start+BigInt(response.blocks.length);
    ranges.push({kind:'direct',start,end,blocks:response.blocks});
  } // first_block_index is explicitly unspecified when blocks is empty.
  for(const a of response.archived_blocks) {
    const start=uint(a.start),length=uint(a.length),end=start+length;
    if(!length || typeof a.callback?.canister!=='string'||!a.callback.canister.length || a.callback.canister.length>128
      ||typeof a.callback.method!=='string'||!a.callback.method.length||a.callback.method.length>128) throw new Error('invalid archive route');
    ranges.push({kind:'archive',start,end,callback:{...a.callback}});
  }
  ranges.sort((a,b)=>a.start<b.start?-1:a.start>b.start?1:0);
  let previousEnd=cursor;
  for(const r of ranges) {
    if(r.start<cursor||r.end>requestEnd||r.end<r.start||r.start<previousEnd) throw new Error('overlapping/out-of-request ranges');
    previousEnd=r.end;
  }
  const first=ranges.find(r=>r.start===cursor);
  if(!first)return {kind:'retry',reason:'NO_CONTIGUOUS_PREFIX'};
  return {...first,start:first.start.toString(),end:first.end.toString()};
}
/** Pure transition. Persist next_cursor AND effects atomically in the future IC host. */
export function consumePage(cursor, page, classify, maxPage=256) {
  cursor=uint(cursor); const start=uint(page.start),chain=uint(page.chain_length);
  if(!Number.isInteger(maxPage)||maxPage<1||maxPage>256)throw new Error('page limit');
  if(start!==cursor)throw new Error('wrong start / replay / gap');
  if(!Array.isArray(page.blocks)||page.blocks.length>maxPage)throw new Error('page limit');
  const end=start+BigInt(page.blocks.length);
  if(chain<end || end>(1n<<64n)-1n)throw new Error('invalid chain range');
  // Validate everything before returning any transition. Unknown wire operations halt, malformed game memos reject.
  const effects=page.blocks.map((block,i)=>{
    unhex(block.hash,32);
    return {position:(start+BigInt(i)).toString(),block_hash:block.hash,...classify(block.transaction)};
  });
  return {next_cursor:end.toString(),effects};
}
export function validateIndexHintPage(page,start=null,max=256) {
  if(!Number.isInteger(max)||max<1||max>256||!Array.isArray(page.transactions)||page.transactions.length>max)throw new Error('index page limit');
  let last=start===null?null:uint(start);
  for(const tx of page.transactions){const id=uint(tx.id);if(last!==null&&id>=last)throw new Error('index order/exclusive-start');last=id;}
  return page.transactions.map(tx=>uint(tx.id).toString()); // Discovery only; never advances authoritative cursor.
}
