import {ascii,be,concat,hex,Reader,uint} from '../protocol/bytes.mjs';
import {sha256} from '../runtime/seal.mjs';
export const MAX_CELLS=1024, MAX_GENERATIONS=32;
function dimensions(width,height){
  width=Number(uint(width,16));height=Number(uint(height,16));
  if(!width||!height||width>64||height>64||width*height>MAX_CELLS)throw new Error('Life dimensions');
  return [width,height];
}
export function board(width,height,cells,generation=0n){
  [width,height]=dimensions(width,height);
  if(!Array.isArray(cells)||cells.length!==width*height)throw new Error('Life cell count');
  return {width,height,generation:uint(generation),cells:cells.map(c=>Number(uint(c,16)))};
}
export function encodeBoard(state){
  const b=board(state.width,state.height,state.cells,state.generation);
  return concat(ascii('LIFE0001'),be(b.width,2),be(b.height,2),be(b.generation,8),...b.cells.map(c=>be(c,2)));
}
export function decodeBoard(data){
  const r=new Reader(data,20+MAX_CELLS*2);
  if(hex(r.take(8))!==hex(ascii('LIFE0001')))throw new Error('Life state version');
  const [w,h]=dimensions(r.integer(2),r.integer(2)),g=r.integer(8);
  const cells=Array.from({length:w*h},()=>Number(r.integer(2)));r.end();return board(w,h,cells,g);
}
function evolve(state,index){
  const x=index%state.width,y=Math.floor(index/state.width),neighbors=[];
  for(let dy=-1;dy<=1;++dy)for(let dx=-1;dx<=1;++dx){
    if(!dx&&!dy)continue;const xx=x+dx,yy=y+dy;
    if(xx>=0&&yy>=0&&xx<state.width&&yy<state.height){const owner=state.cells[yy*state.width+xx];if(owner)neighbors.push(owner);}
  }
  const old=state.cells[index];if(old)return neighbors.length===2||neighbors.length===3?old:0;
  if(neighbors.length!==3)return 0;
  neighbors.sort((a,b)=>a-b);
  return neighbors[0]===neighbors[1]?neighbors[0]:neighbors[1]===neighbors[2]?neighbors[1]:neighbors[0];
}
export function encodeEvents(events){
  if(events.length>MAX_CELLS*MAX_GENERATIONS)throw new Error('event limit');
  return concat(ascii('LIFEEVT1'),be(events.length,4),...events.map(e=>concat(be(e.generation,8),be(e.cell,4),be(e.before,2),be(e.after,2))));
}
export function encodeScores(scores){
  const rows=[...scores].sort((a,b)=>a[0]-b[0]);
  if(rows.length>MAX_CELLS)throw new Error('score limit');
  return concat(ascii('LIFESCR1'),be(rows.length,4),...rows.map(([owner,units])=>concat(be(owner,2),be(units,8))));
}
/** One work unit evaluates one cell. The current generation stays immutable until its final cell. */
export class LifeCursor{
  constructor(initial,generations){
    generations=Number(uint(generations,8));if(!generations||generations>MAX_GENERATIONS)throw new Error('generation limit');
    this.state=board(initial.width,initial.height,initial.cells,initial.generation);
    uint(this.state.generation+BigInt(generations));this.start=this.state.generation;this.total=generations;
    this.remaining=generations;this.cell=0;this.next=Array(this.state.cells.length).fill(0);this.events=[];this.scores=new Map();
  }
  step(budget){
    budget=Number(uint(budget,32));let used=0;
    while(this.remaining&&used<budget){
      const i=this.cell,before=this.state.cells[i],after=evolve(this.state,i);
      if(before)this.scores.set(before,(this.scores.get(before)??0n)+1n);
      this.next[i]=after;
      if(before!==after)this.events.push({generation:this.state.generation+1n,cell:i,before,after});
      this.cell++;used++;
      if(this.cell===this.state.cells.length){
        this.state={...this.state,generation:this.state.generation+1n,cells:this.next};
        this.next=Array(this.state.cells.length).fill(0);this.cell=0;this.remaining--;
      }
    }
    return {complete:this.remaining===0,used};
  }
  result(){if(this.remaining)throw new Error('segment incomplete');return {state:encodeBoard(this.state),events:encodeEvents(this.events),scores:encodeScores(this.scores)};}
  snapshot(){
    const b=encodeBoard(this.state),e=encodeEvents(this.events),s=encodeScores(this.scores);
    return concat(ascii('LIFECUR1'),be(b.length,4),b,be(this.total,1),be(this.remaining,1),be(this.start,8),be(this.cell,4),
      ...this.next.map(c=>be(c,2)),be(e.length,4),e,be(s.length,4),s);
  }
  /** expectedHash must come from a trusted snapshot record, not the untrusted payload itself. */
  static restore(data,expectedHash){
    if(sha256(data)!==expectedHash)throw new Error('cursor snapshot hash mismatch');
    const r=new Reader(data,2*1024*1024);
    if(hex(r.take(8))!==hex(ascii('LIFECUR1')))throw new Error('cursor version');
    const b=decodeBoard(r.take(Number(r.integer(4)))),total=Number(r.integer(1)),remaining=Number(r.integer(1)),start=r.integer(8),cell=Number(r.integer(4));
    if(!total||total>MAX_GENERATIONS||remaining>total||cell>=b.cells.length||(!remaining&&cell)||b.generation!==start+BigInt(total-remaining))throw new Error('cursor invariants');
    uint(start+BigInt(total));
    const next=Array.from({length:b.cells.length},()=>Number(r.integer(2)));
    if(next.slice(cell).some(x=>x!==0))throw new Error('unprocessed scratch must be zero');
    const er=new Reader(r.take(Number(r.integer(4))));if(hex(er.take(8))!==hex(ascii('LIFEEVT1')))throw new Error('events version');
    const count=Number(er.integer(4));if(count>MAX_CELLS*MAX_GENERATIONS)throw new Error('events count');
    const events=[];let prior=null;
    for(let i=0;i<count;++i){
      const e={generation:er.integer(8),cell:Number(er.integer(4)),before:Number(er.integer(2)),after:Number(er.integer(2))};
      if(e.cell>=b.cells.length||e.before===e.after||e.generation<=start||e.generation>b.generation+(cell?1n:0n)
        ||(e.generation>b.generation&&e.cell>=cell)|| (prior&&(e.generation<prior.generation||(e.generation===prior.generation&&e.cell<=prior.cell))))throw new Error('events order/range');
      events.push(e);prior=e;
    }er.end();
    const sr=new Reader(r.take(Number(r.integer(4))));if(hex(sr.take(8))!==hex(ascii('LIFESCR1')))throw new Error('scores version');
    const n=Number(sr.integer(4));if(n>MAX_CELLS)throw new Error('scores count');let last=0,sum=0n;const scores=new Map();
    for(let i=0;i<n;++i){const owner=Number(sr.integer(2)),units=sr.integer(8);if(owner<=last||!units)throw new Error('scores order/value');scores.set(owner,units);last=owner;sum+=units;}sr.end();r.end();
    const work=BigInt((total-remaining)*b.cells.length+cell);if(sum>work||BigInt(events.length)>work)throw new Error('cursor work invariant');
    const out=Object.create(LifeCursor.prototype);Object.assign(out,{state:b,start,total,remaining,cell,next,events,scores});return out;
  }
}
