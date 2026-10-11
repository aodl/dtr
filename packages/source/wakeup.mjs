import { uint } from '../protocol/bytes.mjs';
/** Host scheduling model; clock ticks here are operational, never logical game time. */
export class Wakeup {
  constructor({minGap=2n,fallback=60n,lease=10n}={}) {
    this.minGap=uint(minGap);this.fallback=uint(fallback);this.lease=uint(lease);
    if(!this.lease||!this.fallback)throw new Error('nonzero lease/fallback required');
    this.dirty=false;this.generation=0n;this.active=null;this.lastAttempt=null;this.notBefore=0n;
  }
  hint(authorised=false){if(authorised===true)this.dirty=true;}
  acquire(now){
    now=uint(now);
    if(this.active && now<this.active.until)return null;
    const expired=!!this.active;
    const fallbackDue=this.lastAttempt===null||now-this.lastAttempt>=this.fallback;
    if(now<this.notBefore||(!this.dirty&&!fallbackDue&&!expired))return null;
    const generation=uint(this.generation+1n),until=uint(now+this.lease),notBefore=uint(now+this.minGap);
    this.generation=generation;this.active={generation,until};this.lastAttempt=now;this.notBefore=notBefore;this.dirty=false;
    return Object.freeze({...this.active});
  }
  complete(token,now,success){
    now=uint(now);
    if(!this.active||!token||token.generation!==this.active.generation||token.until!==this.active.until||now>=this.active.until)return false;
    this.active=null;if(success!==true)this.dirty=true;return true;
  }
}
