/** Presentation only. No physics, game decisions, scoring, financial time or wall clock access. */
function finite(n,name){if(!Number.isFinite(n)||n<0)throw new Error(`playout ${name}`);return n;}
export class PlayoutClock {
  constructor({start=0,target=8,low=2,min_rate=0.97,max_rate=1.03,gain=0.02,slew=0.02,max_frame_delta=0.25}={}){
    [start,target,low,gain,slew,max_frame_delta].forEach(n=>finite(n,'configuration'));
    if(target<=low||low<=0||min_rate<=0||min_rate>1||max_rate<1||max_rate>2||max_frame_delta===0
      ||!Number.isFinite(min_rate)||!Number.isFinite(max_rate))throw new Error('playout configuration');
    Object.assign(this,{playhead:start,available:start,target,low,min_rate,max_rate,gain,slew,max_frame_delta,rate:1,phase:'BUFFERING',started:false});
  }
  /** Call only after committed contiguous data has been downloaded AND verified. */
  append(start,end){
    finite(start,'segment start');finite(end,'segment end');
    if(start!==this.available||end<=start)throw new Error('playout gap/overlap');this.available=end;
  }
  sample(deltaSeconds){
    finite(deltaSeconds,'frame delta');const dt=Math.min(deltaSeconds,this.max_frame_delta);
    let buffer=this.available-this.playhead;
    if(!this.started){
      if(buffer<this.target){this.phase='BUFFERING';return this.state();}
      this.started=true;
    }
    if(this.phase==='STALLED'&&buffer<this.low)return this.state();
    if(buffer<=0){this.phase='STALLED';this.rate=1;return this.state();}
    // Deadband avoids reacting to tiny normal changes; slew prevents abrupt perceptual jumps.
    const error=buffer-this.target;
    const desired=Math.abs(error)<0.25?1:Math.max(this.min_rate,Math.min(this.max_rate,1+this.gain*error));
    this.rate+=Math.max(-this.slew*dt,Math.min(this.slew*dt,desired-this.rate));
    this.playhead=Math.min(this.available,this.playhead+dt*this.rate);buffer=this.available-this.playhead;
    this.phase=buffer<=0?'STALLED':buffer<this.low?'DEGRADED_BUFFER':'PLAYING';
    return this.state();
  }
  state(){return {phase:this.phase,playhead:this.playhead,available:this.available,buffer:this.available-this.playhead,rate:this.rate};}
}
