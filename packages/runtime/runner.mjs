import { canonicalInputs, encodeSeal, inputRoot, manifest, sha256 } from './seal.mjs';
/** Offline generic host. No game import, no wall clock, and no publication before completion. */
export function runSegment({seal, inputs, initialState, createCursor, restoreCursor=null, budgets=[1024], maxSlices=100000}) {
  encodeSeal(seal);
  if (sha256(initialState)!==seal.previous_state) throw new Error('wrong initial state');
  if (seal.input_count!==inputs.length || inputRoot(inputs,seal.source_from,seal.source_to_exclusive)!==seal.input_root) throw new Error('wrong sealed inputs');
  if (!Array.isArray(budgets)||!budgets.length||budgets.some(n=>!Number.isSafeInteger(n)||n<1||n>1000000)
      ||!Number.isSafeInteger(maxSlices)||maxSlices<1) throw new Error('host work budget');
  let cursor=createCursor(initialState,canonicalInputs(inputs),seal),slices=0;
  for (;slices<maxSlices;) {
    const budget=budgets[slices%budgets.length];const progress=cursor.step(budget);slices++;
    if(typeof progress.complete!=='boolean'||!Number.isInteger(progress.used)||progress.used<0||progress.used>budget||(!progress.complete&&!progress.used))throw new Error('kernel made invalid/no progress');
    if(restoreCursor){const saved=cursor.snapshot();cursor=restoreCursor(saved,sha256(saved));}
    if(progress.complete){const result=cursor.result();return {manifest:manifest(seal,result.state,result.events,result.scores),result,slices};}
  }
  // No partial output is committed. A future asynchronous IC host retains its staged cursor instead.
  throw new Error('host slice limit reached; no commit');
}
