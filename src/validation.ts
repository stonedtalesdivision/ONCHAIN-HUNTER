export type ValidationMode = "static-only" | "local-fork";
export type ValidationStatus = "not-run" | "ready" | "blocked" | "failed" | "passed";
export type ValidationRequest = { repository:string; findingId:string; mode?:ValidationMode; rpcUrl?:string; forkBlock?:number; sourceRevision?:string };
export type ValidationResult = { findingId:string; mode:ValidationMode; status:ValidationStatus; reason:string; commands:string[]; safety:{localOnly:true;liveNetworkTraffic:false;explicitExecutionRequired:true}; sourceRevision?:string };

export function prepareLocalValidation(request:ValidationRequest):ValidationResult {
  const mode=request.mode??"static-only";
  if(mode==="local-fork"&&!request.rpcUrl) return {findingId:request.findingId,mode,status:"blocked",reason:"An explicit RPC URL is required to create a local fork. ONCHAIN-HUNTER does not select or contact live networks automatically.",commands:[],safety:{localOnly:true,liveNetworkTraffic:false,explicitExecutionRequired:true},sourceRevision:request.sourceRevision};
  const commands=mode==="local-fork"?["anvil --fork-url $FORK_RPC_URL"+(request.forkBlock?" --fork-block-number "+request.forkBlock:""),"forge test -vvv"]:["forge test -vvv"];
  return {findingId:request.findingId,mode,status:"ready",reason:"Validation is prepared for an isolated local Foundry environment. Execution remains explicitly opt-in.",commands,safety:{localOnly:true,liveNetworkTraffic:false,explicitExecutionRequired:true},sourceRevision:request.sourceRevision};
}
