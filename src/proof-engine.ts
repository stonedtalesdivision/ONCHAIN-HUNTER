import { createHash } from "node:crypto";
import type { EvidencePackage } from "./evidence-graph.js";
export type ProofClaim={id:string;claim:string;evidence:string[];strength:"strong"|"moderate"|"weak"};
export type ProofDossier={schemaVersion:"phase-11";packageId:string;findingId:string;fingerprint:string;claims:ProofClaim[];attackPath:string[];transactionSequence:string[];gaps:string[];proofScore:number;humanReviewRequired:true};
function strength(pkg:EvidencePackage):"strong"|"moderate"|"weak"{if(pkg.attackPath.length>=4&&pkg.transactionSequence.length>=3&&pkg.evidence.length>=3&&pkg.confidence>=.85)return "strong";if(pkg.attackPath.length>=2&&pkg.transactionSequence.length>=2&&pkg.evidence.length>=2)return "moderate";return "weak"}
export function buildProofDossier(pkg:EvidencePackage):ProofDossier{
 const claims:ProofClaim[]=[
  {id:"scope",claim:pkg.sourceRevision?"Candidate is tied to a recorded source revision.":"Exact source revision is missing.",evidence:pkg.sourceRevision?["source revision: "+pkg.sourceRevision]:[],strength:pkg.sourceRevision?"strong":"weak"},
  {id:"reachability",claim:pkg.attackPath[0]??"Attacker reachability is not established.",evidence:pkg.attackPath.slice(0,2),strength:pkg.attackPath.length>=2?"moderate":"weak"},
  {id:"impact",claim:pkg.attackPath.at(-1)??"Impact is not established.",evidence:pkg.attackPath.slice(-3),strength:pkg.attackPath.length>=3?"moderate":"weak"},
  {id:"reproduction",claim:pkg.transactionSequence.length>=2?"A multi-step local reproduction sequence is defined.":"A complete reproduction sequence is not yet defined.",evidence:pkg.transactionSequence.map(s=>s.evidence),strength:pkg.transactionSequence.length>=3?"strong":pkg.transactionSequence.length>=2?"moderate":"weak"}
 ];
 const gaps=[...(pkg.attackPath.length<3?["Need a complete attacker-to-impact path."]:[]),...(pkg.transactionSequence.length<3?["Need a multi-step transaction sequence."]:[]),...(pkg.evidence.length<3?["Need additional concrete source evidence."]:[])];
 const proofScore=Math.min(100,Math.round(pkg.confidence*55+(pkg.attackPath.length>=3?15:0)+(pkg.transactionSequence.length>=3?15:0)+(pkg.evidence.length>=3?15:0)));
 const fingerprint=createHash("sha256").update(JSON.stringify({packageId:pkg.packageId,attackPath:pkg.attackPath,transactionSequence:pkg.transactionSequence,evidence:pkg.evidence})).digest("hex");
 return {schemaVersion:"phase-11",packageId:pkg.packageId,findingId:pkg.findingId,fingerprint,claims,attackPath:pkg.attackPath,transactionSequence:pkg.transactionSequence.map(s=>String(s.order)+". "+s.function+" ["+s.role+"] — "+s.evidence),gaps,proofScore,humanReviewRequired:true};
}