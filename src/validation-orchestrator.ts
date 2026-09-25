import { mkdir,writeFile } from "node:fs/promises";
import { generateFoundryHarness } from "./harness.js";
import type { EvidencePackage } from "./evidence-graph.js";
import type { ProofDossier } from "./proof-engine.js";
export type ValidationBundle={schemaVersion:"phase-12";packageId:string;findingId:string;harnessPath:string;proofPath:string;commands:string[];status:"prepared";executionEnabled:false;safety:{localOnly:true;liveNetworkTraffic:false;explicitExecutionRequired:true}};
export async function prepareValidationBundle(pkg:EvidencePackage,proof:ProofDossier):Promise<ValidationBundle>{
 const finding={id:pkg.findingId,title:pkg.title,category:pkg.categories[0]??"unknown",severity:pkg.severity,confidence:pkg.confidence,evidence:pkg.evidence,status:"new",createdAt:new Date().toISOString(),repository:pkg.repository,sourceRevision:pkg.sourceRevision} as any;
 const harness=generateFoundryHarness(finding);await mkdir("artifacts/validation-bundles",{recursive:true});await mkdir("test/onchain-hunter",{recursive:true});await writeFile(harness.path,harness.content,"utf8");
 const proofPath="artifacts/validation-bundles/"+pkg.packageId.replace(/[^a-zA-Z0-9_-]/g,"_")+".proof.json";await writeFile(proofPath,JSON.stringify(proof,null,2),"utf8");
 return {schemaVersion:"phase-12",packageId:pkg.packageId,findingId:pkg.findingId,harnessPath:harness.path,proofPath,commands:["forge test -vvv --match-test test_candidate_"+(pkg.categories[0]??"unknown").replace(/[^a-zA-Z0-9_]/g,"_"),"npm run validate:run"],status:"prepared",executionEnabled:false,safety:{localOnly:true,liveNetworkTraffic:false,explicitExecutionRequired:true}};
}