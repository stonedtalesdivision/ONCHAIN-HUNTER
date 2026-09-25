import {readFile,writeFile,mkdir} from "node:fs/promises";
import {generateFoundryHarness} from "../harness.js";
import type {EvidencePackage} from "../evidence-graph.js";
const huntPath=process.argv[2]??"artifacts/hunt/latest.json";
const hunt=JSON.parse(await readFile(huntPath,"utf8")) as {evidencePackages?:EvidencePackage[];generatedAt?:string};
const packages=hunt.evidencePackages??[];await mkdir("test/onchain-hunter",{recursive:true});const entries=[];
for(const pkg of packages){
 const finding={id:pkg.findingId,programId:"evidence-package",title:pkg.title,category:pkg.categories[0]??"unknown",severity:pkg.severity,confidence:pkg.confidence,evidence:pkg.evidence,status:"new",createdAt:new Date().toISOString(),repository:pkg.repository,sourceRevision:pkg.sourceRevision} as any;
 const h=generateFoundryHarness(finding);await writeFile(h.path,h.content,"utf8");
 entries.push({packageId:pkg.packageId,findingId:pkg.findingId,harnessPath:h.path,sourceRevision:pkg.sourceRevision??null,repository:pkg.repository??null,status:"ready",execution:"blocked-by-default",validationPlan:pkg.validationPlan});
}
const output={schemaVersion:"phase-5",generatedAt:new Date().toISOString(),huntGeneratedAt:hunt.generatedAt??null,safety:{localOnly:true,liveNetworkTraffic:false,automaticExecution:false},total:entries.length,ready:entries.length,blockedUntilExplicitOptIn:entries.length,entries};
await writeFile("artifacts/hunt/validation-suite.json",JSON.stringify(output,null,2),"utf8");console.log(JSON.stringify(output,null,2));
