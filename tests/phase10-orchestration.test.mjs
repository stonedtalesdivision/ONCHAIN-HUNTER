import test from "node:test";
import assert from "node:assert/strict";
import { buildInvestigationAction } from "../dist/investigation-orchestrator.js";

const pkg={
 packageId:"pkg-1",findingId:"finding-1",title:"Test finding",file:"src/Vault.sol",
 severity:"high",confidence:.9,categories:["access-control"],impact:"asset-loss",
 exploitability:"direct",scopeConfidence:"exact-revision",attackPath:["input","impact"],
 transactionSequence:[{order:1,function:"withdraw",role:"entry",evidence:"entry"},{order:2,function:"withdraw",role:"asset-impact",evidence:"transfer"}],
 corroborationCount:2,evidence:["program","repository","revision"],reviewQuestions:[],
 validationPlan:["local test"],repository:"org/repo",sourceRevision:"abc",submissionReady:false
};
const rec={schemaVersion:"phase-9",packageId:"pkg-1",findingId:"finding-1",repository:"org/repo",sourceRevision:"abc",
 fingerprint:"x",relatedFiles:["src/Vault.sol"],relatedFunctions:["withdraw"],revisionChanged:false,validationPlan:["local test"],
 missingEvidence:[],blockers:["Human review remains required."],priority:110,updatedAt:new Date().toISOString()};
test("phase 10 creates a safe investigation action plan",()=>{
 const a=buildInvestigationAction(pkg,rec);
 assert.equal(a.validation.executionAllowed,false);
 assert.equal(a.validation.mode,"prepare-only");
 assert.equal(a.status,"blocked");
 assert.ok(a.actions.some(x=>x.includes("isolated local validation harness")));
});
