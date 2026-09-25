import test from "node:test";
import assert from "node:assert/strict";
import { analyzeSolidityStructure } from "../dist/structural-analysis.js";
import { buildCorrelatedEvidenceGraphs, mergeEvidenceGraphs, rankEvidenceGraphs } from "../dist/evidence-graph.js";

const finding=(id, category="external-call", severity="high")=>({id,programId:"p",title:"Potential issue",category,severity,confidence:.8,evidence:["function execute (external, nonpayable)"],status:"new",createdAt:new Date().toISOString(),repository:"owner/repo",sourceRevision:"abc"});

test("correlates multiple detector signals into one graph",()=>{
 const a=analyzeSolidityStructure(`contract T { uint balance; function execute(address target,uint amount) external { target.call{value:amount}(""); balance-=amount; } }`,"T.sol");
 const g=buildCorrelatedEvidenceGraphs(a,[finding("1"),finding("2","reentrancy","high")]);
 assert.equal(g.length,1); assert.equal(g[0].corroborationCount,2); assert.ok(g[0].nodes.length>=3);
});

test("merges duplicate graph evidence",()=>{
 const a=analyzeSolidityStructure(`contract T { uint balance; function execute(address target,uint amount) external { target.call{value:amount}(""); balance-=amount; } }`,"T.sol");
 const g=buildCorrelatedEvidenceGraphs(a,[finding("1")]);
 const merged=mergeEvidenceGraphs([...g,...g]);
 assert.equal(merged.length,1); assert.ok(merged[0].confidence>=.8);
});

test("ranks critical graphs above lower severity graphs",()=>{
 const a=analyzeSolidityStructure(`contract T { function execute(address target) external { target.delegatecall(""); } }`,"T.sol");
 const g=buildCorrelatedEvidenceGraphs(a,[finding("1","delegatecall","critical"),finding("2","external-call","medium")]);
 const ranked=rankEvidenceGraphs(g); assert.equal(ranked[0].severity,"critical");
});