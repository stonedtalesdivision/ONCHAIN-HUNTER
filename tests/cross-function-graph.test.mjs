import test from "node:test";
import assert from "node:assert/strict";
import { linkCrossFunctionGraphs } from "../dist/evidence-graph.js";

test("links graphs that share state or asset signals",()=>{
 const base=(name,label)=>({findingId:name,file:"T.sol",severity:"high",confidence:.8,categories:["x"],nodes:[{id:"function:"+name,kind:"function",label:name,evidence:[]},{id:"state:"+label,kind:"state",label,evidence:[]}],edges:[],attackPath:["entry "+name,"impact "+label],reviewQuestions:[],correlationKey:name,corroborationCount:1,impact:"state-corruption",exploitability:"direct",scopeConfidence:"exact-revision",deduplicationKey:name,crossFunctionPaths:[],chainConfidence:.8});
 const result=linkCrossFunctionGraphs([base("withdraw","balance"),base("settle","balance")]);
 assert.ok(result[0].crossFunctionPaths.length>0 || result[1].crossFunctionPaths.length>0);
 assert.ok(result.some(x=>x.chainConfidence>.8));
});