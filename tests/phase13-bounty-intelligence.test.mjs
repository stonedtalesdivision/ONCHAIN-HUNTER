import test from "node:test";
import assert from "node:assert/strict";
import { buildBountyIntelligence } from "../dist/bounty-intelligence.js";
const program={id:"p",name:"Test",platform:"Immunefi",url:"https://example.test",status:"active",maxReward:100000,rewardCurrency:"USD",chains:["Ethereum"],inScope:["Smart Contracts"],sourceRepos:["org/repo"],fetchedAt:new Date().toISOString()};
const match={programId:"p",programName:"Test",programUrl:program.url,repository:"org/repo",scope:"exact-repository",impact:"matched",severity:"matched",payoutRoutes:[],requirements:{pocRequired:"unknown",kycRequired:"unknown",prohibitedActivities:[],impactCategories:[],knownIssueNotes:[],sourceUrl:program.url},eligibility:"review-required",reasons:["exact"]};
const pkg={packageId:"pkg",findingId:"f"};
test("phase 13 builds bounty intelligence",()=>{const x=buildBountyIntelligence(pkg, [match], [program])[0];assert.equal(x.schemaVersion,"phase-13");assert.equal(x.scopeConfidence,"exact-repository");assert.ok(x.intelligenceScore>50);});