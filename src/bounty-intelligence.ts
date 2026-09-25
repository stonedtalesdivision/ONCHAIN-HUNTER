import type { BountyProgram, Opportunity } from "./types.js";
import type { BountyMatch } from "./bounty-matcher.js";
import type { EvidencePackage } from "./evidence-graph.js";

export type BountyIntel = {
 schemaVersion:"phase-13";
 programId:string; programName:string; programUrl:string; repository:string|null;
 scopeConfidence:"exact-repository"|"repository-not-listed"|"unknown";
 reward:{maxReward?:number;currency?:string};
 chainSignals:string[]; scopeSignals:string[]; riskSignals:string[];
 requirements:{pocRequired:boolean|"unknown";kycRequired:boolean|"unknown";prohibitedActivities:string[];impactCategories:string[];knownIssueNotes:string[];sourceUrl:string|null};
 freshness:{fetchedAt:string;ageHours:number;stale:boolean};
 intelligenceScore:number; reasons:string[];
};

function hoursSince(iso:string){const t=Date.parse(iso);return Number.isFinite(t)?Math.max(0,(Date.now()-t)/36e5):99999}
function scoreMatch(m:BountyMatch,p:BountyProgram){
 const age=hoursSince(p.fetchedAt), fresh=age<=48, stale=age>168;
 const reward=Math.min(25,Math.log10(Math.max(1,p.maxReward??0)+1)*5);
 const scope=m.scope==="exact-repository"?35:m.scope==="repository-not-listed"?8:0;
 const impact=m.impact==="matched"?12:0, severity=m.severity==="matched"?8:0, freshness=fresh?10:stale?0:5;
 const requirementPenalty=(m.requirements.pocRequired==="unknown"?2:0)+(m.requirements.kycRequired==="unknown"?1:0);
 return Math.max(0,Math.min(100,Math.round(reward+scope+impact+severity+freshness-requirementPenalty)));
}

export function buildBountyIntelligence(pkg:EvidencePackage, matches:BountyMatch[], programs:BountyProgram[]):BountyIntel[]{
 return matches.map(m=>{const p=programs.find(x=>x.id===m.programId);if(!p)throw new Error("Program not found: "+m.programId);const age=hoursSince(p.fetchedAt), stale=age>168;
 const reasons=[...m.reasons];if(p.maxReward)reasons.push("Published maximum reward is "+p.maxReward+(p.rewardCurrency?" "+p.rewardCurrency:"")+"; verify current program terms.");
 if(stale)reasons.push("Catalog data is older than seven days and should be refreshed before relying on it.");
 return {schemaVersion:"phase-13",programId:p.id,programName:p.name,programUrl:p.url,repository:m.repository,scopeConfidence:m.scope,reward:{maxReward:p.maxReward,currency:p.rewardCurrency},chainSignals:p.chains,scopeSignals:p.inScope.slice(0,25),riskSignals:m.requirements.prohibitedActivities,requirements:m.requirements,freshness:{fetchedAt:p.fetchedAt,ageHours:Math.round(age*10)/10,stale},intelligenceScore:scoreMatch(m,p),reasons};});
}

export function rankBountyIntelligence(intel:BountyIntel[]){return [...intel].sort((a,b)=>b.intelligenceScore-a.intelligenceScore||((b.reward.maxReward??0)-(a.reward.maxReward??0)));}
