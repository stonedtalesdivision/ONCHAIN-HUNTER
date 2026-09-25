import type {BountyProgram,Opportunity,Severity} from "./types.js";
import type {EvidencePackage} from "./evidence-graph.js";
import type {PayoutRoute} from "./payout.js";

export type BountyMatch={programId:string;programName:string;programUrl:string;repository:string|null;scope:"exact-repository"|"repository-not-listed"|"unknown";impact:"matched"|"unverified";severity:"matched"|"unverified";payoutRoutes:PayoutRoute[];requirements:{pocRequired:boolean|"unknown";kycRequired:boolean|"unknown";prohibitedActivities:string[];impactCategories:string[];knownIssueNotes:string[];sourceUrl:string|null};eligibility:"review-required"|"scope-mismatch"|"candidate";reasons:string[]};

function severityMatches(program:BountyProgram,severity:Severity){const text=[...program.inScope,...program.chains].join(" ").toLowerCase();if(!text)return "unverified" as const;const high=severity==="critical"||severity==="high";if(high&&/(critical|high|severity|smart contract|code)/.test(text))return "matched" as const;return "unverified" as const}
function impactMatches(program:BountyProgram,category:string):"matched"|"unverified"{const req=program.requirements?.impactCategories??[];if(!req.length)return "unverified" as const;const c=category.toLowerCase();return req.some(x=>x.toLowerCase().includes(c)||c.includes(x.toLowerCase()))?"matched":"unverified"}

export function matchEvidencePackage(pkg:EvidencePackage,programs:BountyProgram[],payout:(p:BountyProgram)=>PayoutRoute[]):BountyMatch[]{
 const repo=pkg.repository??"";
 return programs.filter(p=>p.status==="active").map(p=>{
  const exact=p.sourceRepos.some(r=>r.toLowerCase()===repo.toLowerCase());
  const impact:BountyMatch["impact"]=impactMatches(p,pkg.categories[0]??"");
  const severity=severityMatches(p,pkg.severity);
  const requirements=p.requirements;
  const reasons:string[]=[];
  if(exact)reasons.push("Repository is explicitly listed by the bounty catalog.");
  else if(repo)reasons.push("Repository is not explicitly listed by this program's catalog record.");
  if(impact==="matched")reasons.push("Finding category matches a published impact category.");
  else reasons.push("Impact eligibility requires program-page review.");
  if(severity==="matched")reasons.push("Finding severity is compatible with catalog security scope signals.");
  else reasons.push("Severity/impact limits require program-page review.");
  const scope:BountyMatch["scope"]=exact?"exact-repository":repo?"repository-not-listed":"unknown";
  const eligibility:BountyMatch["eligibility"]=exact?"review-required":"scope-mismatch";
  const pocRequired:BountyMatch["requirements"]["pocRequired"]=requirements?.pocRequired===true?true:"unknown";
  const kycRequired:BountyMatch["requirements"]["kycRequired"]=requirements?.kycRequired===true?true:"unknown";
  return {programId:p.id,programName:p.name,programUrl:p.url,repository:repo||null,scope,impact,severity,payoutRoutes:payout(p),requirements:{pocRequired,kycRequired,prohibitedActivities:requirements?.prohibitedActivities??[],impactCategories:requirements?.impactCategories??[],knownIssueNotes:requirements?.knownIssueNotes??[],sourceUrl:requirements?.sourceUrl??p.url},eligibility,reasons};
 }).filter(m=>m.scope==="exact-repository"||m.impact==="matched");
}

export function rankBountyMatches(matches:BountyMatch[]):BountyMatch[]{
 return [...matches].sort((a,b)=>{
  const scopeA=a.scope==="exact-repository"?2:a.scope==="repository-not-listed"?1:0;
  const scopeB=b.scope==="exact-repository"?2:b.scope==="repository-not-listed"?1:0;
  if(scopeA!==scopeB)return scopeB-scopeA;
  const impactA=a.impact==="matched"?1:0;
  const impactB=b.impact==="matched"?1:0;
  if(impactA!==impactB)return impactB-impactA;
  const severityA=a.severity==="matched"?1:0;
  const severityB=b.severity==="matched"?1:0;
  return severityB-severityA;
 });
}
