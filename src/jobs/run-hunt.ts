import "dotenv/config";
import { ImmunefiBountySource } from "../sources/immunefi.js";
import { inferVersionConstraintForRepository, requiredScanRef } from "../version-scope.js";
import { resolveRepositoryRevision, listRepositoryFiles, fetchRawFile } from "../github.js";
import { scanSoliditySource } from "../scanner.js";
import { writeFile, mkdir } from "node:fs/promises";
import { matchEvidencePackage, rankBountyMatches } from "../bounty-matcher.js";
import { payoutRoutesForProgram } from "../payout.js";
import { prioritizeScanTargets } from "../target-prioritizer.js";
import { analyzeSolidityStructure, structuralFindings } from "../structural-analysis.js";
import { detectBrokenAccessControl } from "../detectors/access-control.js";
import { detectPhase3 } from "../detectors/phase3.js";
import { buildCorrelatedEvidenceGraphs, buildEvidencePackages, deduplicateFindings, mergeEvidenceGraphs, rankEvidenceGraphs, linkCrossFunctionGraphs, type EvidenceGraph, type EvidencePackage } from "../evidence-graph.js";
import type { Opportunity } from "../types.js";
import { loadMonitoringState, prioritizeChangedTargets, updateMonitoringState } from "../monitoring.js";
import { updateInvestigationState } from "../investigation.js";

async function main(): Promise<void> {
 const hasToken=Boolean(process.env.GITHUB_TOKEN),configuredLimit=Number(process.env.ONCHAIN_HUNTER_LIMIT??(hasToken?"5":"1")),limit=Math.max(1,Math.min(Number.isFinite(configuredLimit)?configuredLimit:1,20)),token=process.env.GITHUB_TOKEN,source=new ImmunefiBountySource();
 console.log(JSON.stringify({event:"hunt-start",repositoryLimit:limit,authenticatedGitHub:hasToken}));
 const programs=await source.discover();console.log(JSON.stringify({event:"catalog-loaded",programsDiscovered:programs.length}));
 const candidates:unknown[]=[],structuralSummaries:unknown[]=[],evidenceGraphs:EvidenceGraph[]=[];
 const payoutConfiguration=programs.filter(p=>p.status==="active").map(program=>({programId:program.id,programName:program.name,routes:payoutRoutesForProgram(program)}));
 let scannedRepositories=0,skippedRepositories=0,attemptedRepositories=0,rateLimited=false;
 const activePrograms=programs.filter(p=>p.status==="active"),allRepositoryCount=activePrograms.reduce((t,p)=>t+p.sourceRepos.length,0),targets=prioritizeScanTargets(activePrograms),previousMonitoring=await loadMonitoringState(),monitoringTargets=prioritizeChangedTargets(targets.map(t=>({programId:t.program.id,repository:t.repository,ref:t.ref,score:t.score,target:t})),previousMonitoring).map(t=>t.target),scopeReviewRequired=Math.max(0,allRepositoryCount-targets.length),selectedTargets=monitoringTargets.slice(0,limit);
 console.log(JSON.stringify({event:"targets-prioritized",monitoringBaseline:Boolean(previousMonitoring),activePrograms:activePrograms.length,repositoriesAvailable:allRepositoryCount,exactScopeTargets:targets.length,scopeReviewRequired,selected:selectedTargets.map(t=>({programId:t.program.id,repository:t.repository,ref:t.ref,score:t.score}))}));
 for(const target of selectedTargets){const {program,repository,ref}=target;attemptedRepositories++;console.log(JSON.stringify({event:"scan-start",programId:program.id,repository,ref,priorityScore:target.score,priorityReasons:target.reasons}));
  try{const revision=await resolveRepositoryRevision(repository,ref,token),files=await listRepositoryFiles(repository,token,ref),solidity=files.filter(f=>/\.sol$/i.test(f.path));let repoFindings=0;
   for(const file of solidity){if(!file.download_url)continue;const sourceText=await fetchRawFile(file.download_url,token),structure=analyzeSolidityStructure(sourceText,file.path);structuralSummaries.push(structure);
    const detectorFindings=[...scanSoliditySource(sourceText,file.path),...structuralFindings(structure),...detectBrokenAccessControl(structure),...detectPhase3(structure)].map(finding=>({...finding,id:`${program.id}:${repository}:${revision.commitSha}:${finding.id}`,programId:program.id,repository,sourceRevision:revision.commitSha,scopeMatch:"yes" as const,payoutRoutes:payoutRoutesForProgram(program),evidence:[`program: ${program.id}`,`repository: ${repository}`,`revision: ${revision.commitSha}`,...finding.evidence]})) as Opportunity[];
    const uniqueFindings=deduplicateFindings(detectorFindings);repoFindings+=uniqueFindings.length;evidenceGraphs.push(...buildCorrelatedEvidenceGraphs(structure,uniqueFindings));candidates.push(...uniqueFindings);
   }
   scannedRepositories++;console.log(JSON.stringify({event:"scan-complete",repository,solidityFiles:solidity.length,findings:repoFindings}));
  }catch(error){skippedRepositories++;const reason=error instanceof Error?error.message:String(error);if(reason.startsWith("GitHub API rate limit exhausted;")){rateLimited=true;console.error(JSON.stringify({event:"rate-limit",reason}));break;}candidates.push({type:"scan-error",programId:program.id,repository,reason});console.error(JSON.stringify({event:"scan-error",programId:program.id,repository,reason}));}
 }
 await mkdir("artifacts/hunt",{recursive:true});const path="artifacts/hunt/latest.json";
 const mergedGraphs=mergeEvidenceGraphs(evidenceGraphs),linkedGraphs=linkCrossFunctionGraphs(mergedGraphs),rankedGraphs=rankEvidenceGraphs(linkedGraphs),findings=candidates.filter((x:any)=>!x.type) as Opportunity[],evidencePackages:EvidencePackage[]=buildEvidencePackages(rankedGraphs,findings);
 const bountyMatches=evidencePackages.map(pkg=>({packageId:pkg.packageId,findingId:pkg.findingId,matches:rankBountyMatches(matchEvidencePackage(pkg,programs,payoutRoutesForProgram))}));
 const targetPlan=targets.slice(0,Math.min(targets.length,50)).map(t=>({programId:t.program.id,programName:t.program.name,repository:t.repository,ref:t.ref,score:t.score,reasons:t.reasons}));
 const investigation=await updateInvestigationState(evidencePackages);
 const monitoring=await updateMonitoringState(
  Object.fromEntries(programs.map(p=>[p.id,{status:p.status,url:p.url,maxReward:p.maxReward,chains:p.chains,sourceRepos:p.sourceRepos}])),
  Object.fromEntries(targetPlan.map(t=>[`${t.programId}:${t.repository}`,{programId:t.programId,repository:t.repository,ref:t.ref,score:t.score}])),
  Object.fromEntries(evidencePackages.map(p=>[p.findingId,{severity:p.severity,repository:p.repository,sourceRevision:p.sourceRevision,title:p.title}]))
 );
 const result={generatedAt:new Date().toISOString(),source:source.name,programsDiscovered:programs.length,attemptedRepositories,scannedRepositories,rateLimited,skippedRepositories,scopeReviewRequired,targetPlan,candidateFindings:findings.length,payoutConfiguration,structuralAnalysis:structuralSummaries,evidenceGraphs:rankedGraphs,evidenceGraphSummary:{total:evidenceGraphs.length,unique:rankedGraphs.length,crossFunctionChains:rankedGraphs.filter(g=>g.crossFunctionPaths.length).length,critical:rankedGraphs.filter(g=>g.severity==="critical").length,high:rankedGraphs.filter(g=>g.severity==="high").length},evidencePackages,evidencePackageSummary:{total:evidencePackages.length,reviewReady:evidencePackages.filter(p=>p.submissionReady).length,withCrossFunctionChains:evidencePackages.filter(p=>p.transactionSequence.length>1).length},bountyMatchSummary:{packages:evidencePackages.length,matched:bountyMatches.filter(x=>x.matches.length).length,exactScope:bountyMatches.reduce((n,x)=>n+x.matches.filter(m=>m.scope==="exact-repository").length,0)},monitoring:{events:monitoring.events.length,eventsPath:"artifacts/monitoring/latest-events.json",statePath:"artifacts/monitoring/state.json"},investigation:{total:Object.keys(investigation.current.records).length,revisionChanges:Object.values(investigation.current.records).filter((record)=>record.revisionChanged).length,artifactPath:"artifacts/investigations/latest.json"},bountyMatches,results:candidates};
 await writeFile(path,JSON.stringify(result,null,2),"utf8");console.log(JSON.stringify(result,null,2));
}
main().catch(error=>{console.error(JSON.stringify({event:"hunt-fatal",error:error instanceof Error?{name:error.name,message:error.message,stack:error.stack}:String(error)},null,2));process.exitCode=1;});
