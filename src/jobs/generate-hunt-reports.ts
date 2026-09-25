import {readFile,writeFile,mkdir} from "node:fs/promises";
import {buildDisclosureReport,type DisclosureReport} from "../disclosure-report.js";
import type {EvidencePackage} from "../evidence-graph.js";
import type {BountyMatch} from "../bounty-matcher.js";
const huntPath=process.argv[2]??"artifacts/hunt/latest.json";
const hunt=JSON.parse(await readFile(huntPath,"utf8")) as {evidencePackages?:EvidencePackage[];bountyMatches?:Array<{packageId:string;findingId:string;matches:BountyMatch[]}>};
const packages=hunt.evidencePackages??[];const groups=hunt.bountyMatches??[];await mkdir("artifacts/reports",{recursive:true});
const reports:DisclosureReport[]=[];
for(const group of groups){const pkg=packages.find(p=>p.packageId===group.packageId);if(!pkg)continue;
 for(const match of group.matches.filter(m=>m.scope==="exact-repository")){const report=buildDisclosureReport(pkg,match);const safe=match.programId+"-"+pkg.findingId.replace(/[^a-zA-Z0-9._-]/g,"_");
  await writeFile("artifacts/reports/"+safe+".json",JSON.stringify(report,null,2),"utf8");await writeFile("artifacts/reports/"+safe+".md",report.markdown,"utf8");reports.push(report);}}
const severityRank:Record<string,number>={critical:4,high:3,medium:2,low:1,informational:0};
reports.sort((a,b)=>(severityRank[b.severity]??0)-(severityRank[a.severity]??0)||b.confidence-a.confidence);
const reviewQueue={schemaVersion:"phase-8",generatedAt:new Date().toISOString(),submissionEnabled:false,totalReports:reports.length,priorityOrder:"severity-desc-confidence-desc",reports:reports.map((r,index)=>({priority:index+1,packageId:r.packageId,findingId:r.findingId,programId:r.program.id,severity:r.severity,confidence:r.confidence,scope:r.bounty.scope,validation:r.validation.status,reviewBlockers:r.reviewBlockers,submissionReady:r.submissionReady}))};
await writeFile("artifacts/hunt/review-queue.json",JSON.stringify(reviewQueue,null,2),"utf8");
console.log(JSON.stringify({status:"generated",reports:reports.length,reviewQueue:"artifacts/hunt/review-queue.json"},null,2));
