import type { EvidencePackage } from "./evidence-graph.js";
import type { BountyMatch } from "./bounty-matcher.js";
import type { ValidationExecution } from "./validation-runner.js";

export type DisclosureReport={
 schemaVersion:"phase-7"; generatedAt:string; packageId:string; findingId:string;
 program:{id:string;name:string;url:string}; repository:string|null; sourceRevision:string|null;
 severity:EvidencePackage["severity"]; confidence:number; impact:EvidencePackage["impact"];
 exploitability:EvidencePackage["exploitability"]; scopeConfidence:EvidencePackage["scopeConfidence"];
 attackPath:string[]; transactionSequence:EvidencePackage["transactionSequence"]; evidence:string[];
 validation:{status:"not-run"|"passed"|"failed"|"blocked";artifactPath?:string;command?:string};
 bounty:{scope:BountyMatch["scope"];impact:BountyMatch["impact"];severity:BountyMatch["severity"];payoutRoutes:BountyMatch["payoutRoutes"];requirements:BountyMatch["requirements"];programUrl:string};
 reviewBlockers:string[]; submissionReady:false; markdown:string;
};
const bullets=(items:string[])=>items.length?items.map(x=>"- "+x).join("\n"):"- None recorded";
export function buildDisclosureReport(pkg:EvidencePackage,match:BountyMatch,validation?:ValidationExecution):DisclosureReport{
 const status=validation?.status??"not-run";
 const blockers=[
  ...(match.scope!=="exact-repository"?["Repository is not an exact catalog scope match."]:[]),
  ...(status!=="passed"?["No successful local validation is attached."]:[]),
  ...(match.requirements.pocRequired==="unknown"?["PoC requirement must be verified on the current program page."]:[]),
  ...(match.requirements.kycRequired==="unknown"?["KYC requirement must be verified on the current program page."]:[]),
  "Human review of program scope, impact, known issues and disclosure rules is required before submission."
 ];
 const markdown=[
  "# ONCHAIN-HUNTER Security Finding","",
  "## Program",
  \`- Program: ${match.programName}\`,\`- Program URL: ${match.programUrl}\`,\`- Repository: ${pkg.repository??"unknown"}\`,\`- Source revision: ${pkg.sourceRevision??"unknown"}\`,"",
  "## Finding",\`- Title: ${pkg.title}\`,\`- Severity: ${pkg.severity}\`,\`- Confidence: ${pkg.confidence}\`,\`- Impact: ${pkg.impact}\`,\`- Exploitability: ${pkg.exploitability}\`,"",
  "## Attack path",bullets(pkg.attackPath),"",
  "## Transaction sequence",...(pkg.transactionSequence.length?pkg.transactionSequence.map(s=>\`- ${s.order}. ${s.function} — ${s.role}: ${s.evidence}\`):["- No transaction sequence recorded."]),"",
  "## Evidence",bullets(pkg.evidence),"",
  "## Validation",\`- Status: ${status}\`,\`- Command: ${validation?.command??"Not run"}\`,\`- Artifact: ${validation?.artifactPath??"None"}\`,"",
  "## Bounty checks",\`- Scope: ${match.scope}\`,\`- Impact: ${match.impact}\`,\`- Severity: ${match.severity}\`,\`- PoC required: ${String(match.requirements.pocRequired)}\`,\`- KYC required: ${String(match.requirements.kycRequired)}\`,"",
  "## Review blockers",bullets(blockers),"",
  "## Submission","Submission is intentionally disabled. Complete human review and the program's current disclosure process before submitting."
 ].join("\n");
 return {schemaVersion:"phase-7",generatedAt:new Date().toISOString(),packageId:pkg.packageId,findingId:pkg.findingId,
  program:{id:match.programId,name:match.programName,url:match.programUrl},repository:pkg.repository??null,sourceRevision:pkg.sourceRevision??null,
  severity:pkg.severity,confidence:pkg.confidence,impact:pkg.impact,exploitability:pkg.exploitability,scopeConfidence:pkg.scopeConfidence,
  attackPath:pkg.attackPath,transactionSequence:pkg.transactionSequence,evidence:pkg.evidence,
  validation:{status,artifactPath:validation?.artifactPath,command:validation?.command},
  bounty:{scope:match.scope,impact:match.impact,severity:match.severity,payoutRoutes:match.payoutRoutes,requirements:match.requirements,programUrl:match.programUrl},
  reviewBlockers:blockers,submissionReady:false,markdown};
}
