import { readFile, writeFile, mkdir } from "node:fs/promises";
import type { EvidencePackage } from "./evidence-graph.js";
import type { InvestigationRecord, InvestigationState } from "./investigation.js";

export type InvestigationAction = {
  packageId: string;
  findingId: string;
  priority: number;
  repository?: string;
  sourceRevision?: string;
  actions: string[];
  blockers: string[];
  validation: { mode: "prepare-only"; executionAllowed: false; harnessCommand: string };
  status: "queued" | "blocked";
};

export type InvestigationOrchestration = {
  schemaVersion: "phase-10";
  generatedAt: string;
  executionEnabled: false;
  selected?: InvestigationAction;
  queue: InvestigationAction[];
};

const outputPath="artifacts/investigations/orchestration.json";

export function buildInvestigationAction(pkg: EvidencePackage, record: InvestigationRecord): InvestigationAction {
  const blockers=[...record.blockers];
  const actions=[
    "Confirm exact repository scope and source revision.",
    "Review the evidence graph and attack path against the current source.",
    "Generate or refresh an isolated local validation harness.",
    "Run local validation only after explicit human approval.",
    "Re-check bounty impact, known issues and disclosure requirements.",
    "Prepare the human-review disclosure report; do not submit automatically."
  ];
  if(record.revisionChanged) actions.splice(1,0,"Revalidate all evidence because the source revision changed.");
  return {
    packageId:pkg.packageId,
    findingId:pkg.findingId,
    priority:record.priority,
    repository:pkg.repository,
    sourceRevision:pkg.sourceRevision,
    actions,
    blockers,
    validation:{mode:"prepare-only",executionAllowed:false,harnessCommand:"npm run validate:suite"},
    status:blockers.length?"blocked":"queued"
  };
}

export async function orchestrateInvestigations(
  packages: EvidencePackage[],
  state: InvestigationState | null,
  limit=5
): Promise<InvestigationOrchestration> {
  const records=state?.records??{};
  const queue=packages
    .map(pkg=>({pkg,record:records[pkg.packageId]}))
    .filter(x=>Boolean(x.record))
    .map(x=>buildInvestigationAction(x.pkg,x.record!))
    .sort((a,b)=>b.priority-a.priority)
    .slice(0,Math.max(1,Math.min(limit,20)));
  const result: InvestigationOrchestration={
    schemaVersion:"phase-10",
    generatedAt:new Date().toISOString(),
    executionEnabled:false,
    selected:queue[0],
    queue
  };
  await mkdir("artifacts/investigations",{recursive:true});
  await writeFile(outputPath,JSON.stringify(result,null,2),"utf8");
  return result;
}
