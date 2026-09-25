import type { EvidencePackage } from "./evidence-graph.js";
import type { InvestigationState } from "./investigation.js";
import type { InvestigationOrchestration } from "./investigation-orchestrator.js";
import type { ProofDossier } from "./proof-engine.js";
import type { ValidationBundle } from "./validation-orchestrator.js";
import type { BountyIntel } from "./bounty-intelligence.js";
import { readFile, writeFile } from "node:fs/promises";

export type WorkstationItem = {
  id: string;
  packageId: string;
  findingId: string;
  title: string;
  severity: string;
  confidence: number;
  priority: number;
  repository?: string;
  sourceRevision?: string;
  bountyProgramId?: string;
  bountyProgramName?: string;
  intelligenceScore?: number;
  proofScore?: number;
  validationStatus: "prepared" | "missing";
  investigationStatus: "queued" | "blocked" | "review";
  blockers: string[];
  nextActions: string[];
  evidenceCount: number;
  attackPathSteps: number;
  transactionSteps: number;
};

export type ResearchWorkstation = {
  schemaVersion: "phase-14";
  generatedAt: string;
  humanReviewOnly: true;
  submissionEnabled: false;
  summary: {
    total: number;
    blocked: number;
    readyForReview: number;
    highOrCritical: number;
    validationPrepared: number;
    strongProof: number;
  };
  items: WorkstationItem[];
  reviewQueue: string[];
  sourceArtifacts: string[];
};

function investigationFor(pkg: EvidencePackage, state: InvestigationState): InvestigationState["records"][string] | undefined {
  return state.records[pkg.findingId] ?? Object.values(state.records).find(r => r.packageId === pkg.packageId);
}

export function buildResearchWorkstation(
  packages: EvidencePackage[],
  investigations: InvestigationState,
  orchestration: InvestigationOrchestration,
  proofs: ProofDossier[],
  validationBundles: ValidationBundle[],
  intelligence: BountyIntel[]
): ResearchWorkstation {
  const items = packages.map(pkg => {
    const inv = investigationFor(pkg, investigations);
    const proof = proofs.find(p => p.packageId === pkg.packageId);
    const validation = validationBundles.find(v => v.packageId === pkg.packageId);
    const intel = intelligence.find(i => i.repository === pkg.repository || i.repository === null);
    const blockers = [...(inv?.blockers ?? [])];
    if (!proof) blockers.push("proof dossier missing");
    if (!validation) blockers.push("validation bundle missing");
    const nextActions = [
      "Confirm exact bounty scope and source revision",
      "Review evidence graph and proof claims",
      "Inspect prepared local validation harness",
      "Confirm impact, known-issue and disclosure requirements",
      "Keep submission under explicit human control"
    ];
    if (inv?.revisionChanged) nextActions.unshift("Revalidate all evidence against the new source revision");
    return {
      id: pkg.packageId,
      packageId: pkg.packageId,
      findingId: pkg.findingId,
      title: pkg.title,
      severity: pkg.severity,
      confidence: pkg.confidence,
      priority: inv?.priority ?? 0,
      repository: pkg.repository,
      sourceRevision: pkg.sourceRevision,
      bountyProgramId: intel?.programId,
      bountyProgramName: intel?.programName,
      intelligenceScore: intel?.intelligenceScore,
      proofScore: proof?.proofScore,
      validationStatus: validation?.status ?? "missing",
      investigationStatus: inv?.blockers?.length ? "blocked" : "queued",
      blockers,
      nextActions,
      evidenceCount: pkg.evidence.length,
      attackPathSteps: pkg.attackPath.length,
      transactionSteps: pkg.transactionSequence.length
    };
  });
  const ranked = items.sort((a,b) => b.priority - a.priority || (b.proofScore ?? 0) - (a.proofScore ?? 0));
  return {
    schemaVersion: "phase-14",
    generatedAt: new Date().toISOString(),
    humanReviewOnly: true,
    submissionEnabled: false,
    summary: {
      total: ranked.length,
      blocked: ranked.filter(i => i.blockers.length > 0).length,
      readyForReview: ranked.filter(i => i.blockers.length === 0).length,
      highOrCritical: ranked.filter(i => i.severity === "high" || i.severity === "critical").length,
      validationPrepared: ranked.filter(i => i.validationStatus === "prepared").length,
      strongProof: ranked.filter(i => (i.proofScore ?? 0) >= 80).length
    },
    items: ranked,
    reviewQueue: (orchestration.queue ?? []).map(q => q.packageId),
    sourceArtifacts: [
      "artifacts/hunt/latest.json",
      "artifacts/hunt/bounty-intelligence.json",
      "artifacts/investigations/latest.json",
      "artifacts/investigations/orchestration.json",
      "artifacts/validation-bundles/"
    ]
  };
}


async function main(): Promise<void> {
  const read = async <T>(path: string, fallback: T): Promise<T> => { try { return JSON.parse(await readFile(path, "utf8")) as T; } catch { return fallback; } };
  const hunt = await read<Record<string, unknown>>("artifacts/hunt/latest.json", {});
  const packages = (hunt.evidencePackages ?? []) as EvidencePackage[];
  const investigations = await read<InvestigationState>("artifacts/investigations/state.json", { schemaVersion: "phase-9", updatedAt: new Date().toISOString(), records: {} });
  const orchestration = await read<InvestigationOrchestration>("artifacts/investigations/orchestration.json", { schemaVersion: "phase-10", generatedAt: new Date().toISOString(), executionEnabled: false, queue: [] });
  const proofs = await Promise.all(packages.map(async p => read<ProofDossier>("artifacts/validation-bundles/" + p.packageId.replace(/[^a-zA-Z0-9_-]/g, "_") + ".proof.json", { schemaVersion: "phase-11", packageId: p.packageId, findingId: p.findingId, fingerprint: "", claims: [], attackPath: [], transactionSequence: [], gaps: ["missing artifact"], proofScore: 0, humanReviewRequired: true })));
  const bundles = await Promise.all(packages.map(async p => read<ValidationBundle>("artifacts/validation-bundles/" + p.packageId + ".json", { schemaVersion: "phase-12", packageId: p.packageId, findingId: p.findingId, harnessPath: "", proofPath: "", commands: [], status: "prepared", executionEnabled: false, safety: { localOnly: true, liveNetworkTraffic: false, explicitExecutionRequired: true } })));
  const intel = await read<{ items: BountyIntel[] }>("artifacts/hunt/bounty-intelligence.json", { items: [] });
  const workstation = buildResearchWorkstation(packages, investigations, orchestration, proofs, bundles, intel.items ?? []);
  await writeFile("artifacts/hunt/research-workstation.json", JSON.stringify(workstation, null, 2), "utf8");
  console.log(JSON.stringify(workstation, null, 2));
}

if (process.argv[1]?.endsWith("research-workstation.ts")) main().catch(error => { console.error(error); process.exitCode = 1; });
