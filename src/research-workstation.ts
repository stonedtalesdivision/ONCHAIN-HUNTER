import type { EvidencePackage } from "./evidence-graph.js";
import type { InvestigationState } from "./investigation.js";
import type { InvestigationOrchestration } from "./investigation-orchestrator.js";
import type { ProofDossier } from "./proof-engine.js";
import type { ValidationBundle } from "./validation-orchestrator.js";
import type { BountyIntel } from "./bounty-intelligence.js";

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
  validationStatus: ValidationBundle["status"] | "missing";
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
    const intel = intelligence.find(i => i.programId === pkg.programId && (i.repository === pkg.repository || i.repository === null));
    const blockers = [...(inv?.blockers ?? [])];
    if (!proof) blockers.push("proof dossier missing");
    if (!validation) blockers.push("validation bundle missing");
    if (pkg.bountyMatches?.length === 0) blockers.push("no bounty match recorded");
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
      bountyProgramId: pkg.programId,
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
