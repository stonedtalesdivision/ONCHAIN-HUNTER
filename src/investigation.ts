import { readFile, writeFile, mkdir } from "node:fs/promises";
import { createHash } from "node:crypto";
import type { EvidencePackage } from "./evidence-graph.js";

export type InvestigationRecord = {
  schemaVersion: "phase-9";
  packageId: string;
  findingId: string;
  repository?: string;
  sourceRevision?: string;
  fingerprint: string;
  relatedFiles: string[];
  relatedFunctions: string[];
  revisionChanged: boolean;
  previousRevision?: string;
  validationPlan: string[];
  missingEvidence: string[];
  blockers: string[];
  priority: number;
  updatedAt: string;
};

export type InvestigationState = {
  schemaVersion: "phase-9";
  updatedAt: string;
  records: Record<string, InvestigationRecord>;
};

const statePath = "artifacts/investigations/state.json";

export async function loadInvestigationState(): Promise<InvestigationState | null> {
  try {
    return JSON.parse(await readFile(statePath, "utf8")) as InvestigationState;
  } catch {
    return null;
  }
}

function fingerprint(pkg: EvidencePackage): string {
  return createHash("sha256")
    .update(JSON.stringify({
      findingId: pkg.findingId,
      file: pkg.file,
      attackPath: pkg.attackPath,
      transactionSequence: pkg.transactionSequence,
      evidence: pkg.evidence
    }))
    .digest("hex");
}

export function buildInvestigationRecord(
  pkg: EvidencePackage,
  previous?: InvestigationRecord
): InvestigationRecord {
  const revisionChanged = Boolean(
    previous?.sourceRevision &&
    pkg.sourceRevision &&
    previous.sourceRevision !== pkg.sourceRevision
  );

  const missingEvidence = [
    ...(pkg.attackPath.length < 2 ? ["A complete attacker-to-impact path is not established."] : []),
    ...(pkg.transactionSequence.length < 2 ? ["A multi-step transaction sequence is not established."] : []),
    ...(pkg.evidence.length < 3 ? ["Additional concrete code evidence is required."] : []),
    ...(pkg.sourceRevision ? [] : ["Exact source revision is missing."])
  ];

  const blockers = [
    ...(revisionChanged ? ["Finding changed source revision; revalidate against the new revision."] : []),
    ...missingEvidence,
    "Human review of scope, exploitability, impact and disclosure requirements remains required."
  ];

  const severityWeight: Record<string, number> = {
    critical: 100,
    high: 75,
    medium: 50,
    low: 25,
    informational: 10
  };

  const priority =
    (severityWeight[pkg.severity] ?? 0) +
    Math.round(pkg.confidence * 20) +
    Math.min(20, pkg.corroborationCount * 3) +
    (revisionChanged ? 15 : 0) +
    (missingEvidence.length === 0 ? 10 : 0);

  return {
    schemaVersion: "phase-9",
    packageId: pkg.packageId,
    findingId: pkg.findingId,
    repository: pkg.repository,
    sourceRevision: pkg.sourceRevision,
    fingerprint: fingerprint(pkg),
    relatedFiles: [pkg.file],
    relatedFunctions: [...new Set(pkg.transactionSequence.map(step => step.function))],
    revisionChanged,
    previousRevision: previous?.sourceRevision,
    validationPlan: pkg.validationPlan,
    missingEvidence,
    blockers,
    priority,
    updatedAt: new Date().toISOString()
  };
}

export async function updateInvestigationState(
  packages: EvidencePackage[]
): Promise<{ previous: InvestigationState | null; current: InvestigationState }> {
  const previous = await loadInvestigationState();
  const records: Record<string, InvestigationRecord> = {};

  for (const pkg of packages) {
    const old = previous?.records[pkg.packageId];
    records[pkg.packageId] = buildInvestigationRecord(pkg, old);
  }

  const current: InvestigationState = {
    schemaVersion: "phase-9",
    updatedAt: new Date().toISOString(),
    records
  };

  await mkdir("artifacts/investigations", { recursive: true });
  await writeFile(statePath, JSON.stringify(current, null, 2), "utf8");
  await writeFile(
    "artifacts/investigations/latest.json",
    JSON.stringify({
      schemaVersion: "phase-9",
      generatedAt: current.updatedAt,
      total: packages.length,
      revisionChanges: Object.values(records).filter(r => r.revisionChanged).length,
      incomplete: Object.values(records).filter(r => r.missingEvidence.length > 0).length,
      records: Object.values(records).sort((a, b) => b.priority - a.priority)
    }, null, 2),
    "utf8"
  );

  return { previous, current };
}
