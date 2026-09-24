import type { BountyProgram, Opportunity } from "./types.js";
import { inferVersionConstraint, requiredScanRef } from "./version-scope.js";

export type ScopedOpportunityQueueItem = Opportunity & {
  repository: string;
  requiredRevision?: string;
  scopeState: "ready" | "needs-review";
};

export function buildOpportunityQueue(programs: BountyProgram[]): Opportunity[] {
  return programs.filter(p => p.status === "active").flatMap(p => p.sourceRepos.map((repo, index) => {
    const constraint = inferVersionConstraint(p);
    const requiredRevision = requiredScanRef(constraint);
    return {
      id: `${p.id}:repo:${index}`,
      programId: p.id,
      title: `Investigate authorized repository: ${repo}`,
      category: "repository-review",
      severity: "informational" as const,
      confidence: 0,
      evidence: [
        `Repository is listed by the bounty program: ${repo}`,
        ...(requiredRevision ? [`Required revision candidate: ${requiredRevision}`] : ["No exact release/commit parsed; manual scope review required."])
      ],
      status: "new" as const,
      createdAt: new Date().toISOString(),
      repository: repo,
      sourceRevision: requiredRevision,
      scopeMatch: requiredRevision ? "yes" as const : "unknown" as const
    };
  }));
}
