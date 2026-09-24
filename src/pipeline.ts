import type { BountyProgram, Opportunity } from "./types.js";
export function buildOpportunityQueue(programs: BountyProgram[]): Opportunity[] {
  return programs.filter(p => p.status === "active").flatMap(p => p.sourceRepos.map((repo, index) => ({
    id: `${p.id}:repo:${index}`, programId: p.id, title: `Investigate authorized repository: ${repo}`,
    category: "repository-review", severity: "informational" as const, confidence: 0,
    evidence: [`Repository is listed by the bounty program: ${repo}`], status: "new" as const, createdAt: new Date().toISOString()
  })));
}
