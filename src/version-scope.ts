import type { BountyProgram } from "./types.js";

export type VersionConstraint = {
  repository: string;
  requiredRef?: string;
  requiredCommit?: string;
  requiredRelease?: string;
  notes: string[];
};

function extractConstraint(text: string, repository: string): VersionConstraint {
  const commit = text.match(/\b[0-9a-f]{40}\b/i)?.[0];
  const release = text.match(/\bv?\d+\.\d+\.\d+(?:-[A-Za-z0-9.-]+)?\b/)?.[0];
  const notes: string[] = [];
  if (commit) notes.push("Repository-specific scope contains an exact commit reference.");
  if (release) notes.push("Repository-specific scope contains an explicit release/version reference.");
  if (!commit && !release) notes.push("No repository-specific exact release/commit was parsed; manual scope review required.");
  return { repository, requiredCommit: commit, requiredRelease: release, notes };
}

export function inferVersionConstraint(program: BountyProgram): VersionConstraint {
  const repository = program.sourceRepos[0] ?? "";
  const matchingScope = repository
    ? program.inScope.find(value => value.toLowerCase().includes(repository.toLowerCase()))
    : undefined;
  if (matchingScope) return extractConstraint(matchingScope, repository);
  return extractConstraint("", repository);
}

export function inferVersionConstraintForRepository(program: BountyProgram, repository: string): VersionConstraint {
  const repoLower = repository.toLowerCase();
  const candidates = program.inScope.filter(value => value.toLowerCase().includes(repoLower));
  if (candidates.length === 1) return extractConstraint(candidates[0], repository);
  if (candidates.length > 1) {
    const combined = candidates.join("\n");
    return extractConstraint(combined, repository);
  }
  return extractConstraint("", repository);
}

export function isRepositoryRefEligible(ref: string, constraint: VersionConstraint): boolean | "unknown" {
  if (constraint.requiredCommit) return ref === constraint.requiredCommit;
  if (constraint.requiredRelease) return ref === constraint.requiredRelease || ref === ("v" + constraint.requiredRelease.replace(/^v/, ""));
  return "unknown";
}

export function requiredScanRef(constraint: VersionConstraint): string | undefined {
  return constraint.requiredCommit ?? constraint.requiredRelease;
}
