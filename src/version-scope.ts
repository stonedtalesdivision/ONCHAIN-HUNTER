import type { BountyProgram } from "./types.js";

export type VersionConstraint = {
  repository: string;
  requiredRef?: string;
  requiredCommit?: string;
  requiredRelease?: string;
  notes: string[];
};

export function inferVersionConstraint(program: BountyProgram): VersionConstraint {
  const text = [...program.inScope, ...program.sourceRepos].join("\n");
  const commit = text.match(/\b[0-9a-f]{40}\b/i)?.[0];
  const release = text.match(/\bv?\d+\.\d+\.\d+(?:-[A-Za-z0-9.-]+)?\b/)?.[0];
  const notes: string[] = [];
  if (commit) notes.push("Program scope contains an exact commit reference.");
  if (release) notes.push("Program scope contains an explicit release/version reference.");
  if (!commit && !release) notes.push("No exact commit/release was parsed; consult the current program scope before reporting.");
  return {
    repository: program.sourceRepos[0] ?? "",
    requiredCommit: commit,
    requiredRelease: release,
    notes
  };
}

export function isRepositoryRefEligible(ref: string, constraint: VersionConstraint): boolean | "unknown" {
  if (constraint.requiredCommit) return ref === constraint.requiredCommit;
  if (constraint.requiredRelease) return ref === constraint.requiredRelease || ref === ("v" + constraint.requiredRelease.replace(/^v/, ""));
  return "unknown";
}
\nexport function requiredScanRef(constraint: VersionConstraint): string | undefined {\n  return constraint.requiredCommit ?? constraint.requiredRelease;\n}\n