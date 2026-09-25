import type { BountyProgram } from "./types.js";
import { inferVersionConstraintForRepository, requiredScanRef } from "./version-scope.js";

export type ScanTarget = {
  program: BountyProgram;
  repository: string;
  ref: string;
  score: number;
  reasons: string[];
};

const HIGH_VALUE_SURFACES = [
  "vault", "router", "bridge", "proxy", "upgrade", "governance",
  "controller", "manager", "oracle", "lending", "borrow", "withdraw",
  "deposit", "claim", "settlement", "token", "treasury", "staking",
  "market", "pool", "factory", "escrow"
];

function rewardScore(maxReward?: number): number {
  if (!maxReward || maxReward <= 0) return 0;
  if (maxReward >= 1_000_000) return 30;
  if (maxReward >= 500_000) return 26;
  if (maxReward >= 250_000) return 22;
  if (maxReward >= 100_000) return 18;
  if (maxReward >= 50_000) return 14;
  if (maxReward >= 25_000) return 10;
  return 5;
}

function surfaceScore(program: BountyProgram, repository: string): { score: number; reasons: string[] } {
  const haystack = [
    program.name,
    repository,
    ...program.inScope,
    ...program.chains
  ].join(" ").toLowerCase();

  const hits = HIGH_VALUE_SURFACES.filter(keyword => haystack.includes(keyword));
  if (!hits.length) return { score: 0, reasons: [] };

  return {
    score: Math.min(24, hits.length * 4),
    reasons: ["Security-relevant surface keywords: " + hits.slice(0, 6).join(", ")]
  };
}

function programScore(program: BountyProgram): { score: number; reasons: string[] } {
  const reasons: string[] = [];
  let score = rewardScore(program.maxReward);
  if (program.maxReward && program.maxReward >= 250_000) {
    reasons.push("Substantial published maximum bounty.");
  }

  if (program.sourceRepos.length > 1) {
    score += Math.min(10, program.sourceRepos.length * 2);
    reasons.push(program.sourceRepos.length + " source repositories available.");
  } else if (program.sourceRepos.length === 1) {
    score += 3;
    reasons.push("Public source repository available.");
  }

  if (program.chains.length > 0) {
    score += Math.min(8, program.chains.length);
    reasons.push(program.chains.length + " ecosystem/network entries exposed.");
  }

  return { score, reasons };
}

export function prioritizeScanTargets(programs: BountyProgram[]): ScanTarget[] {
  const targets: ScanTarget[] = [];

  for (const program of programs.filter(p => p.status === "active")) {
    const base = programScore(program);

    for (const repository of program.sourceRepos) {
      const constraint = inferVersionConstraintForRepository(program, repository);
      const ref = requiredScanRef(constraint);
      if (!ref) continue;

      const surface = surfaceScore(program, repository);
      targets.push({
        program,
        repository,
        ref,
        score: base.score + surface.score + 12,
        reasons: [
          ...base.reasons,
          "Exact release/commit scope is available.",
          ...surface.reasons
        ]
      });
    }
  }

  return targets.sort((a, b) =>
    b.score - a.score ||
    a.program.name.localeCompare(b.program.name) ||
    a.repository.localeCompare(b.repository)
  );
}
