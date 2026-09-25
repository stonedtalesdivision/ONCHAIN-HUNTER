import "dotenv/config";
import { ImmunefiBountySource } from "../sources/immunefi.js";
import { inferVersionConstraintForRepository, requiredScanRef } from "../version-scope.js";
import { resolveRepositoryRevision, listRepositoryFiles, fetchRawFile } from "../github.js";
import { scanSoliditySource } from "../scanner.js";
import { writeFile, mkdir } from "node:fs/promises";
import { payoutRoutesForProgram } from "../payout.js";
import { prioritizeScanTargets } from "../target-prioritizer.js";
import { analyzeSolidityStructure, structuralFindings } from "../structural-analysis.js";

async function main(): Promise<void> {
  const hasToken = Boolean(process.env.GITHUB_TOKEN);
  const configuredLimit = Number(process.env.ONCHAIN_HUNTER_LIMIT ?? (hasToken ? "5" : "1"));
  const limit = Math.max(1, Math.min(Number.isFinite(configuredLimit) ? configuredLimit : 1, 20));
  const token = process.env.GITHUB_TOKEN;
  const source = new ImmunefiBountySource();

  console.log(JSON.stringify({ event: "hunt-start", repositoryLimit: limit, authenticatedGitHub: hasToken }));
  const programs = await source.discover();
  console.log(JSON.stringify({ event: "catalog-loaded", programsDiscovered: programs.length }));

  const candidates: unknown[] = [];
  const structuralSummaries: unknown[] = [];
  const payoutConfiguration = programs.filter(p => p.status === "active").map(program => ({
    programId: program.id,
    programName: program.name,
    routes: payoutRoutesForProgram(program)
  }));
  let scannedRepositories = 0;
  let skippedRepositories = 0;
  let attemptedRepositories = 0;
  let rateLimited = false;

  const activePrograms = programs.filter(p => p.status === "active");
  const allRepositoryCount = activePrograms.reduce((total, program) => total + program.sourceRepos.length, 0);
  const targets = prioritizeScanTargets(activePrograms);
  const scopeReviewRequired = Math.max(0, allRepositoryCount - targets.length);
  const selectedTargets = targets.slice(0, limit);

  console.log(JSON.stringify({
    event: "targets-prioritized",
    activePrograms: activePrograms.length,
    repositoriesAvailable: allRepositoryCount,
    exactScopeTargets: targets.length,
    scopeReviewRequired,
    selected: selectedTargets.map(target => ({ programId: target.program.id, repository: target.repository, ref: target.ref, score: target.score }))
  }));

  for (const target of selectedTargets) {
    const { program, repository, ref } = target;
    attemptedRepositories++;

    console.log(JSON.stringify({ event: "scan-start", programId: program.id, repository, ref, priorityScore: target.score, priorityReasons: target.reasons }));
      try {
        const revision = await resolveRepositoryRevision(repository, ref, token);
        const files = await listRepositoryFiles(repository, token, ref);
        const solidity = files.filter(f => /\.(sol|vy)$/i.test(f.path));
        let repoFindings = 0;

        const structuralFiles: unknown[] = [];
        for (const file of solidity) {
          if (!file.download_url) continue;
          const sourceText = await fetchRawFile(file.download_url, token);
          const structure = analyzeSolidityStructure(sourceText, file.path);
          structuralFiles.push(structure);
          structuralSummaries.push(structure);

          for (const finding of [...scanSoliditySource(sourceText, file.path), ...structuralFindings(structure)]) {
            repoFindings++;
            candidates.push({
              ...finding,
              id: `${program.id}:${repository}:${revision.commitSha}:${finding.id}`,
              programId: program.id,
              repository,
              sourceRevision: revision.commitSha,
              scopeMatch: "yes",
              payoutRoutes: payoutRoutesForProgram(program),
              evidence: [`program: ${program.id}`, `repository: ${repository}`, `revision: ${revision.commitSha}`, ...finding.evidence]
            });
          }
        }

        scannedRepositories++;
        console.log(JSON.stringify({ event: "scan-complete", repository, solidityFiles: solidity.length, findings: repoFindings }));
      } catch (error) {
        skippedRepositories++;
        const reason = error instanceof Error ? error.message : String(error);
        if (reason.startsWith("GitHub API rate limit exhausted;")) {
          rateLimited = true;
          console.error(JSON.stringify({ event: "rate-limit", reason }));
          break;
        }
        candidates.push({ type: "scan-error", programId: program.id, repository, reason });
        console.error(JSON.stringify({ event: "scan-error", programId: program.id, repository, reason }));
      }
  }

  await mkdir("artifacts/hunt", { recursive: true });
  const path = "artifacts/hunt/latest.json";
  const result = {
    generatedAt: new Date().toISOString(),
    source: source.name,
    programsDiscovered: programs.length,
    attemptedRepositories,
    scannedRepositories,
    rateLimited,
    skippedRepositories,
    scopeReviewRequired,
    targetPlan: targets.slice(0, Math.min(targets.length, 50)).map(target => ({
      programId: target.program.id,
      programName: target.program.name,
      repository: target.repository,
      ref: target.ref,
      score: target.score,
      reasons: target.reasons
    })),
    candidateFindings: candidates.filter((x: any) => !x.type).length,
    payoutConfiguration,
    structuralAnalysis: structuralSummaries,
    results: candidates
  };
  await writeFile(path, JSON.stringify(result, null, 2), "utf8");
  console.log(JSON.stringify(result, null, 2));
}

main().catch(error => {
  console.error(JSON.stringify({
    event: "hunt-fatal",
    error: error instanceof Error ? { name: error.name, message: error.message, stack: error.stack } : String(error)
  }, null, 2));
  process.exitCode = 1;
});
