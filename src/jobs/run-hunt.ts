import "dotenv/config";
import { ImmunefiBountySource } from "../sources/immunefi.js";
import { inferVersionConstraintForRepository, requiredScanRef } from "../version-scope.js";
import { resolveRepositoryRevision, listRepositoryFiles, fetchRawFile } from "../github.js";
import { scanSoliditySource } from "../scanner.js";
import { writeFile, mkdir } from "node:fs/promises";
import { payoutRoutesForProgram } from "../payout.js";

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
  const payoutConfiguration = programs.filter(p => p.status === "active").map(program => ({
    programId: program.id,
    programName: program.name,
    routes: payoutRoutesForProgram(program)
  }));
  let scannedRepositories = 0;
  let skippedRepositories = 0;
  let attemptedRepositories = 0;
  let rateLimited = false;

  outer:
  for (const program of programs.filter(p => p.status === "active")) {
    for (const repository of program.sourceRepos) {
      const constraint = inferVersionConstraintForRepository(program, repository);
      const ref = requiredScanRef(constraint);
      if (!ref) {
        skippedRepositories++;
        candidates.push({ type: "scope-review-required", programId: program.id, programName: program.name, repository, reason: "No exact release/commit was exposed by the current catalog data." });
        continue;
      }
      if (attemptedRepositories >= limit) break outer;
      attemptedRepositories++;

      console.log(JSON.stringify({ event: "scan-start", programId: program.id, repository, ref }));
      try {
        const revision = await resolveRepositoryRevision(repository, ref, token);
        const files = await listRepositoryFiles(repository, token, ref);
        const solidity = files.filter(f => /\.(sol|vy)$/i.test(f.path));
        let repoFindings = 0;

        for (const file of solidity) {
          if (!file.download_url) continue;
          const sourceText = await fetchRawFile(file.download_url, token);
          for (const finding of scanSoliditySource(sourceText, file.path)) {
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
          break outer;
        }
        candidates.push({ type: "scan-error", programId: program.id, repository, reason });
        console.error(JSON.stringify({ event: "scan-error", programId: program.id, repository, reason }));
      }
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
    candidateFindings: candidates.filter((x: any) => !x.type).length,
    payoutConfiguration,
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
