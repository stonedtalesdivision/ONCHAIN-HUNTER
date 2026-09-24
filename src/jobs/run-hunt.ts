import "dotenv/config";
import { ImmunefiBountySource } from "../sources/immunefi.js";
import { inferVersionConstraint, requiredScanRef } from "../version-scope.js";
import { resolveRepositoryRevision, listRepositoryFiles, fetchRawFile } from "../github.js";
import { scanSoliditySource } from "../scanner.js";
import { writeFile, mkdir } from "node:fs/promises";

const limit = Math.max(1, Number(process.env.ONCHAIN_HUNTER_LIMIT ?? "5"));
const token = process.env.GITHUB_TOKEN;
const source = new ImmunefiBountySource();
const programs = await source.discover();
const candidates: unknown[] = [];
let scannedRepositories = 0;
let skippedRepositories = 0;

outer:
for (const program of programs.filter(p => p.status === "active")) {
  for (const repository of program.sourceRepos) {
    if (scannedRepositories >= limit) break outer;
    const constraint = inferVersionConstraint(program);
    const ref = requiredScanRef(constraint);
    if (!ref) {
      skippedRepositories++;
      candidates.push({
        type: "scope-review-required",
        programId: program.id,
        programName: program.name,
        repository,
        reason: "No exact release/commit was exposed by the current catalog data."
      });
      continue;
    }

    try {
      const revision = await resolveRepositoryRevision(repository, ref, token);
      const files = await listRepositoryFiles(repository, token, ref);
      const solidity = files.filter(f => /\.(sol|vy)$/i.test(f.path));
      for (const file of solidity) {
        if (!file.download_url) continue;
        const sourceText = await fetchRawFile(file.download_url, token);
        for (const finding of scanSoliditySource(sourceText, file.path)) {
          candidates.push({
            ...finding,
            id: `${program.id}:${repository}:${revision.commitSha}:${finding.id}`,
            programId: program.id,
            repository,
            sourceRevision: revision.commitSha,
            scopeMatch: "yes",
            evidence: [
              `program: ${program.id}`,
              `repository: ${repository}`,
              `revision: ${revision.commitSha}`,
              ...finding.evidence
            ]
          });
        }
      }
      scannedRepositories++;
    } catch (error) {
      skippedRepositories++;
      candidates.push({
        type: "scan-error",
        programId: program.id,
        repository,
        reason: error instanceof Error ? error.message : String(error)
      });
    }
  }
}

await mkdir("artifacts/hunt", { recursive: true });
const path = "artifacts/hunt/latest.json";
const result = {
  generatedAt: new Date().toISOString(),
  source: source.name,
  programsDiscovered: programs.length,
  scannedRepositories,
  skippedRepositories,
  candidateFindings: candidates.filter((x: any) => !x.type).length,
  results: candidates
};
await writeFile(path, JSON.stringify(result, null, 2), "utf8");
console.log(JSON.stringify(result, null, 2));
