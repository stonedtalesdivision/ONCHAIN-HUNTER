import "dotenv/config";
import { ImmunefiBountySource } from "../sources/immunefi.js";
import { inferVersionConstraint, isRepositoryRefEligible, requiredScanRef } from "../version-scope.js";
import { listRepositoryFiles, fetchRawFile, resolveRepositoryRevision } from "../github.js";
import { scanSoliditySource } from "../scanner.js";

const args = process.argv.slice(2);
const programId = args[0];
const repository = args[1];
const refIndex = args.indexOf("--ref");
const requestedRef = refIndex >= 0 ? args[refIndex + 1] : undefined;

if (!programId || !repository) {
  console.error("Usage: npm run scan:scoped -- immunefi:<slug> owner/name [--ref <commit|tag>]");
  process.exit(1);
}
if (refIndex >= 0 && !requestedRef) {
  console.error("--ref requires a value");
  process.exit(1);
}

const source = new ImmunefiBountySource();
const programs = await source.discover();
const program = programs.find(p => p.id === programId);
if (!program) {
  console.error(JSON.stringify({ error: "Program not found", programId }, null, 2));
  process.exit(1);
}
if (!program.sourceRepos.some(r => r.toLowerCase() === repository.toLowerCase())) {
  console.error(JSON.stringify({
    error: "Repository is not currently listed in the program source scope",
    programId,
    repository,
    sourceRepos: program.sourceRepos
  }, null, 2));
  process.exit(1);
}

const constraint = inferVersionConstraint(program);
const requiredRef = requiredScanRef(constraint);
const effectiveRef = requestedRef ?? requiredRef;

if (!effectiveRef) {
  console.error(JSON.stringify({
    error: "No exact commit/release was parsed from the current program data",
    action: "Supply an explicit --ref after reviewing the current program scope",
    programId,
    repository,
    notes: constraint.notes
  }, null, 2));
  process.exit(2);
}

const token = process.env.GITHUB_TOKEN;
const revision = await resolveRepositoryRevision(repository, effectiveRef, token);
const scopeMatch = isRepositoryRefEligible(effectiveRef, constraint);
if (scopeMatch === false) {
  console.error(JSON.stringify({
    error: "Resolved revision does not satisfy the parsed program scope",
    programId,
    repository,
    requestedRef: effectiveRef,
    resolvedCommit: revision.commitSha,
    constraint
  }, null, 2));
  process.exit(2);
}

const files = await listRepositoryFiles(repository, token, effectiveRef);
const solidity = files.filter(f => /\.(sol|vy)$/i.test(f.path));
const findings = [];
for (const file of solidity) {
  if (!file.download_url) continue;
  const sourceText = await fetchRawFile(file.download_url, token);
  findings.push(...scanSoliditySource(sourceText, file.path).map(f => ({
    ...f,
    evidence: [
      "program: " + program.id,
      "repository: " + repository,
      "revision: " + revision.commitSha,
      ...f.evidence
    ]
  })));
}

console.log(JSON.stringify({
  program: {
    id: program.id,
    name: program.name,
    url: program.url
  },
  repository,
  requestedRef: effectiveRef,
  resolvedCommit: revision.commitSha,
  scopeMatch: scopeMatch === true ? "yes" : "unknown",
  versionConstraint: constraint,
  filesDiscovered: files.length,
  solidityFiles: solidity.length,
  findings
}, null, 2));
