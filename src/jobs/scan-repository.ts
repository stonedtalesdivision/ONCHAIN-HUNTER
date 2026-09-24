import "dotenv/config";
import { listRepositoryFiles, fetchRawFile, resolveRepositoryRevision } from "../github.js";
import { scanSoliditySource } from "../scanner.js";

const args = process.argv.slice(2);
const repo = args[0];
const refIndex = args.indexOf("--ref");
const ref = refIndex >= 0 ? args[refIndex + 1] : process.env.ONCHAIN_HUNTER_REF;
if (!repo) { console.error("Usage: npm run scan:repo -- owner/name [--ref <commit|tag|branch>]"); process.exit(1); }
if (refIndex >= 0 && !ref) { console.error("--ref requires a value"); process.exit(1); }

const token = process.env.GITHUB_TOKEN;
const revision = ref ? await resolveRepositoryRevision(repo, ref, token) : undefined;
const files = await listRepositoryFiles(repo, token, ref);
const solidity = files.filter(f => /\.(sol|vy)$/i.test(f.path));
const findings = [];
for (const file of solidity) {
  if (!file.download_url) continue;
  const source = await fetchRawFile(file.download_url, token);
  findings.push(...scanSoliditySource(source, file.path).map(f => ({
    ...f,
    evidence: ["repository: " + repo, "revision: " + (revision?.commitSha ?? "default-branch"), ...f.evidence]
  })));
}
console.log(JSON.stringify({
  repository: repo,
  requestedRef: revision?.requestedRef ?? null,
  commitSha: revision?.commitSha ?? null,
  filesDiscovered: files.length,
  solidityFiles: solidity.length,
  findings
}, null, 2));
