import "dotenv/config";
import { listRepositoryFiles, fetchRawFile } from "../github.js";
import { scanSoliditySource } from "../scanner.js";
const repo = process.argv[2];
if (!repo) { console.error("Usage: npm run scan:repo -- owner/name"); process.exit(1); }
const token = process.env.GITHUB_TOKEN;
const files = await listRepositoryFiles(repo, token);
const solidity = files.filter(f => /\.(sol|vy)$/i.test(f.path));
const findings = [];
for (const file of solidity) {
  if (!file.download_url) continue;
  const source = await fetchRawFile(file.download_url, token);
  findings.push(...scanSoliditySource(source, file.path).map(f => ({ ...f, evidence: ["repository: " + repo, ...f.evidence] })));
}
console.log(JSON.stringify({ repository: repo, filesDiscovered: files.length, solidityFiles: solidity.length, findings: findings.length, findings }, null, 2));
