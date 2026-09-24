import "dotenv/config";
import { writeFile, mkdir } from "node:fs/promises";
import { ImmunefiBountySource } from "../sources/immunefi.js";
import { inferVersionConstraint } from "../version-scope.js";

const source = new ImmunefiBountySource();
const programs = await source.discover();
const versionScopes = programs.map(program => ({
  programId: program.id,
  name: program.name,
  repository: program.sourceRepos[0] ?? null,
  versionScope: inferVersionConstraint(program)
}));
await mkdir("data", { recursive: true });
await writeFile("data/version-scopes.json", JSON.stringify({ generatedAt: new Date().toISOString(), versionScopes }, null, 2), "utf8");
console.log(JSON.stringify({ status: "generated", programs: versionScopes.length, constrained: versionScopes.filter(x => x.versionScope.requiredCommit || x.versionScope.requiredRelease).length }, null, 2));
