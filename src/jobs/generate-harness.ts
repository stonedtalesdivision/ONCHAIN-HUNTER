import { writeFile, mkdir } from "node:fs/promises";
import { generateFoundryHarness } from "../harness.js";
import type { Opportunity } from "../types.js";

const findingFile = process.argv[2];
if (!findingFile) {
  console.error("Usage: npm run harness:generate -- finding.json");
  process.exit(1);
}
const raw = await import("node:fs/promises").then(fs => fs.readFile(findingFile, "utf8"));
const finding = JSON.parse(raw) as Opportunity;
const harness = generateFoundryHarness(finding);
await mkdir("test/onchain-hunter", { recursive: true });
await writeFile(harness.path, harness.content, "utf8");
console.log(JSON.stringify({ status: "generated", ...harness }, null, 2));
