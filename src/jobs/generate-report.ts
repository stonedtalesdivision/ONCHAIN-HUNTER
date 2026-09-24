import { readFile } from "node:fs/promises";
import { buildSecurityReport, writeSecurityReport } from "../report.js";
import type { Opportunity } from "../types.js";
import type { ValidationExecution } from "../validation-runner.js";

const findingPath = process.argv[2];
const validationPath = process.argv[3];
if (!findingPath || !validationPath) {
  console.error("Usage: npm run report:generate -- finding.json validation.json");
  process.exit(1);
}
const finding = JSON.parse(await readFile(findingPath, "utf8")) as Opportunity;
const validation = JSON.parse(await readFile(validationPath, "utf8")) as ValidationExecution;
const report = buildSecurityReport(finding, validation);
const path = await writeSecurityReport(report);
console.log(JSON.stringify({ status: "generated", path, report }, null, 2));
