import { runLocalFoundryTest } from "../validation-runner.js";
const testName = process.argv[2];
const result = await runLocalFoundryTest(testName);
console.log(JSON.stringify(result, null, 2));
process.exitCode = result.status === "failed" ? 1 : 0;
