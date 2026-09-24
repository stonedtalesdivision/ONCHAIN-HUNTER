import { spawn } from "node:child_process";
import { mkdir, writeFile } from "node:fs/promises";

export type ValidationExecution = {
  status: "passed" | "failed" | "blocked";
  exitCode: number | null;
  command: string;
  stdout: string;
  stderr: string;
  artifactPath?: string;
};

export async function runLocalFoundryTest(testName?: string, cwd = "."): Promise<ValidationExecution> {
  if (process.env.ONCHAIN_HUNTER_ALLOW_EXECUTION !== "1") {
    return { status: "blocked", exitCode: null, command: "forge test", stdout: "", stderr: "Execution disabled. Set ONCHAIN_HUNTER_ALLOW_EXECUTION=1 inside an isolated local validation environment.", };
  }

  const args = ["test", "-vvv"];
  if (testName) args.push("--match-test", testName);
  const command = "forge " + args.join(" ");

  return new Promise(resolve => {
    const child = spawn("forge", args, { cwd, env: { ...process.env }, shell: false });
    let stdout = "", stderr = "";
    child.stdout.on("data", d => { stdout += d.toString(); });
    child.stderr.on("data", d => { stderr += d.toString(); });
    child.on("error", err => resolve({ status: "failed", exitCode: null, command, stdout, stderr: stderr + err.message }));
    child.on("close", async code => {
      const status = code === 0 ? "passed" : "failed";
      const dir = cwd + "/artifacts/onchain-hunter";
      await mkdir(dir, { recursive: true });
      const artifactPath = dir + "/forge-test-" + Date.now() + ".json";
      await writeFile(artifactPath, JSON.stringify({ command, exitCode: code, stdout, stderr }, null, 2), "utf8");
      resolve({ status, exitCode: code, command, stdout, stderr, artifactPath });
    });
  });
}
