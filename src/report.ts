import { writeFile, mkdir } from "node:fs/promises";
import type { Opportunity } from "./types.js";
import type { ValidationExecution } from "./validation-runner.js";

export type SecurityReport = {
  schemaVersion: "1.0";
  generatedAt: string;
  finding: Opportunity;
  validation: {
    status: ValidationExecution["status"];
    exitCode: number | null;
    command: string;
    evidenceArtifact?: string;
  };
  assessment: {
    conclusion: "candidate-only" | "locally-reproduced" | "not-reproduced";
    confidence: number;
    impact: string;
    limitations: string[];
  };
  submissionChecklist: string[];
};

export function buildSecurityReport(finding: Opportunity, validation: ValidationExecution): SecurityReport {
  const reproduced = validation.status === "passed";
  return {
    schemaVersion: "1.0",
    generatedAt: new Date().toISOString(),
    finding,
    validation: { status: validation.status, exitCode: validation.exitCode, command: validation.command, evidenceArtifact: validation.artifactPath },
    assessment: {
      conclusion: reproduced ? "locally-reproduced" : validation.status === "failed" ? "not-reproduced" : "candidate-only",
      confidence: finding.confidence,
      impact: "Impact must be demonstrated and tied to the specific bounty program's in-scope impact definitions before submission.",
      limitations: [
        "Static findings are candidates, not confirmed vulnerabilities.",
        "A local test result does not by itself establish bounty eligibility.",
        "Program scope, known issues, release/version requirements, PoC requirements and prohibited activities must be checked before any report is submitted."
      ]
    },
    submissionChecklist: [
      "Confirm the affected asset is explicitly in scope.",
      "Confirm the demonstrated impact is in scope for the program.",
      "Check the program's current PoC and reproduction requirements.",
      "Check known issues/audits and release/version eligibility.",
      "Attach reproducible local evidence and a clear impact explanation.",
      "Do not submit automatically; perform human review first."
    ]
  };
}

export async function writeSecurityReport(report: SecurityReport, outputDir = "artifacts/reports"): Promise<string> {
  await mkdir(outputDir, { recursive: true });
  const path = outputDir + "/" + report.finding.id.replace(/[^a-zA-Z0-9._-]/g, "_") + ".json";
  await writeFile(path, JSON.stringify(report, null, 2), "utf8");
  return path;
}
