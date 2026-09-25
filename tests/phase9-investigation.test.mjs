import test from "node:test";
import assert from "node:assert/strict";
import { buildInvestigationRecord } from "../dist/investigation.js";

const base = {
  packageId: "pkg-1",
  findingId: "finding-1",
  title: "Test finding",
  file: "src/Vault.sol",
  severity: "high",
  confidence: 0.9,
  categories: ["access-control"],
  impact: "asset-loss",
  exploitability: "direct",
  scopeConfidence: "exact-revision",
  attackPath: ["attacker-controlled input", "reachable function", "asset impact"],
  transactionSequence: [
    { order: 1, function: "withdraw", role: "entry", evidence: "entry" },
    { order: 2, function: "withdraw", role: "asset-impact", evidence: "transfer" }
  ],
  corroborationCount: 2,
  evidence: ["program", "repository", "revision"],
  reviewQuestions: [],
  validationPlan: ["local test"],
  repository: "org/repo",
  sourceRevision: "abc",
  submissionReady: false
};

test("phase 9 detects revision changes and computes investigation priority", () => {
  const first = buildInvestigationRecord(base);
  assert.equal(first.revisionChanged, false);
  const second = buildInvestigationRecord({ ...base, sourceRevision: "def" }, first);
  assert.equal(second.revisionChanged, true);
  assert.equal(second.previousRevision, "abc");
  assert.ok(second.priority > first.priority);
  assert.equal(second.missingEvidence.length, 0);
});
