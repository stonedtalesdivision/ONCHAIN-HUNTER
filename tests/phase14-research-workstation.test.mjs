import test from "node:test";
import assert from "node:assert/strict";
import { buildResearchWorkstation } from "../dist/research-workstation.js";

const pkg = {
  packageId: "pkg-1",
  findingId: "finding-1",
  programId: "program-1",
  title: "Unauthorized state transition",
  severity: "high",
  confidence: 0.9,
  evidence: ["a", "b", "c"],
  attackPath: ["entry", "state change", "impact"],
  transactionSequence: ["call", "write"],
  bountyMatches: [{ programId: "program-1" }]
};

test("phase 14 builds a human-review workstation", () => {
  const result = buildResearchWorkstation(
    [pkg],
    { schemaVersion: "phase-9", updatedAt: new Date().toISOString(), records: {
      "finding-1": {
        schemaVersion: "phase-9", packageId: "pkg-1", findingId: "finding-1",
        fingerprint: "fp", relatedFiles: ["A.sol"], relatedFunctions: ["A.x"],
        revisionChanged: false, validationPlan: [], missingEvidence: [], blockers: [],
        priority: 91, updatedAt: new Date().toISOString()
      }
    }},
    { schemaVersion: "phase-10", generatedAt: new Date().toISOString(), executionEnabled: false, selected: null, queue: [] },
    [{ schemaVersion: "phase-11", packageId: "pkg-1", findingId: "finding-1", fingerprint: "fp", claims: [], attackPath: ["a"], transactionSequence: ["b"], gaps: [], proofScore: 85, humanReviewRequired: true }],
    [{ schemaVersion: "phase-12", packageId: "pkg-1", findingId: "finding-1", harnessPath: "test/x", proofPath: "artifacts/x", commands: ["forge test"], status: "prepared", executionEnabled: false, safety: { localOnly: true, liveNetworkTraffic: false, explicitExecutionRequired: true } }],
    [{ schemaVersion: "phase-13", programId: "program-1", programName: "Example", programUrl: "https://example.com", repository: "org/repo", scopeConfidence: "exact-repository", reward: { maxReward: 1000 }, chainSignals: [], scopeSignals: [], riskSignals: [], requirements: { pocRequired: "unknown", kycRequired: "unknown", prohibitedActivities: [], impactCategories: [], knownIssueNotes: [], sourceUrl: null }, freshness: { fetchedAt: new Date().toISOString(), ageHours: 0, stale: false }, intelligenceScore: 80, reasons: [] }]
  );
  assert.equal(result.schemaVersion, "phase-14");
  assert.equal(result.humanReviewOnly, true);
  assert.equal(result.submissionEnabled, false);
  assert.equal(result.summary.total, 1);
  assert.equal(result.items[0].proofScore, 85);
  assert.equal(result.items[0].validationStatus, "prepared");
});
