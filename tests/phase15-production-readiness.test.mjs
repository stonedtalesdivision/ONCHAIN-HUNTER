import test from "node:test";
import assert from "node:assert/strict";
import { buildProductionReadiness } from "../dist/production-readiness.js";

test("final product readiness preserves safety gates", async () => {
  const r = await buildProductionReadiness(process.cwd());
  assert.equal(r.schemaVersion, "phase-15");
  assert.equal(r.release, "final");
  assert.equal(r.humanReviewOnly, true);
  assert.equal(r.liveExecutionEnabled, false);
  assert.equal(r.automaticSubmissionEnabled, false);
  assert.ok(r.checks.some(c => c.id === "no-live-execution" && c.status === "pass"));
  assert.ok(r.checks.some(c => c.id === "no-auto-submit" && c.status === "pass"));
});
