import test from "node:test";
import assert from "node:assert/strict";
import { mkdir, rm, readFile } from "node:fs/promises";
import { updateMonitoringState } from "../dist/monitoring.js";

test("phase 8 detects added and changed monitoring records", async () => {
  await rm("artifacts/monitoring", { recursive: true, force: true });
  await mkdir("artifacts", { recursive: true });

  const first = await updateMonitoringState(
    { p1: { status: "active", url: "https://example.test/p1", chains: ["Ethereum"], sourceRepos: ["org/repo"] } },
    { "p1:org/repo": { programId: "p1", repository: "org/repo", ref: "main", score: 10 } },
    { f1: { severity: "high", repository: "org/repo", sourceRevision: "abc", title: "Finding" } }
  );
  assert.equal(first.events.length, 3);

  const second = await updateMonitoringState(
    { p1: { status: "active", url: "https://example.test/p1", chains: ["Ethereum"], sourceRepos: ["org/repo"] } },
    { "p1:org/repo": { programId: "p1", repository: "org/repo", ref: "def", score: 12 } },
    { f1: { severity: "critical", repository: "org/repo", sourceRevision: "def", title: "Finding" } }
  );
  assert.equal(second.events.filter((e) => e.type === "target-changed").length, 1);
  assert.equal(second.events.filter((e) => e.type === "finding-changed").length, 1);

  const saved = JSON.parse(await readFile("artifacts/monitoring/latest-events.json", "utf8"));
  assert.equal(saved.schemaVersion, "phase-8");
});
