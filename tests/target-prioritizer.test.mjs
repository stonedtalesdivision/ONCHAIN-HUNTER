import test from "node:test";
import assert from "node:assert/strict";
import { prioritizeScanTargets } from "../dist/target-prioritizer.js";

function program(overrides = {}) {
  return {
    id: "immunefi:test",
    name: "Test Protocol",
    platform: "Immunefi",
    url: "https://immunefi.com/bug-bounty/test/",
    status: "active",
    maxReward: 100000,
    rewardCurrency: "USDC",
    chains: ["ETH"],
    inScope: ["https://github.com/example/protocol/tree/v1.2.3"],
    sourceRepos: ["example/protocol"],
    fetchedAt: new Date().toISOString(),
    ...overrides
  };
}

test("prioritizer returns only repositories with exact scope refs", () => {
  const targets = prioritizeScanTargets([
    program(),
    program({
      id: "immunefi:unknown",
      name: "Unknown Scope",
      sourceRepos: ["example/unknown"],
      inScope: ["https://github.com/example/unknown"]
    })
  ]);

  assert.equal(targets.length, 1);
  assert.equal(targets[0].repository, "example/protocol");
  assert.equal(targets[0].ref, "v1.2.3");
});

test("prioritizer favors higher-value security surfaces", () => {
  const plain = program({
    id: "immunefi:plain",
    name: "Plain Protocol",
    sourceRepos: ["example/plain"],
    inScope: ["https://github.com/example/plain/tree/v1.0.0"],
    maxReward: 100000
  });
  const vault = program({
    id: "immunefi:vault",
    name: "Vault Protocol",
    sourceRepos: ["example/vault"],
    inScope: ["https://github.com/example/vault/tree/v1.0.0/vault"],
    maxReward: 100000
  });

  const targets = prioritizeScanTargets([plain, vault]);
  assert.equal(targets[0].repository, "example/vault");
  assert.ok(targets[0].score > targets[1].score);
});

test("prioritizer rewards published bounty ceiling without treating it as a finding", () => {
  const low = program({
    id: "immunefi:low",
    sourceRepos: ["example/low"],
    inScope: ["https://github.com/example/low/tree/v1.0.0"],
    maxReward: 25000
  });
  const high = program({
    id: "immunefi:high",
    sourceRepos: ["example/high"],
    inScope: ["https://github.com/example/high/tree/v1.0.0"],
    maxReward: 1000000
  });

  const targets = prioritizeScanTargets([low, high]);
  assert.equal(targets[0].repository, "example/high");
  assert.ok(targets[0].score > targets[1].score);
});
