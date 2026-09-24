import test from "node:test";
import assert from "node:assert/strict";
import { isRepositoryRefEligible } from "../dist/version-scope.js";

test("exact commit scope only accepts the exact commit", () => {
  const c = { repository: "a/b", requiredCommit: "a".repeat(40), notes: [] };
  assert.equal(isRepositoryRefEligible("a".repeat(40), c), true);
  assert.equal(isRepositoryRefEligible("b".repeat(40), c), false);
});

test("release scope accepts v-prefixed or unprefixed tag", () => {
  const c = { repository: "a/b", requiredRelease: "1.2.3", notes: [] };
  assert.equal(isRepositoryRefEligible("1.2.3", c), true);
  assert.equal(isRepositoryRefEligible("v1.2.3", c), true);
});
