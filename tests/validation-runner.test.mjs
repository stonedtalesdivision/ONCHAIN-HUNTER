import test from "node:test";
import assert from "node:assert/strict";
import { runLocalFoundryTest } from "../dist/validation-runner.js";

test("execution is blocked unless explicitly enabled", async () => {
  const previous = process.env.ONCHAIN_HUNTER_ALLOW_EXECUTION;
  delete process.env.ONCHAIN_HUNTER_ALLOW_EXECUTION;
  const result = await runLocalFoundryTest();
  assert.equal(result.status, "blocked");
  if (previous !== undefined) process.env.ONCHAIN_HUNTER_ALLOW_EXECUTION = previous;
});
