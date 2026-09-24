import test from "node:test";
import assert from "node:assert/strict";
import { scanSoliditySource } from "../dist/scanner.js";

test("ignores obvious comments", () => {
  const findings = scanSoliditySource("// tx.origin\n/* selfdestruct(msg.sender) */", "Comments.sol");
  assert.equal(findings.length, 0);
});

test("raises contextual confidence for authorization-related tx.origin", () => {
  const findings = scanSoliditySource("function admin() external { require(tx.origin == owner); }", "Auth.sol");
  assert.equal(findings.length, 1);
  assert.ok(findings[0].confidence > 0.82);
});

test("low-level call with success handling is down-weighted", () => {
  const findings = scanSoliditySource("(bool success,) = target.call(data); require(success);", "Call.sol");
  assert.equal(findings.length, 1);
  assert.ok(findings[0].confidence < 0.55);
});
