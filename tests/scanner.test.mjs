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

test("ignores obvious test and mock files", () => {
  const findings = scanSoliditySource("selfdestruct(msg.sender);\n tx.origin;", "src/contracts/test/SmartSellOrder.sol");
  assert.equal(findings.length, 0);
  const mockFindings = scanSoliditySource("delegatecall(data);", "contracts/mocks/RouterMock.sol");
  assert.equal(mockFindings.length, 0);
});

test("keeps production Solidity candidates", () => {
  const findings = scanSoliditySource("function execute() external { (bool ok,) = target.call(data); }", "src/contracts/Router.sol");
  assert.equal(findings.length, 1);
  assert.equal(findings[0].category, "external-call");
});
