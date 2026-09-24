import test from "node:test";
import assert from "node:assert/strict";
import { scanSoliditySource } from "../dist/scanner.js";

test("static scanner reports high-signal Solidity patterns", () => {
  const findings = scanSoliditySource(`function admin() external { require(tx.origin == owner); }\nfunction kill() external { selfdestruct(payable(msg.sender)); }`, "Example.sol");
  assert.equal(findings.length, 2);
  assert.equal(findings[0].severity, "high");
  assert.equal(findings[1].category, "destructive-operation");
});
