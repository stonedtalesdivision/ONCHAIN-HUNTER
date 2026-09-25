import test from "node:test";
import assert from "node:assert/strict";
import { analyzeSolidityStructure } from "../dist/structural-analysis.js";
import { detectBrokenAccessControl } from "../dist/detectors/access-control.js";

test("detects an unprotected privileged state change", () => {
  const source = [
    "contract Admin {",
    "  address public owner;",
    "  function setOwner(address newOwner) external {",
    "    owner = newOwner;",
    "  }",
    "}"
  ].join("\n");

  const findings = detectBrokenAccessControl(analyzeSolidityStructure(source, "Admin.sol"));
  assert.equal(findings.length, 1);
  assert.equal(findings[0].severity, "critical");
  assert.match(findings[0].title, /broken access control/i);
  assert.match(findings[0].evidence.join(" "), /owner/);
});

test("does not flag an access-controlled privileged state change", () => {
  const source = [
    "contract Admin {",
    "  address public owner;",
    "  function setOwner(address newOwner) external onlyOwner {",
    "    owner = newOwner;",
    "  }",
    "}"
  ].join("\n");

  const findings = detectBrokenAccessControl(analyzeSolidityStructure(source, "Admin.sol"));
  assert.equal(findings.length, 0);
});

test("does not flag ordinary user state changes", () => {
  const source = [
    "contract Vault {",
    "  uint256 public balance;",
    "  function deposit(uint256 amount) external {",
    "    balance += amount;",
    "  }",
    "}"
  ].join("\n");

  const findings = detectBrokenAccessControl(analyzeSolidityStructure(source, "Vault.sol"));
  assert.equal(findings.length, 0);
});
