import test from "node:test";
import assert from "node:assert/strict";
import { analyzeSolidityStructure, structuralFindings } from "../dist/structural-analysis.js";

test("extracts function structure, state writes, calls and access control", () => {
  const source = [
    "contract Vault {",
    "  address public owner;",
    "  uint256 public total;",
    "  function deposit(uint256 amount) external payable { total += amount; }",
    "  function adminWithdraw(address recipient, uint256 amount) external onlyOwner {",
    "    total -= amount;",
    '    recipient.call{value: amount}("");',
    "  }",
    "}"
  ].join("\n");

  const analysis = analyzeSolidityStructure(source, "Vault.sol");
  assert.deepEqual(analysis.contracts, ["Vault"]);
  assert.ok(analysis.stateVariables.includes("owner"));
  assert.ok(analysis.stateVariables.includes("total"));
  const deposit = analysis.functions.find(x => x.name === "deposit");
  assert.ok(deposit);
  assert.equal(deposit.visibility, "external");
  assert.equal(deposit.mutability, "payable");
  assert.deepEqual(deposit.stateWrites, ["total"]);

  const withdraw = analysis.functions.find(x => x.name === "adminWithdraw");
  assert.ok(withdraw);
  assert.equal(withdraw.accessControlled, true);
  assert.ok(withdraw.valueTransfers.includes("recipient"));
});

test("flags high-signal user-controlled delegatecall without detected authorization", () => {
  const source = [
    "contract Proxy {",
    "  function execute(address target, bytes calldata data) external {",
    "    target.delegatecall(data);",
    "  }",
    "}"
  ].join("\n");

  const analysis = analyzeSolidityStructure(source, "Proxy.sol");
  const findings = structuralFindings(analysis);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].severity, "critical");
  assert.match(findings[0].title, /delegatecall/i);
});

test("does not flag an access-controlled upgrade function", () => {
  const source = [
    "contract ProxyAdmin {",
    "  address implementation;",
    "  function upgradeTo(address newImplementation) external onlyOwner {",
    "    implementation = newImplementation;",
    "  }",
    "}"
  ].join("\n");

  const findings = structuralFindings(analyzeSolidityStructure(source, "ProxyAdmin.sol"));
  assert.equal(findings.length, 0);
});
