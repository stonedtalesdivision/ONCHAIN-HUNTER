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

test("filters ordinary expiry timestamp checks", () => {
  const findings = scanSoliditySource(
    'require(order.validTo >= block.timestamp, "expired");',
    "Settlement.sol"
  );
  assert.equal(findings.length, 0);
});

test("filters ordinary self-call plumbing", () => {
  const findings = scanSoliditySource(
    "(, response) = address(this).call(innerCall);",
    "StorageAccessible.sol"
  );
  assert.equal(findings.length, 0);
});

test("extracts contextual reachability and target-control evidence", () => {
  const findings = scanSoliditySource(
    'function execute(address targetContract, bytes calldata calldataPayload) external onlyOwner {\n' +
    '  (success, response) = targetContract.delegatecall(calldataPayload);\n' +
    '}',
    "Storage.sol"
  );
  assert.equal(findings.length, 1);
  assert.ok(findings[0].evidence.some(x => x.includes("context.function=execute")));
  assert.ok(findings[0].evidence.some(x => x.includes("context.reachability=restricted")));
  assert.ok(findings[0].evidence.some(x => x.includes("context.accessControl=true")));
  assert.ok(findings[0].evidence.some(x => x.includes("context.targetControl=user-influenced")));
});

test("filters intentional reverting delegatecall simulation wrappers", () => {
  const source = [
    "function simulateDelegatecall(address targetContract, bytes memory payload) public returns (bytes memory) {",
    "  return this.simulateDelegatecallInternal(targetContract, payload);",
    "}",
    "function simulateDelegatecallInternal(address targetContract, bytes memory payload) external returns (bytes memory response) {",
    "  (success, response) = targetContract.delegatecall(payload);",
    "  revertWith(abi.encodePacked(response, success));",
    "}",
    "function revertWith(bytes memory response) internal pure {",
    "  revert();",
    "}"
  ].join("\n");
  const findings = scanSoliditySource(source, "StorageAccessible.sol");
  assert.equal(findings.length, 0);
});

test("filters ordinary timestamp bookkeeping", () => {
  const findings = scanSoliditySource(
    'lastAddedAt[_account] = block.timestamp;',
    "Vault.sol"
  );
  assert.equal(findings.length, 0);
});

test("filters ordinary timestamp interval accounting", () => {
  const findings = scanSoliditySource(
    'if (lastFundingTime + fundingInterval > block.timestamp) return;',
    "Vault.sol"
  );
  assert.equal(findings.length, 0);
});

test("keeps timestamp in security-sensitive randomness context", () => {
  const findings = scanSoliditySource(
    'uint256 seed = uint256(keccak256(abi.encodePacked(block.timestamp, msg.sender)));\n' +
    'require(seed % 100 == 0);',
    "Lottery.sol"
  );
  assert.equal(findings.length, 1);
});
