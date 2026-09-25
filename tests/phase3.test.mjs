import test from "node:test";
import assert from "node:assert/strict";
import { analyzeSolidityStructure } from "../dist/structural-analysis.js";
import { detectPhase3 } from "../dist/detectors/phase3.js";

function scan(source) {
  return detectPhase3(analyzeSolidityStructure(source, "Test.sol"));
}

test("detects arbitrary external call", () => {
  const f = scan(`contract T { function execute(address target, bytes calldata data) external { target.call(data); } }`);
  assert.ok(f.some(x => x.category === "external-call"));
});

test("detects unauthorized token movement", () => {
  const f = scan(`contract T { function sweep(address token, address recipient, uint amount) external { token.transfer(recipient, amount); } }`);
  assert.ok(f.some(x => x.category === "asset-transfer"));
});

test("detects delegatecall takeover", () => {
  const f = scan(`contract T { function upgrade(address implementation) external { implementation.delegatecall(""); } }`);
  assert.ok(f.some(x => x.category === "delegatecall" || x.category === "upgrade-takeover"));
});

test("detects reentrancy candidate", () => {
  const f = scan(`contract T { uint balance; function withdraw(address recipient, uint amount) external { recipient.call{value: amount}(""); balance -= amount; } }`);
  assert.ok(f.some(x => x.category === "reentrancy"));
});

test("detects signature replay candidate", () => {
  const f = scan(`contract T { function execute(bytes sig, bytes32 digest) external { ecrecover(digest,27,bytes32(0),bytes32(0)); } }`);
  assert.ok(f.some(x => x.category === "signature-replay"));
});

test("detects unguarded initialization", () => {
  const f = scan(`contract T { function initialize(address admin) external { owner = admin; } }`);
  assert.ok(f.some(x => x.category === "initialization"));
});
