import test from "node:test";
import assert from "node:assert/strict";
import { analyzeSolidityStructure } from "../dist/structural-analysis.js";
import { buildEvidenceGraph } from "../dist/evidence-graph.js";

test("builds an attacker-to-impact evidence path", () => {
  const source = `contract Vault { uint balance; function withdraw(address recipient, uint amount) external { recipient.call{value: amount}(""); balance -= amount; } }`;
  const analysis = analyzeSolidityStructure(source, "Vault.sol");
  const fn = analysis.functions[0];
  const finding = { id: "finding-1", programId: "p", title: "test", category: "reentrancy", severity: "high", confidence: .8, evidence: [], status: "new", createdAt: new Date().toISOString() };
  const graph = buildEvidenceGraph(analysis, fn, finding);
  assert.ok(graph.nodes.some(n => n.kind === "input"));
  assert.ok(graph.nodes.some(n => n.kind === "asset"));
  assert.ok(graph.nodes.some(n => n.kind === "state"));
  assert.ok(graph.attackPath.some(x => x.includes("recipient")));
  assert.ok(graph.reviewQuestions.length >= 4);
});
