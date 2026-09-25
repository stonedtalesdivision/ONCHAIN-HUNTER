import test from "node:test";
import assert from "node:assert/strict";
import { analyzeSolidityStructure } from "../dist/structural-analysis.js";
import { buildCorrelatedEvidenceGraphs, deduplicateFindings } from "../dist/evidence-graph.js";

function finding(category, title, confidence=.7) {
  return { id: category+"-1", programId:"p", title, category, severity:"high", confidence, evidence:["function withdraw (external, nonpayable) lines 1-1"], status:"new", createdAt:new Date().toISOString(), repository:"r", sourceRevision:"sha" };
}

test("correlates multiple detector signals into one graph", () => {
  const analysis = analyzeSolidityStructure(`contract Vault { uint balance; function withdraw(address recipient, uint amount) external { recipient.call{value: amount}(""); balance -= amount; } }`, "Vault.sol");
  const graphs = buildCorrelatedEvidenceGraphs(analysis, [finding("external-call","Potential arbitrary external call path: withdraw"), finding("reentrancy","Potential reentrancy with state impact: withdraw")]);
  assert.equal(graphs.length, 1);
  assert.equal(graphs[0].corroborationCount, 2);
  assert.ok(graphs[0].categories.includes("external-call"));
  assert.ok(graphs[0].categories.includes("reentrancy"));
});

test("deduplicates repeated detector findings", () => {
  const a=finding("access-control","Potential broken access control on privileged operation: withdraw",.7);
  const b={...a,id:"duplicate",confidence:.8,evidence:["second detector signal"]};
  const result=deduplicateFindings([a,b]);
  assert.equal(result.length,1);
  assert.ok(result[0].confidence > .8);
  assert.match(result[0].evidence.join(" "),/corroborated/);
});
