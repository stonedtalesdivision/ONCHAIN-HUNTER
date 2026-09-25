import type { Opportunity, Severity } from "./types.js";
import type { StructuralFileAnalysis, StructuralFunction } from "./structural-analysis.js";

export type EvidenceNode = {
  id: string;
  kind: "input" | "function" | "authorization" | "operation" | "state" | "asset" | "oracle";
  label: string;
  evidence: string[];
};
export type EvidenceEdge = { from: string; to: string; relation: string; evidence: string[] };
export type EvidenceGraph = {
  findingId: string;
  file: string;
  severity: Severity;
  confidence: number;
  nodes: EvidenceNode[];
  edges: EvidenceEdge[];
  attackPath: string[];
  reviewQuestions: string[];
};

function node(id: string, kind: EvidenceNode["kind"], label: string, evidence: string[] = []): EvidenceNode {
  return { id, kind, label, evidence };
}

export function buildEvidenceGraph(analysis: StructuralFileAnalysis, fn: StructuralFunction, finding: Opportunity): EvidenceGraph {
  const nodes: EvidenceNode[] = [];
  const edges: EvidenceEdge[] = [];
  const add = (n: EvidenceNode) => { if (!nodes.some(x => x.id === n.id)) nodes.push(n); };
  const edge = (from: string, to: string, relation: string, evidence: string[] = []) => edges.push({ from, to, relation, evidence });

  const f = `function:${fn.name}:${fn.startLine}`;
  add(node(f, "function", fn.name, [`lines ${fn.startLine}-${fn.endLine}`, `visibility=${fn.visibility}`, `mutability=${fn.mutability}`]));

  for (const input of fn.userControlledInputs) {
    const id = `input:${input}`;
    add(node(id, "input", input, ["parameter classified as target/value/recipient-like input"]));
    edge(id, f, "controls", [`parameter ${input}`]);
  }

  const auth = `auth:${fn.name}`;
  add(node(auth, "authorization", fn.accessControlled ? "authorization detected" : "authorization not detected", []));
  edge(f, auth, fn.accessControlled ? "protected-by" : "missing-or-uncertain", []);

  for (const call of fn.externalCalls) {
    const id = `call:${call}`;
    add(node(id, "operation", `low-level call on ${call}`, []));
    edge(f, id, "reaches", []);
  }
  for (const call of fn.delegateCalls) {
    const id = `delegate:${call}`;
    add(node(id, "operation", `delegatecall on ${call}`, []));
    edge(f, id, "reaches", []);
  }
  for (const transfer of [...fn.valueTransfers, ...fn.tokenTransfers]) {
    const id = `asset:${transfer}`;
    add(node(id, "asset", transfer, ["asset/value movement signal"]));
    edge(f, id, "moves", []);
  }
  for (const state of fn.stateWrites) {
    const id = `state:${state}`;
    add(node(id, "state", state, ["detected state write"]));
    edge(f, id, "modifies", []);
  }
  for (const oracle of fn.oracleReads) {
    const id = `oracle:${oracle}`;
    add(node(id, "oracle", oracle, ["oracle/price read signal"]));
    edge(id, f, "influences", []);
  }

  const operationIds = nodes.filter(n => n.kind === "operation" || n.kind === "asset" || n.kind === "state").map(n => n.id);
  for (const id of operationIds) {
    edge(auth, id, "authorization-gates", [fn.accessControlled ? "authorization detected" : "authorization not detected"]);
  }

  const attackPath = [
    ...fn.userControlledInputs.map(x => `attacker-controlled input: ${x}`),
    `reachable function: ${fn.name}`,
    fn.accessControlled ? "authorization guard detected" : "authorization guard not detected",
    ...fn.externalCalls.map(x => `external call: ${x}`),
    ...fn.delegateCalls.map(x => `delegatecall: ${x}`),
    ...fn.stateWrites.map(x => `state impact: ${x}`),
    ...fn.valueTransfers.map(x => `native value movement: ${x}`),
    ...fn.tokenTransfers.map(x => `token operation: ${x}`)
  ];

  return {
    findingId: finding.id,
    file: analysis.file,
    severity: finding.severity,
    confidence: finding.confidence,
    nodes, edges, attackPath,
    reviewQuestions: [
      "Can the attacker control the identified input or target?",
      "Is authorization inherited, indirect, or enforced outside this function?",
      "Can the operation change privileged state or move assets?",
      "Is the affected code in the exact bounty scope and revision?",
      "Can the suspected impact be reproduced in an isolated local test?"
    ]
  };
}
