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
  categories: string[];
  nodes: EvidenceNode[];
  edges: EvidenceEdge[];
  attackPath: string[];
  reviewQuestions: string[];
  correlationKey: string;
  corroborationCount: number;
  impact: "asset-loss" | "privilege-escalation" | "state-corruption" | "oracle-manipulation" | "external-execution" | "unknown";
  exploitability: "direct" | "conditional" | "uncertain";
  scopeConfidence: "exact-revision" | "repository" | "unknown";
  deduplicationKey: string;
};

function node(id: string, kind: EvidenceNode["kind"], label: string, evidence: string[] = []): EvidenceNode {
  return { id, kind, label, evidence };
}

function graphForFunction(analysis: StructuralFileAnalysis, fn: StructuralFunction, findings: Opportunity[]): EvidenceGraph {
  const primary = findings[0];
  const categories = [...new Set(findings.map(f => f.category))];
  const nodes: EvidenceNode[] = [];
  const edges: EvidenceEdge[] = [];
  const add = (n: EvidenceNode) => { if (!nodes.some(x => x.id === n.id)) nodes.push(n); };
  const edge = (from: string, to: string, relation: string, evidence: string[] = []) => {
    if (!edges.some(e => e.from === from && e.to === to && e.relation === relation)) edges.push({ from, to, relation, evidence });
  };

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
  for (const id of operationIds) edge(auth, id, "authorization-gates", [fn.accessControlled ? "authorization detected" : "authorization not detected"]);

  const impact = fn.valueTransfers.length || fn.tokenTransfers.length ? "asset-loss" : fn.delegateCalls.length || fn.upgradeOperations.length ? "privilege-escalation" : fn.oracleReads.length ? "oracle-manipulation" : fn.stateWrites.length ? "state-corruption" : fn.externalCalls.length ? "external-execution" : "unknown";
  const exploitability = fn.userControlledInputs.length && !fn.accessControlled ? "direct" : fn.userControlledInputs.length ? "conditional" : "uncertain";
  const scopeConfidence = primary.sourceRevision ? "exact-revision" : primary.repository ? "repository" : "unknown";
  const attackPath = [
    ...fn.userControlledInputs.map(x => `attacker-controlled input: ${x}`),
    `reachable function: ${fn.name}`,
    fn.accessControlled ? "authorization guard detected" : "authorization guard not detected",
    ...fn.oracleReads.map(x => `oracle influence: ${x}`),
    ...fn.externalCalls.map(x => `external call: ${x}`),
    ...fn.delegateCalls.map(x => `delegatecall: ${x}`),
    ...fn.stateWrites.map(x => `state impact: ${x}`),
    ...fn.valueTransfers.map(x => `native value movement: ${x}`),
    ...fn.tokenTransfers.map(x => `token operation: ${x}`)
  ];

  return {
    findingId: primary.id,
    file: analysis.file,
    severity: findings.some(f => f.severity === "critical") ? "critical" : findings.some(f => f.severity === "high") ? "high" : primary.severity,
    confidence: Math.min(0.99, Math.max(...findings.map(f => f.confidence)) + (findings.length > 1 ? 0.04 : 0)),
    categories,
    nodes, edges, attackPath,
    reviewQuestions: [
      "Can the attacker control the identified input or target?",
      "Is authorization inherited, indirect, or enforced outside this function?",
      "Do multiple detector signals describe the same underlying execution path?",
      "Can the operation change privileged state or move assets?",
      "Is the affected code in the exact bounty scope and revision?",
      "Can the suspected impact be reproduced in an isolated local test?"
    ],
    correlationKey: `${analysis.file}:${fn.name}:${fn.startLine}`,
    corroborationCount: findings.length,
    impact,
    exploitability,
    scopeConfidence,
    deduplicationKey: `${primary.repository ?? ""}:${primary.sourceRevision ?? ""}:${analysis.file}:${fn.name}:${fn.startLine}`
  };
}

export function buildEvidenceGraph(analysis: StructuralFileAnalysis, fn: StructuralFunction, finding: Opportunity): EvidenceGraph {
  return graphForFunction(analysis, fn, [finding]);
}

export function buildCorrelatedEvidenceGraphs(analysis: StructuralFileAnalysis, findings: Opportunity[]): EvidenceGraph[] {
  const groups = new Map<string, Opportunity[]>();
  for (const finding of findings) {
    const fn = analysis.functions.find(x => finding.evidence.some(e => e.includes(`function ${x.name} `)) || finding.title.includes(x.name));
    if (!fn) continue;
    const key = `${analysis.file}:${fn.name}:${fn.startLine}`;
    const list = groups.get(key) ?? [];
    list.push(finding);
    groups.set(key, list);
  }
  return [...groups.values()].map(group => {
    const fn = analysis.functions.find(x => group.some(f => f.evidence.some(e => e.includes(`function ${x.name} `)) || f.title.includes(x.name)))!;
    return graphForFunction(analysis, fn, group);
  });
}

export function deduplicateFindings(findings: Opportunity[]): Opportunity[] {
  const groups = new Map<string, Opportunity[]>();
  for (const finding of findings) {
    const key = [
      finding.repository ?? "",
      finding.sourceRevision ?? "",
      finding.category,
      finding.title.replace(/^Potential |^Critical /, "").toLowerCase().replace(/[^a-z0-9]+/g, " ").trim()
    ].join("|");
    const list = groups.get(key) ?? [];
    list.push(finding);
    groups.set(key, list);
  }
  return [...groups.values()].map(group => {
    const primary = group.reduce((best, x) => x.confidence > best.confidence ? x : best);
    const corroborated = [...new Set(group.flatMap(x => x.evidence))];
    return {
      ...primary,
      id: primary.id,
      confidence: Math.min(0.99, Math.max(...group.map(x => x.confidence)) + Math.min(0.08, (group.length - 1) * 0.02)),
      evidence: [...corroborated, `corroborated detector signals: ${group.length}`]
    };
  });
}

export function buildAttackChains(analysis: StructuralFileAnalysis, findings: Opportunity[]): EvidenceGraph[] {
  const relevant = findings.filter(f => f.repository || f.sourceRevision);
  return buildCorrelatedEvidenceGraphs(analysis, relevant);
}

export function rankEvidenceGraphs(graphs: EvidenceGraph[]): EvidenceGraph[] {
  return [...graphs].sort((a, b) => {
    const severity = (x: Severity) => ({ critical: 5, high: 4, medium: 3, low: 2, informational: 1 }[x]);
    const impact = (x: EvidenceGraph["impact"]) => x === "asset-loss" || x === "privilege-escalation" ? 3 : x === "state-corruption" || x === "oracle-manipulation" ? 2 : 1;
    return (severity(b.severity) * 10 + impact(b.impact) + b.corroborationCount) - (severity(a.severity) * 10 + impact(a.impact) + a.corroborationCount);
  });
}

export function mergeEvidenceGraphs(graphs: EvidenceGraph[]): EvidenceGraph[] {
  const merged = new Map<string, EvidenceGraph>();
  for (const graph of graphs) {
    const existing = merged.get(graph.deduplicationKey);
    if (!existing) { merged.set(graph.deduplicationKey, graph); continue; }
    existing.nodes = [...existing.nodes, ...graph.nodes].filter((n, i, a) => a.findIndex(x => x.id === n.id) === i);
    existing.edges = [...existing.edges, ...graph.edges].filter((e, i, a) => a.findIndex(x => x.from === e.from && x.to === e.to && x.relation === e.relation) === i);
    existing.attackPath = [...new Set([...existing.attackPath, ...graph.attackPath])];
    existing.reviewQuestions = [...new Set([...existing.reviewQuestions, ...graph.reviewQuestions])];
    existing.categories = [...new Set([...existing.categories, ...graph.categories])];
    existing.corroborationCount += graph.corroborationCount;
    existing.confidence = Math.min(0.99, Math.max(existing.confidence, graph.confidence) + 0.02);
  }
  return [...merged.values()];
}
