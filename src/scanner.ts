import type { Opportunity, Severity } from "./types.js";

type Candidate = {
  id: string; title: string; category: string; severity: Severity; confidence: number;
  line: number; text: string; rationale: string;
};

const PATTERNS = [
  { id: "tx-origin", title: "tx.origin used in authorization-sensitive code", category: "access-control", severity: "high" as Severity, base: 0.82, re: /\btx\.origin\b/ },
  { id: "selfdestruct", title: "selfdestruct usage", category: "destructive-operation", severity: "high" as Severity, base: 0.72, re: /\bselfdestruct\s*\(/ },
  { id: "delegatecall", title: "delegatecall usage", category: "external-call", severity: "medium" as Severity, base: 0.62, re: /\.delegatecall\s*\(/ },
  { id: "low-level-call", title: "Low-level external call", category: "external-call", severity: "medium" as Severity, base: 0.55, re: /\.(call|callcode|staticcall)\s*\(/ },
  { id: "timestamp", title: "block.timestamp used", category: "time-dependence", severity: "low" as Severity, base: 0.42, re: /\bblock\.timestamp\b/ }
];

function isComment(line: string): boolean {
  const t = line.trim();
  return t.startsWith("//") || t.startsWith("*") || t.startsWith("/*") || t.endsWith("*/");
}

function isLikelyNonProductionFile(file: string): boolean {
  const normalized = file.replace(/\\/g, "/").toLowerCase();
  const parts = normalized.split("/");
  const base = parts.at(-1) ?? normalized;
  return parts.some(p => ["test", "tests", "mock", "mocks", "fixture", "fixtures"].includes(p))
    || /(?:test|tests|mock|fixture)(?:interface)?\.sol$/.test(base)
    || /testinterface\.sol$/.test(base);
}

function contextScore(ruleId: string, lines: string[], i: number): number {
  const window = lines.slice(Math.max(0, i - 4), Math.min(lines.length, i + 5)).join("\n");
  let score = 0;
  if (/\b(require|revert|assert)\s*\(/.test(window)) score += 0.06;
  if (/\b(owner|admin|role|authorized|only[A-Z]\w*)\b/.test(window)) score += 0.08;
  if (ruleId === "tx-origin" && /\b(owner|admin|authorized|only[A-Z])/.test(window)) score += 0.08;
  if (ruleId === "delegatecall" && /\b(address\s+)?(target|implementation|module|plugin)\b/.test(window)) score += 0.06;
  if (ruleId === "low-level-call" && /\b(bool|success|ok)\b/.test(window)) score -= 0.12;
  if (ruleId === "timestamp" && /\b(random|lottery|raffle|seed|secret|nonce)\b/i.test(window)) score += 0.12;
  return score;
}

export function scanSoliditySource(source: string, file = "unknown.sol"): Opportunity[] {
  if (isLikelyNonProductionFile(file)) return [];
  const lines = source.split(/\r?\n/);
  const findings: Opportunity[] = [];
  for (const rule of PATTERNS) {
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (isComment(line) || !rule.re.test(line)) continue;
      const confidence = Math.max(0.05, Math.min(0.99, rule.base + contextScore(rule.id, lines, i)));
      const candidate: Candidate = { id: rule.id, title: rule.title, category: rule.category, severity: rule.severity, confidence, line: i + 1, text: line.trim(), rationale: "Static candidate requiring contextual review; confidence is heuristic." };
      findings.push({
        id: `static:${candidate.id}:${file}:${candidate.line}`,
        programId: "unknown", title: candidate.title, category: candidate.category,
        severity: candidate.severity, confidence: candidate.confidence,
        evidence: [`${file}:${candidate.line}: ${candidate.text}`, candidate.rationale],
        status: "new", createdAt: new Date().toISOString()
      });
    }
  }
  return findings.sort((a,b) => b.confidence - a.confidence);
}
