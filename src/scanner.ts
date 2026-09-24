import type { Opportunity, Severity } from "./types.js";

type FindingRule = {
  id: string;
  title: string;
  category: string;
  severity: Severity;
  confidence: number;
  pattern: RegExp;
  rationale: string;
};

const RULES: FindingRule[] = [
  { id: "tx-origin", title: "tx.origin used in authorization-sensitive code", category: "access-control", severity: "high", confidence: 0.82, pattern: /\btx\.origin\b/g, rationale: "tx.origin can create phishing-style authorization hazards when used as an access-control primitive." },
  { id: "selfdestruct", title: "selfdestruct usage", category: "destructive-operation", severity: "high", confidence: 0.72, pattern: /\bselfdestruct\s*\(/g, rationale: "Destructive operations deserve review for reachability and authorization." },
  { id: "delegatecall", title: "delegatecall usage", category: "external-call", severity: "medium", confidence: 0.62, pattern: /\.delegatecall\s*\(/g, rationale: "delegatecall executes another target in the caller's storage context and requires careful target validation." },
  { id: "unchecked-call", title: "Low-level call result may be unchecked", category: "external-call", severity: "medium", confidence: 0.58, pattern: /\.(call|callcode|staticcall)\s*\(/g, rationale: "Low-level calls should be reviewed to ensure return values and failure paths are handled correctly." },
  { id: "timestamp", title: "block.timestamp used", category: "time-dependence", severity: "low", confidence: 0.42, pattern: /\bblock\.timestamp\b/g, rationale: "Timestamp-dependent security logic can be manipulable within protocol-specific bounds and needs contextual review." }
];

export function scanSoliditySource(source: string, file = "unknown.sol"): Opportunity[] {
  const lines = source.split(/\r?\n/);
  const findings: Opportunity[] = [];
  for (const rule of RULES) {
    for (let i = 0; i < lines.length; i++) {
      if (!rule.pattern.test(lines[i])) continue;
      rule.pattern.lastIndex = 0;
      findings.push({
        id: `static:${rule.id}:${file}:${i + 1}`,
        programId: "unknown",
        title: rule.title,
        category: rule.category,
        severity: rule.severity,
        confidence: rule.confidence,
        evidence: [`${file}:${i + 1}: ${lines[i].trim()}`, rule.rationale],
        status: "new",
        createdAt: new Date().toISOString()
      });
    }
    rule.pattern.lastIndex = 0;
  }
  return findings;
}
