import type { Opportunity, Severity } from "./types.js";

type Candidate = {
  id: string; title: string; category: string; severity: Severity; confidence: number;
  line: number; text: string; rationale: string;
};

export type ContextAssessment = {
  functionName?: string;
  modifiers: string[];
  hasAccessControl: boolean;
  targetExpressions: string[];
  calldataExpressions: string[];
  nearbyStateWrites: string[];
  reachability: "unknown" | "externally-reachable" | "restricted";
  targetControl: "unknown" | "user-influenced" | "constrained";
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

function isBenignTimestampCheck(line: string, lines: string[], i: number): boolean {
  const window = lines.slice(Math.max(0, i - 3), Math.min(lines.length, i + 4)).join("\n");
  const deadlineGuard = /\b(require|revert|assert)\s*\(/.test(window)
    && /\b(validTo|validUntil|deadline|expiry|expiresAt|expiration)\b/i.test(window)
    && /[<>]=?/.test(window);
  const bookkeeping = /\b(?:lastAddedAt|lastRemovedAt|lastUpdatedAt|lastCreatedAt|lastTimestamp|fundingTime|blockTimestampLast|(?:observation|observationsById)\b[^\n;]*)\s*=\s*[^;]*\bblock\.timestamp\b/i.test(window)
    || /\bblock\.timestamp\b[^;\n]*\.(?:initialize|update)\s*\(/i.test(window);
  const elapsedTime = /\b(?:cooldown|delay|duration|interval|maxTimeDelay|minTimeDelay|expiration|expiry|deadline|fundingInterval)\b/i.test(window)
    && /\bblock\.timestamp\b/.test(window)
    && /(?:[+\-]|>=|<=|>|<)/.test(window);
  return deadlineGuard || bookkeeping || elapsedTime;
}

function isBenignSelfCall(line: string, lines: string[], i: number): boolean {
  const window = lines.slice(Math.max(0, i - 2), Math.min(lines.length, i + 3)).join("\n");
  return /address\s*\(\s*this\s*\)\.call\s*\(/.test(line)
    && /\b(response|innerCall|calldata|success|ok)\b/.test(window);
}

function assessContext(lines: string[], i: number, ruleId: string): ContextAssessment {
  const start = Math.max(0, i - 18);
  const end = Math.min(lines.length, i + 18);
  const windowLines = lines.slice(start, end);
  const window = windowLines.join("\n");
  const functionMatch = window.match(/function\s+([A-Za-z_][A-Za-z0-9_]*)\s*\([^)]*\)[^{]*(?:\{|$)/);
  const modifiers = [...window.matchAll(/\b(only[A-Z][A-Za-z0-9_]*|onlyOwner|onlyAdmin|whenNotPaused|nonReentrant)\b/g)].map(m => m[1]);
  const accessTerms = /\b(require|revert|assert)\s*\(|\b(only[A-Z][A-Za-z0-9_]*|onlyOwner|onlyAdmin)\b|\b(msg\.sender|hasRole|authorized|owner|admin)\b/.test(window);
  const targetExpressions = [...new Set([...window.matchAll(/\b(?:targetContract|target|implementation|module|plugin)\b\s*(?:=|,|\))/g)].map(m => m[0].trim()))];
  const calldataExpressions = [...new Set([...window.matchAll(/\b(?:calldataPayload|calldata|data|innerCall)\b/g)].map(m => m[0]))];
  const nearbyStateWrites = windowLines.filter(line => /\b\w+\s*(?:\[[^\]]+\])?\s*=/.test(line) && !/\b(?:return|let|const|function)\b/.test(line)).map(line => line.trim()).slice(0, 8);
  const externallyReachable = /\b(?:external|public)\b/.test(window);
  return {
    functionName: functionMatch?.[1],
    modifiers: [...new Set(modifiers)],
    hasAccessControl: accessTerms,
    targetExpressions,
    calldataExpressions,
    nearbyStateWrites,
    reachability: externallyReachable ? (modifiers.length || accessTerms ? "restricted" : "externally-reachable") : "unknown",
    targetControl: /\b(?:msg\.sender|user|caller|targetContract)\b/.test(window) ? "user-influenced" : "unknown"
  };
}

function isRevertingSimulationWrapper(lines: string[], i: number, ruleId: string): boolean {
  if (ruleId !== "delegatecall") return false;
  const start = Math.max(0, i - 20);
  const end = Math.min(lines.length, i + 20);
  const window = lines.slice(start, end).join("\n");
  return /function\s+simulate[A-Za-z0-9_]*\s*\([^)]*\)[^{]*\{/.test(window)
    && /\.delegatecall\s*\(/.test(window)
    && /\brevertWith\s*\(/.test(window)
    && /function\s+revertWith\s*\([^)]*\)[^{]*\{/.test(lines.join("\n"));
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
      if (rule.id === "timestamp" && isBenignTimestampCheck(line, lines, i)) continue;
      if (rule.id === "low-level-call" && isBenignSelfCall(line, lines, i)) continue;
      if (isRevertingSimulationWrapper(lines, i, rule.id)) continue;
      const confidence = Math.max(0.05, Math.min(0.99, rule.base + contextScore(rule.id, lines, i)));
      const candidate: Candidate = { id: rule.id, title: rule.title, category: rule.category, severity: rule.severity, confidence, line: i + 1, text: line.trim(), rationale: "Static candidate requiring contextual review; confidence is heuristic." };
      const assessment = assessContext(lines, i, rule.id);
      findings.push({
        id: `static:${candidate.id}:${file}:${candidate.line}`,
        programId: "unknown", title: candidate.title, category: candidate.category,
        severity: candidate.severity, confidence: candidate.confidence,
        evidence: [
          `${file}:${candidate.line}: ${candidate.text}`,
          candidate.rationale,
          `context.function=${assessment.functionName ?? "unknown"}`,
          `context.reachability=${assessment.reachability}`,
          `context.accessControl=${assessment.hasAccessControl}`,
          `context.targetControl=${assessment.targetControl}`,
          ...(assessment.modifiers.length ? [`context.modifiers=${assessment.modifiers.join(",")}`] : []),
          ...(assessment.nearbyStateWrites.length ? [`context.stateWrites=${assessment.nearbyStateWrites.join(" | ")}`] : [])
        ],
        status: "new", createdAt: new Date().toISOString()
      });
    }
  }
  return findings.sort((a,b) => b.confidence - a.confidence);
}
