/**
 * ONCHAIN-HUNTER — Solidity Vulnerability Scanner
 * Scans Solidity source files for common security anti-patterns and
 * produces structured Opportunity objects suitable for triage.
 */

import type { Opportunity, Severity } from "./types.js";

/* ------------------------------------------------------------------ */
/*  Types                                                              */
/* ------------------------------------------------------------------ */

export interface ContextAssessment {
  isTest: boolean;
  isComment: boolean;
  isNonProduction: boolean;
  isBenign: boolean;
  surroundingCode: string;
  score: number; // 0-1, higher = more likely real
}

interface Candidate {
  patternId: string;
  title: string;
  category: string;
  severity: Severity;
  confidence: number;
  line: number;
  matchedText: string;
  file?: string;
}

interface Pattern {
  id: string;
  title: string;
  category: string;
  severity: Severity;
  confidence: number;
  regex: RegExp;
}

/* ------------------------------------------------------------------ */
/*  Helper utilities                                                   */
/* ------------------------------------------------------------------ */

/** True when the matched line lives inside a comment block or line comment. */
function isComment(line: string, lines: string[], index: number): boolean {
  const trimmed = line.trimStart();
  if (trimmed.startsWith("//")) return true;
  if (trimmed.startsWith("*")) return true; // inside /** ... */ block
  // Walk backwards to see if we are inside a block comment
  let inBlock = false;
  for (let i = 0; i <= index; i++) {
    const l = lines[i];
    if (l.includes("/*")) inBlock = true;
    if (l.includes("*/")) inBlock = false;
  }
  return inBlock;
}

/** Heuristic: file path looks like a test, mock, or script. */
function isLikelyNonProductionFile(file?: string): boolean {
  if (!file) return false;
  const lower = file.toLowerCase();
  return (
    /(?:test|mock|fake|stub|script|migration|deploy|fixture|helper)[s]?[./\\]/i.test(lower) ||
    lower.endsWith(".t.sol") ||
    lower.endsWith(".s.sol") ||
    lower.includes("node_modules")
  );
}

/** Timestamp comparisons that are clearly benign (e.g. deadline checks). */
function isBenignTimestampCheck(line: string): boolean {
  const lower = line.toLowerCase();
  return (
    /deadline/i.test(lower) ||
    /expir/i.test(lower) ||
    /timeout/i.test(lower) ||
    /lock\s*time/i.test(lower) ||
    /block\.timestamp\s*[><=]+\s*\w*(deadline|expir|timeout|end)/i.test(lower)
  );
}

/** Self-calls (`address(this).call(...)`) are usually benign. */
function isBenignSelfCall(line: string): boolean {
  return /address\s*\(\s*this\s*\)/.test(line);
}

/** Check if Solidity pragma is >= 0.8.0 (built-in overflow checks). */
function isPragmaAbove08(source: string): boolean {
  const match = source.match(/pragma\s+solidity\s+[\^>=]*\s*(\d+)\.(\d+)/);
  if (!match) return false;
  const major = parseInt(match[1], 10);
  const minor = parseInt(match[2], 10);
  return major > 0 || minor >= 8;
}

/** Check if file uses SafeERC20. */
function hasSafeERC20(source: string): boolean {
  return (
    /using\s+SafeERC20\b/.test(source) ||
    /import\s+.*SafeERC20/.test(source) ||
    /\.safeTransfer\b/.test(source) ||
    /\.safeTransferFrom\b/.test(source) ||
    /\.safeApprove\b/.test(source)
  );
}

/** Check if the function surrounding line `i` has a nonReentrant modifier. */
function hasReentrancyGuard(lines: string[], i: number): boolean {
  // Walk backwards from the matched line to the function declaration
  for (let j = i; j >= Math.max(0, i - 30); j--) {
    const l = lines[j];
    if (/\bfunction\b/.test(l)) {
      // Check this line and the next few for `nonReentrant`
      const snippet = lines.slice(j, Math.min(lines.length, j + 5)).join(" ");
      return /\bnonReentrant\b/.test(snippet);
    }
  }
  return false;
}

/** Check if a reverting simulation wrapper surrounds the match. */
function isRevertingSimulationWrapper(lines: string[], index: number): boolean {
  // Look for patterns like try/catch around the call, or
  // staticcall-based simulation that immediately reverts on success.
  const start = Math.max(0, index - 10);
  const end = Math.min(lines.length, index + 10);
  const block = lines.slice(start, end).join("\n");
  return (
    /\btry\b/.test(block) && /\bcatch\b/.test(block) &&
    /\brevert\b/.test(block)
  );
}

/**
 * Assess the surrounding context of a match to estimate how likely
 * it is to be a genuine, exploitable finding.
 */
function assessContext(
  lines: string[],
  index: number,
  file?: string,
): ContextAssessment {
  const line = lines[index] ?? "";
  const start = Math.max(0, index - 5);
  const end = Math.min(lines.length, index + 6);
  const surroundingCode = lines.slice(start, end).join("\n");

  const assessment: ContextAssessment = {
    isTest: isLikelyNonProductionFile(file),
    isComment: isComment(line, lines, index),
    isNonProduction: isLikelyNonProductionFile(file),
    isBenign: false,
    surroundingCode,
    score: 0.5,
  };

  return assessment;
}

/**
 * Compute a contextual confidence score (0–1) for a candidate.
 * Adjusts the raw pattern confidence based on surrounding code signals.
 */
function contextScore(
  candidate: Candidate,
  ctx: ContextAssessment,
  source: string,
  lines: string[],
): number {
  let score = candidate.confidence;

  // Universal suppressors
  if (ctx.isComment) return 0;
  if (ctx.isTest) score *= 0.3;
  if (ctx.isNonProduction) score *= 0.4;

  const line = lines[candidate.line] ?? "";

  // ---- Pattern-specific adjustments ---- //

  switch (candidate.patternId) {
    case "tx-origin": {
      // Boost when used in auth, suppress when used in events/logging
      if (/require|if|assert/.test(line)) score *= 1.3;
      if (/emit\s/.test(line)) score *= 0.3;
      break;
    }

    case "selfdestruct": {
      // Suppress if behind onlyOwner or similar access control
      const fnBlock = getFunctionBlock(lines, candidate.line);
      if (/\bonlyOwner\b/.test(fnBlock)) score *= 0.5;
      break;
    }

    case "delegatecall": {
      if (isBenignSelfCall(line)) score *= 0.3;
      if (isRevertingSimulationWrapper(lines, candidate.line)) score *= 0.3;
      break;
    }

    case "low-level-call": {
      if (isBenignSelfCall(line)) score *= 0.3;
      // Check if return value is captured
      if (/\(\s*bool\s+\w+/.test(line)) score *= 0.6;
      break;
    }

    case "timestamp": {
      if (isBenignTimestampCheck(line)) score *= 0.2;
      break;
    }

    case "reentrancy-pattern": {
      if (hasReentrancyGuard(lines, candidate.line)) score *= 0.15;
      // Boost if state write found after external call
      const after = lines.slice(candidate.line + 1, candidate.line + 8).join("\n");
      if (/\b\w+\s*(?:\[[^\]]*\])?\s*=[^=]/.test(after)) score *= 1.3;
      break;
    }

    case "unchecked-return": {
      // Suppress if return value is captured on same line
      if (/\(\s*bool\b/.test(line) || /=\s*\S+\.call/.test(line)) score *= 0.2;
      break;
    }

    case "integer-overflow-pre08": {
      if (isPragmaAbove08(source)) score *= 0.05; // almost entirely suppress
      if (/SafeMath/i.test(source)) score *= 0.2;
      break;
    }

    case "unsafe-downcast": {
      if (/SafeCast/i.test(source)) score *= 0.15;
      if (isPragmaAbove08(source) && /SafeCast/.test(source)) score *= 0.1;
      break;
    }

    case "missing-zero-check": {
      // Check if there is a zero-address require nearby
      const fnBody = getFunctionBlock(lines, candidate.line);
      if (/require\s*\([^)]*!=\s*address\s*\(\s*0\s*\)/.test(fnBody)) score *= 0.15;
      if (/address\s*\(\s*0\s*\)/.test(fnBody)) score *= 0.4;
      break;
    }

    case "unprotected-initializer": {
      const fnDecl = lines
        .slice(candidate.line, Math.min(lines.length, candidate.line + 5))
        .join(" ");
      if (/\binitializer\b/.test(fnDecl)) score *= 0.1;
      if (/\bonlyOwner\b/.test(fnDecl)) score *= 0.4;
      break;
    }

    case "storage-collision": {
      // Boost if no EIP-1967 standard slot
      if (/0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc/.test(source)) {
        score *= 0.4; // Known standard slot
      }
      break;
    }

    case "oracle-manipulation": {
      // Suppress if TWAP or averaging logic is present
      if (/twap|TWAP|observe|timeWeight|cumulativePrice/i.test(source)) score *= 0.35;
      // Boost if single-block read with no averaging
      const block = lines.slice(
        Math.max(0, candidate.line - 3),
        Math.min(lines.length, candidate.line + 3),
      ).join("\n");
      if (!/require.*updatedAt|staleness|heartbeat/i.test(block)) score *= 1.2;
      break;
    }

    case "flash-loan-callback": {
      // Check for initiator/sender validation
      const fnBody = getFunctionBlock(lines, candidate.line);
      if (/require.*msg\.sender|require.*initiator|onlyPool|onlyLending/i.test(fnBody)) {
        score *= 0.3;
      }
      break;
    }

    case "unchecked-erc20": {
      if (hasSafeERC20(source)) score *= 0.1;
      // Check if return value is captured
      if (/=\s*\S+\.transfer/.test(line) || /require\s*\(\s*\S+\.transfer/.test(line)) {
        score *= 0.25;
      }
      break;
    }

    case "arbitrary-from-transferFrom": {
      // Suppress if `from` is clearly msg.sender or a verified address
      if (/\.transferFrom\s*\(\s*msg\.sender/.test(line)) score *= 0.05;
      if (hasSafeERC20(source)) score *= 0.5; // still suspicious even with SafeERC20
      break;
    }

    case "signature-replay": {
      // Suppress if nonce tracking or EIP-712 domain separator found
      if (/nonce|_nonces|DOMAIN_SEPARATOR|EIP712|_domainSeparator/i.test(source)) {
        score *= 0.25;
      }
      break;
    }

    case "weak-randomness": {
      // Suppress if VRF or Chainlink randomness is also used
      if (/VRF|chainlink|requestRandomness|fulfillRandomWords/i.test(source)) {
        score *= 0.2;
      }
      break;
    }

    case "open-redirect": {
      if (hasSafeERC20(source)) score *= 0.4;
      break;
    }

    case "denial-of-service": {
      // Boost if no gas limit or length cap found
      const fnBody = getFunctionBlock(lines, candidate.line);
      if (/\.length\s*[<>]|maxLength|batchSize|limit/i.test(fnBody)) score *= 0.4;
      break;
    }

    case "frontrunning-risk": {
      // Suppress if approve(0) is called before
      const preceding = lines
        .slice(Math.max(0, candidate.line - 5), candidate.line)
        .join("\n");
      if (/\.approve\s*\([^,]+,\s*0\s*\)/.test(preceding)) score *= 0.15;
      if (/increaseAllowance|safeIncreaseAllowance|safeApprove/.test(line)) score *= 0.1;
      break;
    }
  }

  return Math.max(0, Math.min(1, score));
}

/** Extract the function body surrounding a given line index. */
function getFunctionBlock(lines: string[], index: number): string {
  let start = index;
  for (let j = index; j >= Math.max(0, index - 50); j--) {
    if (/\bfunction\b/.test(lines[j])) {
      start = j;
      break;
    }
  }
  let depth = 0;
  let end = Math.min(lines.length, start + 100);
  for (let j = start; j < lines.length; j++) {
    for (const ch of lines[j]) {
      if (ch === "{") depth++;
      if (ch === "}") depth--;
    }
    if (depth <= 0 && j > start) {
      end = j + 1;
      break;
    }
  }
  return lines.slice(start, end).join("\n");
}

/**
 * Decide whether a scored candidate should be emitted as a finding.
 * Threshold is severity-dependent.
 */
function shouldReport(candidate: Candidate, finalScore: number): boolean {
  const thresholds: Record<Severity, number> = {
    critical: 0.25,
    high: 0.30,
    medium: 0.35,
    low: 0.40,
    informational: 0.45,
  };
  return finalScore >= (thresholds[candidate.severity] ?? 0.35);
}

/* ------------------------------------------------------------------ */
/*  Patterns                                                           */
/* ------------------------------------------------------------------ */

const PATTERNS: Pattern[] = [
  // ---- Original 5 patterns ---- //
  {
    id: "tx-origin",
    title: "Use of tx.origin for Authorization",
    category: "Access Control",
    severity: "high",
    confidence: 0.70,
    regex: /\btx\.origin\b/,
  },
  {
    id: "selfdestruct",
    title: "Use of selfdestruct / SELFDESTRUCT",
    category: "Denial of Service",
    severity: "critical",
    confidence: 0.75,
    regex: /\bselfdestruct\s*\(/,
  },
  {
    id: "delegatecall",
    title: "Use of delegatecall",
    category: "Proxy / Upgrade",
    severity: "high",
    confidence: 0.65,
    regex: /\.delegatecall\s*\(/,
  },
  {
    id: "low-level-call",
    title: "Low-level .call() Usage",
    category: "Unchecked Calls",
    severity: "medium",
    confidence: 0.55,
    regex: /\.call\s*[\({]/,
  },
  {
    id: "timestamp",
    title: "Block Timestamp Dependence",
    category: "Timestamp Manipulation",
    severity: "low",
    confidence: 0.45,
    regex: /\bblock\.timestamp\b/,
  },

  // ---- New patterns (16 additions) ---- //
  {
    id: "reentrancy-pattern",
    title: "Potential Reentrancy — State Write After External Call",
    category: "Reentrancy",
    severity: "critical",
    confidence: 0.75,
    regex: /\.call\s*[\({]/,
  },
  {
    id: "unchecked-return",
    title: "Unchecked Return Value from External Call",
    category: "Unchecked Calls",
    severity: "high",
    confidence: 0.70,
    regex: /(?:\.call|\.send)\s*[\({][^;]*;\s*$/m,
  },
  {
    id: "integer-overflow-pre08",
    title: "Potential Integer Overflow/Underflow (pre-0.8)",
    category: "Arithmetic",
    severity: "high",
    confidence: 0.68,
    regex: /[\+\-\*]\s*(?:\w+|\d+)\s*[;,)]/,
  },
  {
    id: "unsafe-downcast",
    title: "Unsafe Integer Downcast",
    category: "Arithmetic",
    severity: "medium",
    confidence: 0.55,
    regex: /uint(?:8|16|32|64|96|128)\s*\(/,
  },
  {
    id: "missing-zero-check",
    title: "Missing Zero-Address Validation",
    category: "Input Validation",
    severity: "medium",
    confidence: 0.50,
    regex: /function\s+\w+\s*\([^)]*\baddress\s+\w+/,
  },
  {
    id: "unprotected-initializer",
    title: "Unprotected Initializer Function",
    category: "Access Control",
    severity: "critical",
    confidence: 0.80,
    regex: /function\s+initialize\s*\(/,
  },
  {
    id: "storage-collision",
    title: "Potential Proxy Storage Collision",
    category: "Proxy / Upgrade",
    severity: "critical",
    confidence: 0.78,
    regex: /bytes32\s+(?:private\s+|internal\s+)?constant\s+\w+\s*=\s*(?:keccak256|bytes32)\s*\(/,
  },
  {
    id: "oracle-manipulation",
    title: "Oracle Price Manipulation Risk",
    category: "Oracle",
    severity: "high",
    confidence: 0.72,
    regex: /\.(?:latestAnswer|latestRoundData|getReserves|slot0|observe)\s*\(/,
  },
  {
    id: "flash-loan-callback",
    title: "Flash Loan Callback Without Proper Validation",
    category: "Flash Loan",
    severity: "high",
    confidence: 0.68,
    regex: /function\s+(?:onFlashLoan|executeOperation|uniswapV[23](?:Call|SwapCallback)|pancakeCall|flashCallback)\s*\(/,
  },
  {
    id: "unchecked-erc20",
    title: "Unchecked ERC-20 Transfer Return Value",
    category: "Token Safety",
    severity: "high",
    confidence: 0.70,
    regex: /\.(?:transfer|transferFrom|approve)\s*\(/,
  },
  {
    id: "arbitrary-from-transferFrom",
    title: "Arbitrary `from` in transferFrom",
    category: "Token Safety",
    severity: "critical",
    confidence: 0.82,
    regex: /\.transferFrom\s*\(\s*(?!msg\.sender)\w/,
  },
  {
    id: "signature-replay",
    title: "Signature Replay — ecrecover Without Nonce/Domain",
    category: "Cryptography",
    severity: "high",
    confidence: 0.72,
    regex: /\becrecover\s*\(/,
  },
  {
    id: "weak-randomness",
    title: "Weak On-Chain Randomness",
    category: "Randomness",
    severity: "high",
    confidence: 0.70,
    regex: /\b(?:blockhash|block\.(?:difficulty|prevrandao))\b/,
  },
  {
    id: "open-redirect",
    title: "Unvalidated Address in Token Approval",
    category: "Token Safety",
    severity: "medium",
    confidence: 0.55,
    regex: /\.approve\s*\(\s*(?!address\s*\(\s*(?:this|0))\w/,
  },
  {
    id: "denial-of-service",
    title: "Denial of Service — Unbounded Loop with External Call",
    category: "Denial of Service",
    severity: "high",
    confidence: 0.65,
    regex: /\b(?:for|while)\s*\(/,
  },
  {
    id: "frontrunning-risk",
    title: "Front-Running Risk — approve Without Reset",
    category: "Token Safety",
    severity: "medium",
    confidence: 0.55,
    regex: /\.approve\s*\(\s*[^,]+,\s*(?!0\s*[,)]))([\w.]+/,
  },
];

/* ------------------------------------------------------------------ */
/*  Multi-line / cross-line pattern helpers                            */
/* ------------------------------------------------------------------ */

/**
 * For the reentrancy pattern we need to distinguish from the plain
 * `low-level-call` pattern by checking if state writes follow
 * the external call within the same function.
 */
function hasStateWriteAfterCall(lines: string[], callIndex: number): boolean {
  const end = Math.min(lines.length, callIndex + 15);
  for (let j = callIndex + 1; j < end; j++) {
    const l = lines[j].trim();
    // Hit end of function
    if (l === "}") break;
    // State write: something = something (but not ==)
    if (/\b\w+\s*(?:\[[^\]]*\])?\s*=[^=]/.test(l) && !/\/\//.test(l.split("=")[0])) {
      return true;
    }
  }
  return false;
}

/**
 * For the denial-of-service pattern, check if the loop body contains
 * an external call (.call, .transfer, .send).
 */
function loopContainsExternalCall(lines: string[], loopIndex: number): boolean {
  let depth = 0;
  let started = false;
  for (let j = loopIndex; j < Math.min(lines.length, loopIndex + 50); j++) {
    for (const ch of lines[j]) {
      if (ch === "{") { depth++; started = true; }
      if (ch === "}") depth--;
    }
    if (started && depth <= 0) break;
    if (/\.(?:call|transfer|send)\s*[\({]/.test(lines[j]) && j > loopIndex) {
      return true;
    }
  }
  return false;
}

/* ------------------------------------------------------------------ */
/*  Main scanner                                                       */
/* ------------------------------------------------------------------ */

export function scanSoliditySource(
  source: string,
  file?: string,
): Opportunity[] {
  const lines = source.split("\n");
  const candidates: Candidate[] = [];

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    for (const pattern of PATTERNS) {
      if (!pattern.regex.test(line)) continue;

      // ---------- Pattern-specific pre-filters ---------- //

      // The reentrancy pattern reuses the `.call` regex but requires
      // a state write AFTER the call — skip if none found.
      if (pattern.id === "reentrancy-pattern") {
        if (!hasStateWriteAfterCall(lines, i)) continue;
      }

      // integer-overflow is only relevant for pre-0.8 contracts
      if (pattern.id === "integer-overflow-pre08") {
        if (isPragmaAbove08(source)) continue;
      }

      // denial-of-service requires an external call inside the loop
      if (pattern.id === "denial-of-service") {
        if (!loopContainsExternalCall(lines, i)) continue;
      }

      // unchecked-erc20: skip if SafeERC20 is in use
      if (pattern.id === "unchecked-erc20") {
        if (hasSafeERC20(source)) continue;
      }

      const matched = line.match(pattern.regex);

      candidates.push({
        patternId: pattern.id,
        title: pattern.title,
        category: pattern.category,
        severity: pattern.severity,
        confidence: pattern.confidence,
        line: i,
        matchedText: matched ? matched[0] : line.trim(),
        file,
      });
    }
  }

  // ---- Score, filter, deduplicate, and convert to Opportunity[] ---- //

  const opportunities: Opportunity[] = [];
  const seenLines = new Map<string, number>(); // "patternId:line" -> best score

  for (const candidate of candidates) {
    const ctx = assessContext(lines, candidate.line, file);
    const finalScore = contextScore(candidate, ctx, source, lines);

    if (!shouldReport(candidate, finalScore)) continue;

    const key = `${candidate.patternId}:${candidate.line}`;
    const existing = seenLines.get(key);
    if (existing !== undefined && existing >= finalScore) continue;
    seenLines.set(key, finalScore);

    const evidence: string[] = [
      `Line ${candidate.line + 1}: ${candidate.matchedText}`,
    ];
    if (ctx.surroundingCode) {
      evidence.push(`Context:\n${ctx.surroundingCode}`);
    }

    const opp: Opportunity = {
      id: `static:${candidate.patternId}:${file ?? "unknown.sol"}:${candidate.line + 1}`,
      programId: "unknown",
      title: candidate.title,
      category: candidate.category,
      severity: candidate.severity,
      confidence: Math.round(finalScore * 100) / 100,
      evidence,
      status: "new",
      createdAt: new Date().toISOString(),
    };

    if (file) {
      opp.repository = file;
    }

    opportunities.push(opp);
  }

  // Sort by severity weight then by confidence descending
  const severityWeight: Record<Severity, number> = {
    critical: 5,
    high: 4,
    medium: 3,
    low: 2,
    informational: 1,
  };

  opportunities.sort((a, b) => {
    const wA = severityWeight[a.severity] ?? 0;
    const wB = severityWeight[b.severity] ?? 0;
    if (wB !== wA) return wB - wA;
    return (b.confidence ?? 0) - (a.confidence ?? 0);
  });

  return opportunities;
}
