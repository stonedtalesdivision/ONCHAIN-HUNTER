import type { Opportunity, Severity } from "./types.js";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface GeminiFinding {
  title: string;
  category: string;
  severity: string;
  confidence: number;
  evidence: string[];
  line?: number;
}

interface GeminiResponse {
  candidates?: Array<{
    content?: {
      parts?: Array<{ text?: string }>;
    };
    finishReason?: string;
  }>;
  error?: { message: string; code: number };
}

interface TokenBucket {
  tokens: number;
  lastRefill: number;
}

interface AnalysisStats {
  requestsThisMinute: number;
  totalAnalyzed: number;
  totalFindings: number;
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const GEMINI_MODEL = process.env.GEMINI_MODEL ?? "gemini-1.5-flash";
const GEMINI_ENDPOINT =
  `https://generativelanguage.googleapis.com/v1beta/models/${GEMINI_MODEL}:generateContent`;
const MAX_REQUESTS_PER_MINUTE = 15;
const REQUEST_TIMEOUT_MS = 30_000;

// ---------------------------------------------------------------------------
// Module state
// ---------------------------------------------------------------------------

const bucket: TokenBucket = {
  tokens: MAX_REQUESTS_PER_MINUTE,
  lastRefill: Date.now(),
};

const stats: AnalysisStats = {
  requestsThisMinute: 0,
  totalAnalyzed: 0,
  totalFindings: 0,
};

// ---------------------------------------------------------------------------
// Rate limiter (simple token-bucket, 15 req / 60 s)
// ---------------------------------------------------------------------------

function refillBucket(): void {
  const now = Date.now();
  const elapsed = now - bucket.lastRefill;
  if (elapsed >= 60_000) {
    bucket.tokens = MAX_REQUESTS_PER_MINUTE;
    bucket.lastRefill = now;
    stats.requestsThisMinute = 0;
  }
}

function tryConsume(): boolean {
  refillBucket();
  if (bucket.tokens > 0) {
    bucket.tokens -= 1;
    stats.requestsThisMinute += 1;
    return true;
  }
  return false;
}

// ---------------------------------------------------------------------------
// Prompt construction
// ---------------------------------------------------------------------------

function buildPrompt(source: string, file: string, structuralContext?: string): string {
  const contextBlock = structuralContext
    ? `\n\nAdditional structural context about the codebase:\n${structuralContext}`
    : "";

  return `You are a smart contract security auditor. Analyze this Solidity code for exploitable vulnerabilities.

Focus on bugs that would qualify for bug bounties — real exploitable issues, not gas optimizations or style.

Vulnerability classes to check:
- Reentrancy vulnerabilities (cross-function, read-only, cross-contract)
- Access control flaws (missing modifiers, privilege escalation)
- Logic errors (incorrect state transitions, wrong math, off-by-one)
- Flash loan attack vectors
- Price oracle manipulation opportunities
- MEV/frontrunning exposure
- Token integration bugs (fee-on-transfer, rebasing, ERC777 hooks)
- Storage layout issues in upgradeable contracts
- Signature replay / malleability
- Griefing / DOS vectors

For each finding, provide:
- title: a concise descriptive title
- category: one of reentrancy, access-control, logic-error, oracle-manipulation, flash-loan, dos, token-integration, signature, storage-layout, mev
- severity: one of critical, high, medium, low (only real exploitable issues)
- confidence: a float between 0.0 and 1.0 indicating how confident you are
- evidence: an array of strings explaining the vulnerability and how it could be exploited
- line: the approximate line number in the source if identifiable

Respond with ONLY a JSON array of finding objects. No markdown, no explanation outside the JSON. If there are no findings, respond with an empty array [].${contextBlock}

File: ${file}

\`\`\`solidity
${source}
\`\`\``;
}

// ---------------------------------------------------------------------------
// Severity mapping
// ---------------------------------------------------------------------------

const SEVERITY_MAP: Record<string, Severity> = {
  critical: "critical",
  high: "high",
  medium: "medium",
  low: "low",
  informational: "informational",
};

function normalizeSeverity(raw: string): Severity {
  const lower = raw.toLowerCase().trim();
  return SEVERITY_MAP[lower] ?? "medium";
}

// ---------------------------------------------------------------------------
// Response parsing
// ---------------------------------------------------------------------------

function extractJsonArray(text: string): GeminiFinding[] {
  // Try direct parse first
  try {
    const parsed = JSON.parse(text);
    if (Array.isArray(parsed)) return parsed;
  } catch {
    // Fall through to extraction attempts
  }

  // Try to extract a JSON array from markdown fences or surrounding text
  const arrayMatch = text.match(/\[[\s\S]*\]/);
  if (arrayMatch) {
    try {
      const parsed = JSON.parse(arrayMatch[0]);
      if (Array.isArray(parsed)) return parsed;
    } catch {
      // Could not parse extracted block
    }
  }

  return [];
}

function findingToOpportunity(finding: GeminiFinding, file: string): Opportunity {
  const lineRef = finding.line ? ` (line ${finding.line})` : "";
  const evidence = Array.isArray(finding.evidence)
    ? finding.evidence.map(String)
    : [String(finding.evidence ?? "No evidence provided")];

  return {
    id: `ai-${Date.now()}-${Math.random().toString(36).slice(2, 10)}`,
    programId: "onchain-hunter",
    title: `[${file}${lineRef}] ${finding.title ?? "Unnamed finding"}`,
    category: finding.category ?? "unknown",
    severity: normalizeSeverity(finding.severity ?? "medium"),
    confidence: typeof finding.confidence === "number"
      ? Math.max(0, Math.min(1, finding.confidence))
      : 0.5,
    evidence,
    status: "new" as const,
    createdAt: new Date().toISOString(),
  };
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Returns true when the GEMINI_API_KEY environment variable is set and
 * non-empty, meaning AI-powered analysis can be performed.
 */
export function isAIAnalysisAvailable(): boolean {
  return typeof process.env.GEMINI_API_KEY === "string" && process.env.GEMINI_API_KEY.length > 0;
}

/**
 * Returns live statistics about AI analysis usage.
 */
export function getAIAnalysisStats(): {
  requestsThisMinute: number;
  totalAnalyzed: number;
  totalFindings: number;
} {
  refillBucket();
  return { ...stats };
}

/**
 * Sends a Solidity source file to Gemini for deep security analysis and
 * returns any findings as `Opportunity[]`.
 *
 * Gracefully degrades: returns an empty array when the API key is missing,
 * the rate limit is exhausted, the request times out, or the response cannot
 * be parsed.
 */
export async function analyzeContractWithAI(
  source: string,
  file: string,
  structuralContext?: string,
): Promise<Opportunity[]> {
  // Guard: no API key
  if (!isAIAnalysisAvailable()) {
    console.warn("[ai-analyzer] GEMINI_API_KEY is not set — skipping AI analysis");
    return [];
  }

  // Guard: rate limit
  if (!tryConsume()) {
    console.warn("[ai-analyzer] Rate limit reached (15 req/min) — skipping AI analysis");
    return [];
  }

  const apiKey = process.env.GEMINI_API_KEY!;
  const url = `${GEMINI_ENDPOINT}?key=${apiKey}`;
  const prompt = buildPrompt(source, file, structuralContext);

  const body = JSON.stringify({
    contents: [
      {
        parts: [{ text: prompt }],
      },
    ],
    generationConfig: {
      temperature: 0.2,
      maxOutputTokens: 8192,
    },
  });

  let response: Response;
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

    response = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body,
      signal: controller.signal,
    });

    clearTimeout(timeout);
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    console.warn(`[ai-analyzer] Request failed for ${file}: ${message}`);
    return [];
  }

  // Handle non-OK HTTP statuses
  if (!response.ok) {
    const statusText = response.statusText ?? "unknown";
    console.warn(
      `[ai-analyzer] Gemini API returned ${response.status} (${statusText}) for ${file}`,
    );
    return [];
  }

  let json: GeminiResponse;
  try {
    json = (await response.json()) as GeminiResponse;
  } catch {
    console.warn(`[ai-analyzer] Failed to parse Gemini response JSON for ${file}`);
    return [];
  }

  // Handle API-level errors
  if (json.error) {
    console.warn(`[ai-analyzer] Gemini error ${json.error.code}: ${json.error.message}`);
    return [];
  }

  // Extract text from the response
  const text = json.candidates?.[0]?.content?.parts?.[0]?.text;
  if (!text) {
    console.warn(`[ai-analyzer] Empty response from Gemini for ${file}`);
    return [];
  }

  // Parse findings
  const rawFindings = extractJsonArray(text);
  const opportunities = rawFindings.map((f) => findingToOpportunity(f, file));

  // Update stats
  stats.totalAnalyzed += 1;
  stats.totalFindings += opportunities.length;

  return opportunities;
}
