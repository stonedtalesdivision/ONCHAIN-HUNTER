import type { Opportunity, Severity } from "./types.js";

export type StructuralFunction = {
  name: string;
  visibility: "external" | "public" | "internal" | "private" | "unknown";
  mutability: "view" | "pure" | "payable" | "nonpayable" | "unknown";
  modifiers: string[];
  parameters: string[];
  accessControlled: boolean;
  stateWrites: string[];
  externalCalls: string[];
  delegateCalls: string[];
  valueTransfers: string[];
  userControlledInputs: string[];
  sensitive: boolean;
  startLine: number;
  endLine: number;
};

export type StructuralFileAnalysis = {
  file: string;
  contracts: string[];
  stateVariables: string[];
  functions: StructuralFunction[];
};

const SENSITIVE_NAMES = /^(?:withdraw|withdrawAll|sweep|rescue|claim|mint|burn|upgradeTo|upgradeToAndCall|setImplementation|changeAdmin|transferOwnership|renounceOwnership|setOwner|setAdmin|pause|unpause|execute|executeBatch|multicall|delegate|initialize|init|setOracle|setPrice|settle|liquidate|borrow|repay|deposit|redeem)$/i;
const TARGET_NAMES = /\b(?:target|targetContract|recipient|to|destination|implementation|newImplementation|admin|owner|oracle|router|caller|account|user|receiver)\b/i;
const VALUE_NAMES = /\b(?:amount|value|shares|assets|tokenAmount|msg\.value)\b/i;

function stripCommentsAndStrings(source: string): string {
  return source
    .replace(/\/\*[\s\S]*?\*\//g, m => m.replace(/[^\n]/g, " "))
    .replace(/\/\/.*$/gm, "")
    .replace(/"(?:\\.|[^"\\])*"/g, '""')
    .replace(/'(?:\\.|[^'\\])*'/g, "''");
}

function lineAt(source: string, offset: number): number {
  return source.slice(0, offset).split(/\r?\n/).length;
}

function matchingBrace(source: string, open: number): number {
  let depth = 0;
  for (let i = open; i < source.length; i++) {
    if (source[i] === "{") depth++;
    else if (source[i] === "}" && --depth === 0) return i;
  }
  return -1;
}

function visibilityOf(signature: string): StructuralFunction["visibility"] {
  const m = signature.match(/\b(external|public|internal|private)\b/);
  return (m?.[1] as StructuralFunction["visibility"]) ?? "unknown";
}

function mutabilityOf(signature: string): StructuralFunction["mutability"] {
  const m = signature.match(/\b(view|pure|payable)\b/);
  return (m?.[1] as StructuralFunction["mutability"]) ?? "nonpayable";
}

function modifiersOf(signature: string, parameterText: string): string[] {
  const tail = signature.slice(signature.indexOf(")") + 1);
  const reserved = new Set(["external", "public", "internal", "private", "view", "pure", "payable", "returns", "virtual", "override"]);
  return [...new Set((tail.match(/\b[A-Za-z_][A-Za-z0-9_]*(?:\([^)]*\))?/g) ?? [])
    .map(x => x.replace(/\(.*$/, ""))
    .filter(x => !reserved.has(x) && x !== parameterText))];
}

function parameterNames(parameterText: string): string[] {
  return parameterText
    .split(",")
    .map(part => part.trim().match(/(?:^|\s)([A-Za-z_][A-Za-z0-9_]*)\s*$/)?.[1])
    .filter((x): x is string => Boolean(x));
}

function hasAccessControl(signature: string, body: string): boolean {
  return /\b(?:only[A-Z][A-Za-z0-9_]*|onlyOwner|onlyAdmin|nonReentrant|whenNotPaused)\b/.test(signature)
    || /\b(?:require|revert|assert)\s*\([^;\n]*(?:msg\.sender|hasRole|owner|admin|authorized)\b/.test(body)
    || /\b(?:hasRole|_checkRole|_authorizeUpgrade)\s*\(/.test(body);
}

function findStateVariables(clean: string): string[] {
  const variables: string[] = [];
  for (const m of clean.matchAll(/\b(?:uint(?:8|16|32|64|128|256)?|int(?:8|16|32|64|128|256)?|address|bool|bytes(?:32)?|mapping\s*\([^;]+\)|string)\s+(?:public|private|internal)?\s*(?:immutable|constant)?\s*([A-Za-z_][A-Za-z0-9_]*)\s*(?:=[^;]*)?;/g)) {
    variables.push(m[1]);
  }
  return [...new Set(variables)];
}

export function analyzeSolidityStructure(source: string, file = "unknown.sol"): StructuralFileAnalysis {
  const clean = stripCommentsAndStrings(source);
  const contracts = [...clean.matchAll(/\b(?:contract|library|interface)\s+([A-Za-z_][A-Za-z0-9_]*)/g)].map(m => m[1]);
  const stateVariables = findStateVariables(clean);
  const functions: StructuralFunction[] = [];

  const functionRe = /\bfunction\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)([^\{;]*?)\{/g;
  for (const match of clean.matchAll(functionRe)) {
    const open = match.index! + match[0].lastIndexOf("{");
    const close = matchingBrace(clean, open);
    if (close < 0) continue;
    const signature = match[0];
    const body = clean.slice(open + 1, close);
    const params = parameterNames(match[2]);
    const modifiers = modifiersOf(signature, match[2]);
    const stateWrites = [...new Set(
      [...body.matchAll(/\b([A-Za-z_][A-Za-z0-9_]*)(?:\s*\[[^\]]+\])?\s*(?:\+=|-=|\*=|\/=|%=|=)/g)]
        .map(m => m[1])
        .filter(name => stateVariables.includes(name))
    )];
    const externalCalls = [...new Set([...body.matchAll(/\b([A-Za-z_][A-Za-z0-9_]*)\.(?:call|callcode|staticcall)\s*(?:\{|\()/g)].map(m => m[1]))];
    const delegateCalls = [...new Set([...body.matchAll(/\b([A-Za-z_][A-Za-z0-9_]*)\.delegatecall\s*\(/g)].map(m => m[1]))];
    const valueTransfers = [...new Set([
      ...[...body.matchAll(/\b([A-Za-z_][A-Za-z0-9_]*)\.call\s*\{\s*value\s*:/g)].map(m => m[1]),
      ...[...body.matchAll(/\b(?:transfer|send)\s*\(/g)].map(() => "native-transfer")
    ])];
    const userControlledInputs = params.filter(p => TARGET_NAMES.test(p) || VALUE_NAMES.test(p));
    functions.push({
      name: match[1],
      visibility: visibilityOf(signature),
      mutability: mutabilityOf(signature),
      modifiers,
      parameters: params,
      accessControlled: hasAccessControl(signature, body),
      stateWrites,
      externalCalls,
      delegateCalls,
      valueTransfers,
      userControlledInputs,
      sensitive: SENSITIVE_NAMES.test(match[1]),
      startLine: lineAt(source, match.index!),
      endLine: lineAt(source, close)
    });
  }

  return { file, contracts: [...new Set(contracts)], stateVariables, functions };
}

export function structuralFindings(analysis: StructuralFileAnalysis): Opportunity[] {
  const findings: Opportunity[] = [];

  for (const fn of analysis.functions) {
    if (!["external", "public"].includes(fn.visibility) || fn.mutability === "view" || fn.mutability === "pure") continue;

    const evidenceBase = [
      `function ${fn.name} (${fn.visibility}, ${fn.mutability}) lines ${fn.startLine}-${fn.endLine}`,
      `parameters=${fn.parameters.join(",") || "none"}`,
      `accessControl=${fn.accessControlled}`,
      `stateWrites=${fn.stateWrites.join(",") || "none"}`,
      `externalCalls=${fn.externalCalls.join(",") || "none"}`,
      `delegateCalls=${fn.delegateCalls.join(",") || "none"}`,
      `valueTransfers=${fn.valueTransfers.join(",") || "none"}`
    ];

    if (fn.sensitive && !fn.accessControlled) {
      findings.push({
        id: `structural:unrestricted-sensitive-function:${analysis.file}:${fn.startLine}`,
        programId: "unknown",
        title: `Sensitive externally reachable function without detected access control: ${fn.name}`,
        category: "access-control",
        severity: "high" as Severity,
        confidence: fn.stateWrites.length || fn.valueTransfers.length ? 0.72 : 0.62,
        evidence: [...evidenceBase, "review candidate: sensitive function name plus no detected authorization guard."],
        status: "new",
        createdAt: new Date().toISOString()
      });
    }

    if (fn.delegateCalls.length && fn.userControlledInputs.length && !fn.accessControlled) {
      findings.push({
        id: `structural:user-controlled-delegatecall:${analysis.file}:${fn.startLine}`,
        programId: "unknown",
        title: `User-controlled delegatecall path in externally reachable function: ${fn.name}`,
        category: "external-call",
        severity: "critical" as Severity,
        confidence: 0.84,
        evidence: [...evidenceBase, "review candidate: user-influenced parameter and delegatecall occur in the same externally reachable function without detected access control."],
        status: "new",
        createdAt: new Date().toISOString()
      });
    }

    if (fn.externalCalls.length && fn.valueTransfers.length && fn.userControlledInputs.length && !fn.accessControlled) {
      findings.push({
        id: `structural:user-controlled-value-call:${analysis.file}:${fn.startLine}`,
        programId: "unknown",
        title: `User-controlled value-forwarding external call path: ${fn.name}`,
        category: "external-call",
        severity: "high" as Severity,
        confidence: 0.78,
        evidence: [...evidenceBase, "review candidate: external call forwards value and accepts target/value-like user input without detected access control."],
        status: "new",
        createdAt: new Date().toISOString()
      });
    }
  }

  return findings;
}
