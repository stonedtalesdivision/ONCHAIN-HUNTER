import type { Opportunity } from "../types.js";
import type { StructuralFileAnalysis, StructuralFunction } from "../structural-analysis.js";

function base(fn: StructuralFunction, category: string, title: string, severity: Opportunity["severity"], confidence: number, extra: string): Opportunity {
  return {
    id: `phase3:${category}:${fn.name}:${fn.startLine}`,
    programId: "unknown",
    title,
    category,
    severity,
    confidence,
    evidence: [
      `function ${fn.name} (${fn.visibility}, ${fn.mutability}) lines ${fn.startLine}-${fn.endLine}`,
      `parameters=${fn.parameters.join(",") || "none"}`,
      `accessControl=${fn.accessControlled}`,
      `stateWrites=${fn.stateWrites.join(",") || "none"}`,
      `externalCalls=${fn.externalCalls.join(",") || "none"}`,
      `delegateCalls=${fn.delegateCalls.join(",") || "none"}`,
      `valueTransfers=${fn.valueTransfers.join(",") || "none"}`,
      extra
    ],
    status: "new",
    createdAt: new Date().toISOString()
  };
}

function reachable(fn: StructuralFunction): boolean {
  return ["external", "public"].includes(fn.visibility) && !["view", "pure"].includes(fn.mutability);
}

export function detectPhase3(analysis: StructuralFileAnalysis): Opportunity[] {
  const findings: Opportunity[] = [];

  for (const fn of analysis.functions) {
    if (!reachable(fn)) continue;

    const userTarget = fn.userControlledInputs.length > 0;
    const external = fn.externalCalls.length > 0;
    const value = fn.valueTransfers.length > 0;
    const privileged = fn.sensitive || fn.stateWrites.length > 0;

    // 3.2 Arbitrary external call: exclude delegatecall, which has its own detector.
    if (external && userTarget && !fn.delegateCalls.length && !fn.accessControlled) {
      findings.push(base(fn, "external-call", `Potential arbitrary external call path: ${fn.name}`, value ? "high" : "medium", value ? 0.82 : 0.72,
        "review candidate: externally reachable function combines a user-influenced target/recipient-like input with a low-level external call without a detected authorization guard."));
    }

    // 3.3 Unauthorized asset movement.
    if (fn.tokenTransfers.length > 0 && !fn.accessControlled && (userTarget || value || /withdraw|sweep|rescue|claim|transfer|redeem/i.test(fn.name))) {
      findings.push(base(fn, "asset-transfer", `Potential unauthorized asset movement: ${fn.name}`, value ? "high" : "medium", 0.78,
        `tokenOperations=${fn.tokenTransfers.join(",")}; review recipient/amount authorization and accounting before treating as a vulnerability.`));
    }

    // 3.4 Delegatecall/proxy takeover.
    if (fn.delegateCalls.length && !fn.accessControlled) {
      findings.push(base(fn, "delegatecall", `Potential delegatecall/proxy takeover path: ${fn.name}`, "critical", 0.86,
        "review candidate: delegatecall is externally reachable without a detected authorization guard; confirm whether the target is attacker-influenced and whether proxy storage can be corrupted."));
    }
    if (fn.upgradeOperations.length && !fn.accessControlled) {
      findings.push(base(fn, "upgrade-takeover", `Potential unauthorized upgrade path: ${fn.name}`, "critical", 0.84,
        `upgradeOperations=${fn.upgradeOperations.join(",")}; confirm proxy/admin authorization and initializer state.`));
    }

    // 3.5 Reentrancy with state impact.
    if (external && fn.stateWrites.length && fn.stateWriteAfterExternalCall && !fn.hasReentrancyGuard) {
      findings.push(base(fn, "reentrancy", `Potential reentrancy with state impact: ${fn.name}`, "high", 0.79,
        "review candidate: external interaction is followed by a state write without a detected reentrancy guard; verify attacker-controlled callback reachability."));
    }

    // 3.6 Oracle manipulation.
    if (fn.oracleReads.length && (userTarget || /swap|borrow|liquidate|redeem|mint|settle|price|quote/i.test(fn.name))) {
      findings.push(base(fn, "oracle-manipulation", `Potential oracle manipulation surface: ${fn.name}`, "high", 0.68,
        `oracleSignals=${fn.oracleReads.join(",")}; verify oracle source, freshness, manipulation resistance, and whether sensitive accounting relies on a manipulable spot value.`));
    }

    // 3.7 Accounting/invariant violations.
    if (fn.accountingSignals.length >= 2 && fn.stateWrites.length && /deposit|withdraw|redeem|mint|burn|borrow|repay|claim|settle/i.test(fn.name)) {
      findings.push(base(fn, "accounting", `Potential accounting/invariant risk: ${fn.name}`, "high", 0.64,
        `accountingSignals=${fn.accountingSignals.join(",")}; review conservation of assets/shares/debt and rounding/ordering invariants.`));
    }

    // 3.8 Signature/replay flaws.
    if (fn.signatureOperations.length && !fn.nonceWrites.length && !/cancel|invalidate|revoke/i.test(fn.name)) {
      findings.push(base(fn, "signature-replay", `Potential signature replay surface: ${fn.name}`, "high", 0.67,
        `signatureOperations=${fn.signatureOperations.join(",")}; no nonce write was detected in the same function. Verify nonce/domain/deadline enforcement across the complete authorization flow.`));
    }

    // 3.9 Initialization/upgrade takeover.
    if (fn.initializer && !fn.initializerGuard) {
      findings.push(base(fn, "initialization", `Potential unguarded initialization path: ${fn.name}`, "critical", 0.82,
        "review candidate: initializer-like function has no detected initializer guard; verify whether it can be called after deployment and seize privileged state."));
    }

    // 3.10 Critical business logic.
    if (fn.businessCritical && (!fn.accessControlled || fn.valueTransfers.length || fn.oracleReads.length || fn.accountingSignals.length)) {
      findings.push(base(fn, "business-logic", `Critical business-logic review candidate: ${fn.name}`, "high", 0.60,
        "review candidate: financially or governance-sensitive operation detected; validate authorization, state transitions, price inputs, and asset conservation."));
    }
  }

  return findings;
}
