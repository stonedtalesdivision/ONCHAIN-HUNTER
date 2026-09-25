import type { Opportunity } from "../types.js";
import type { StructuralFileAnalysis, StructuralFunction } from "../structural-analysis.js";

const PRIVILEGED_STATE = /^(?:owner|admin|implementation|pendingOwner|pendingAdmin|operator|guardian|treasury|feeRecipient|protocolFee|oracle|priceOracle|router|paused|whitelist|blacklist|merkleRoot|root|roles?|admins?)$/i;
const PRIVILEGED_ACTION = /^(?:set|update|change|replace|upgrade|transfer|renounce|pause|unpause|grant|revoke|initialize|init|setOracle|setPrice|setFee|setTreasury)/i;

function evidence(fn: StructuralFunction): string[] {
  return [
    `function ${fn.name} (${fn.visibility}, ${fn.mutability}) lines ${fn.startLine}-${fn.endLine}`,
    `accessControl=${fn.accessControlled}`,
    `stateWrites=${fn.stateWrites.join(",") || "none"}`,
    `valueTransfers=${fn.valueTransfers.join(",") || "none"}`,
    `externalCalls=${fn.externalCalls.join(",") || "none"}`
  ];
}

export function detectBrokenAccessControl(analysis: StructuralFileAnalysis): Opportunity[] {
  const findings: Opportunity[] = [];

  for (const fn of analysis.functions) {
    if (!["external", "public"].includes(fn.visibility)) continue;
    if (fn.mutability === "view" || fn.mutability === "pure") continue;
    if (fn.accessControlled) continue;

    const privilegedWrites = fn.stateWrites.filter(name => PRIVILEGED_STATE.test(name));
    const privilegedAction = PRIVILEGED_ACTION.test(fn.name);

    if (!privilegedWrites.length && !privilegedAction) continue;

    findings.push({
      id: `access-control:unprotected-privileged-operation:${analysis.file}:${fn.startLine}`,
      programId: "unknown",
      title: `Potential broken access control on privileged operation: ${fn.name}`,
      category: "access-control",
      severity: privilegedWrites.some(name => /implementation|owner|admin/i.test(name)) ? "critical" : "high",
      confidence: privilegedWrites.length ? 0.86 : 0.76,
      evidence: [
        ...evidence(fn),
        privilegedWrites.length
          ? `privileged state writes without detected authorization: ${privilegedWrites.join(",")}`
          : "privileged action name without detected authorization guard",
        "review candidate: authorization may exist indirectly or through inherited/constructor context; confirm with project-specific access-control implementation."
      ],
      status: "new",
      createdAt: new Date().toISOString()
    });
  }

  return findings;
}
