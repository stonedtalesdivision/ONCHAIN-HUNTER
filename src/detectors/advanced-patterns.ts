import type { Opportunity, Severity } from "../types.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

type FunctionInfo = {
  name: string;
  visibility: string;
  mutability: string;
  modifiers: string[];
  parameters: Array<{ name: string; type: string }>;
  stateWrites: string[];
  externalCalls: string[];
  delegateCalls: string[];
  valueTransfers: string[];
  tokenTransfers: string[];
  signatureOps: string[];
  nonceWrites: string[];
  oracleReads: string[];
  accountingSignals: string[];
  upgradeOps: string[];
  userControlledInputs: string[];
  hasReentrancyGuard: boolean;
};

const ACCESS_CONTROL_MODIFIERS = [
  "onlyowner",
  "onlyadmin",
  "onlyrole",
  "onlyauthorized",
  "onlygovernance",
  "onlyminter",
  "onlyoperator",
  "onlyguardian",
  "onlykeeper",
  "auth",
  "restricted",
  "requiresauth",
];

const REENTRANCY_MODIFIERS = [
  "nonreentrant",
  "noreentrant",
  "lock",
  "mutex",
];

function isExternallyCallable(fn: FunctionInfo): boolean {
  return fn.visibility === "public" || fn.visibility === "external";
}

function hasAccessControl(fn: FunctionInfo): boolean {
  return fn.modifiers.some((m) =>
    ACCESS_CONTROL_MODIFIERS.includes(m.toLowerCase()),
  );
}

function hasReentrancyGuard(fn: FunctionInfo): boolean {
  return (
    fn.hasReentrancyGuard ||
    fn.modifiers.some((m) =>
      REENTRANCY_MODIFIERS.includes(m.toLowerCase()),
    )
  );
}

function makeOpportunity(
  pattern: string,
  file: string,
  functionName: string,
  title: string,
  category: string,
  severity: Severity,
  confidence: number,
  evidence: string[],
): Opportunity {
  return {
    id: `advanced:${pattern}:${file}:${functionName}`,
    programId: "unknown",
    title,
    category,
    severity,
    confidence,
    evidence,
    status: "new",
    createdAt: new Date().toISOString(),
  };
}

// ---------------------------------------------------------------------------
// Pattern detectors
// ---------------------------------------------------------------------------

function detectCrossFunctionReentrancy(
  file: string,
  functions: FunctionInfo[],
): Opportunity[] {
  const findings: Opportunity[] = [];

  const writersWithExternalCalls = functions.filter(
    (fn) =>
      isExternallyCallable(fn) &&
      fn.stateWrites.length > 0 &&
      (fn.externalCalls.length > 0 || fn.delegateCalls.length > 0) &&
      !hasReentrancyGuard(fn),
  );

  for (const writer of writersWithExternalCalls) {
    const writtenVars = new Set(writer.stateWrites);

    for (const reader of functions) {
      if (reader.name === writer.name) continue;
      if (!isExternallyCallable(reader)) continue;

      const overlapping = reader.stateWrites.filter((s) => writtenVars.has(s));
      if (overlapping.length === 0) continue;

      findings.push(
        makeOpportunity(
          "cross-function-reentrancy",
          file,
          writer.name,
          `Cross-function reentrancy: ${writer.name} -> ${reader.name}`,
          "reentrancy",
          "high",
          0.7,
          [
            `${writer.name} writes state [${writer.stateWrites.join(", ")}] and makes external calls [${[...writer.externalCalls, ...writer.delegateCalls].join(", ")}] without a reentrancy guard.`,
            `${reader.name} (${reader.visibility}) also accesses shared state [${overlapping.join(", ")}].`,
            `An attacker could reenter ${reader.name} during ${writer.name}'s external call, observing inconsistent state.`,
          ],
        ),
      );
    }
  }

  return findings;
}

function detectUnguardedStateWriteWithExternalCall(
  file: string,
  functions: FunctionInfo[],
): Opportunity[] {
  const findings: Opportunity[] = [];

  for (const fn of functions) {
    if (!isExternallyCallable(fn)) continue;
    if (fn.stateWrites.length === 0) continue;
    if (fn.externalCalls.length === 0 && fn.delegateCalls.length === 0) continue;
    if (hasReentrancyGuard(fn)) continue;

    findings.push(
      makeOpportunity(
        "unguarded-state-external",
        file,
        fn.name,
        `Unguarded state write with external call in ${fn.name}`,
        "reentrancy",
        "high",
        0.8,
        [
          `${fn.name} (${fn.visibility}) writes state [${fn.stateWrites.join(", ")}].`,
          `It also makes external calls [${[...fn.externalCalls, ...fn.delegateCalls].join(", ")}].`,
          `No reentrancy guard (nonReentrant or equivalent) was detected among modifiers [${fn.modifiers.join(", ") || "none"}].`,
        ],
      ),
    );
  }

  return findings;
}

function detectUnguardedValueTransfer(
  file: string,
  functions: FunctionInfo[],
): Opportunity[] {
  const findings: Opportunity[] = [];

  for (const fn of functions) {
    if (!isExternallyCallable(fn)) continue;
    if (fn.valueTransfers.length === 0) continue;
    if (hasAccessControl(fn)) continue;
    if (hasReentrancyGuard(fn)) continue;

    findings.push(
      makeOpportunity(
        "unguarded-value-transfer",
        file,
        fn.name,
        `Unguarded value transfer in ${fn.name}`,
        "access-control",
        "critical",
        0.75,
        [
          `${fn.name} (${fn.visibility}) performs value transfers [${fn.valueTransfers.join(", ")}].`,
          `No access control modifiers detected among [${fn.modifiers.join(", ") || "none"}].`,
          `Any external account may be able to trigger this transfer.`,
        ],
      ),
    );
  }

  return findings;
}

function detectPrivilegedWithoutAccessControl(
  file: string,
  functions: FunctionInfo[],
): Opportunity[] {
  const findings: Opportunity[] = [];

  for (const fn of functions) {
    if (!isExternallyCallable(fn)) continue;

    const privilegedOps = [
      ...fn.upgradeOps,
      ...fn.delegateCalls,
    ];

    const isLargeStateMutation = fn.stateWrites.length >= 3;

    if (privilegedOps.length === 0 && !isLargeStateMutation) continue;
    if (hasAccessControl(fn)) continue;

    const evidenceLines: string[] = [];
    if (fn.upgradeOps.length > 0) {
      evidenceLines.push(
        `Performs upgrade operations [${fn.upgradeOps.join(", ")}].`,
      );
    }
    if (fn.delegateCalls.length > 0) {
      evidenceLines.push(
        `Uses delegatecall [${fn.delegateCalls.join(", ")}], which can alter contract storage.`,
      );
    }
    if (isLargeStateMutation) {
      evidenceLines.push(
        `Writes ${fn.stateWrites.length} state variables [${fn.stateWrites.join(", ")}], indicating a bulk state mutation.`,
      );
    }
    evidenceLines.push(
      `No access control modifiers found among [${fn.modifiers.join(", ") || "none"}].`,
    );

    findings.push(
      makeOpportunity(
        "privileged-no-access-control",
        file,
        fn.name,
        `Privileged function ${fn.name} lacks access control`,
        "access-control",
        "critical",
        0.7,
        evidenceLines,
      ),
    );
  }

  return findings;
}

function detectOracleWithoutValidation(
  file: string,
  functions: FunctionInfo[],
): Opportunity[] {
  const findings: Opportunity[] = [];

  for (const fn of functions) {
    if (fn.oracleReads.length === 0) continue;

    const hasDownstreamEffect =
      fn.accountingSignals.length > 0 ||
      fn.valueTransfers.length > 0 ||
      fn.tokenTransfers.length > 0;

    if (!hasDownstreamEffect) continue;

    findings.push(
      makeOpportunity(
        "oracle-no-validation",
        file,
        fn.name,
        `Oracle dependency without validation in ${fn.name}`,
        "oracle-manipulation",
        "high",
        0.6,
        [
          `${fn.name} reads oracle data [${fn.oracleReads.join(", ")}].`,
          `It then performs downstream effects: ${[
            fn.accountingSignals.length > 0
              ? `accounting [${fn.accountingSignals.join(", ")}]`
              : "",
            fn.valueTransfers.length > 0
              ? `value transfers [${fn.valueTransfers.join(", ")}]`
              : "",
            fn.tokenTransfers.length > 0
              ? `token transfers [${fn.tokenTransfers.join(", ")}]`
              : "",
          ]
            .filter(Boolean)
            .join(", ")}.`,
          `Oracle result validation (staleness check, zero-price check) was not structurally detected. Manual review recommended.`,
        ],
      ),
    );
  }

  return findings;
}

function detectSignatureWithoutNonce(
  file: string,
  functions: FunctionInfo[],
): Opportunity[] {
  const findings: Opportunity[] = [];

  for (const fn of functions) {
    if (fn.signatureOps.length === 0) continue;
    if (fn.nonceWrites.length > 0) continue;

    findings.push(
      makeOpportunity(
        "sig-without-nonce",
        file,
        fn.name,
        `Signature operation without nonce in ${fn.name}`,
        "replay-attack",
        "high",
        0.75,
        [
          `${fn.name} performs signature operations [${fn.signatureOps.join(", ")}].`,
          `No nonce writes were detected, meaning the same signature may be replayed.`,
          `Verify that replay protection exists via deadline, domain separator, or external nonce tracking.`,
        ],
      ),
    );
  }

  return findings;
}

function detectTokenTransferWithUserInput(
  file: string,
  functions: FunctionInfo[],
): Opportunity[] {
  const findings: Opportunity[] = [];

  for (const fn of functions) {
    if (!isExternallyCallable(fn)) continue;
    if (fn.tokenTransfers.length === 0) continue;
    if (fn.userControlledInputs.length === 0) continue;

    findings.push(
      makeOpportunity(
        "token-transfer-user-input",
        file,
        fn.name,
        `Token transfer with user-controlled input in ${fn.name}`,
        "input-validation",
        "high",
        0.65,
        [
          `${fn.name} (${fn.visibility}) performs token transfers [${fn.tokenTransfers.join(", ")}].`,
          `User-controlled inputs detected: [${fn.userControlledInputs.join(", ")}].`,
          `If token address, amount, or recipient is attacker-controlled, this may enable arbitrary token drain.`,
        ],
      ),
    );
  }

  return findings;
}

function detectPayableWithoutValueCheck(
  file: string,
  functions: FunctionInfo[],
): Opportunity[] {
  const findings: Opportunity[] = [];

  for (const fn of functions) {
    if (!isExternallyCallable(fn)) continue;
    if (fn.mutability !== "payable") continue;

    if (fn.valueTransfers.length > 0) continue;

    const mentionsValue = fn.accountingSignals.some(
      (s) => s.toLowerCase().includes("value") || s.toLowerCase().includes("msg.value"),
    );
    if (mentionsValue) continue;

    findings.push(
      makeOpportunity(
        "payable-no-value-check",
        file,
        fn.name,
        `Payable function ${fn.name} may not use msg.value`,
        "locked-ether",
        "medium",
        0.6,
        [
          `${fn.name} (${fn.visibility}, payable) accepts ETH but has no detected value transfers or accounting for msg.value.`,
          `Received ETH may become permanently locked in the contract.`,
          `Verify that msg.value is checked or forwarded within the function body.`,
        ],
      ),
    );
  }

  return findings;
}

// ---------------------------------------------------------------------------
// Main export
// ---------------------------------------------------------------------------

export function detectAdvancedPatterns(analysis: any): Opportunity[] {
  const file: string = analysis.file ?? "unknown";
  const functions: FunctionInfo[] = analysis.functions ?? [];

  if (functions.length === 0) return [];

  const findings: Opportunity[] = [
    ...detectCrossFunctionReentrancy(file, functions),
    ...detectUnguardedStateWriteWithExternalCall(file, functions),
    ...detectUnguardedValueTransfer(file, functions),
    ...detectPrivilegedWithoutAccessControl(file, functions),
    ...detectOracleWithoutValidation(file, functions),
    ...detectSignatureWithoutNonce(file, functions),
    ...detectTokenTransferWithUserInput(file, functions),
    ...detectPayableWithoutValueCheck(file, functions),
  ];

  return findings;
}
