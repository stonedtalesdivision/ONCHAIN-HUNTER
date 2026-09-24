export type ValidationMode = "static-only" | "local-fork";
export type ValidationRequest = { repository: string; findingId: string; mode?: ValidationMode; rpcUrl?: string; forkBlock?: number };
export type ValidationResult = { findingId: string; mode: ValidationMode; status: "not-run"|"ready"|"blocked"; reason: string; commands: string[] };

export function prepareLocalValidation(request: ValidationRequest): ValidationResult {
  if (request.mode === "local-fork" && !request.rpcUrl) {
    return { findingId: request.findingId, mode: "local-fork", status: "blocked", reason: "An explicit RPC URL is required to create a local fork; no live-chain interaction is performed by ONCHAIN-HUNTER.", commands: [] };
  }
  const commands = request.mode === "local-fork"
    ? ["anvil --fork-url $FORK_RPC_URL" + (request.forkBlock ? " --fork-block-number " + request.forkBlock : ""), "forge test -vvv"]
    : ["forge test -vvv"];
  return { findingId: request.findingId, mode: request.mode ?? "static-only", status: "ready", reason: "Validation is prepared for an isolated local Foundry environment.", commands };
}
