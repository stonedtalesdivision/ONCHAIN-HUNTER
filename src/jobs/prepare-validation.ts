import { prepareLocalValidation } from "../validation.js";
const repository = process.argv[2];
const findingId = process.argv[3];
if (!repository || !findingId) {
  console.error("Usage: npm run validate:prepare -- owner/name finding-id");
  process.exit(1);
}
const mode = process.env.VALIDATION_MODE === "local-fork" ? "local-fork" as const : "static-only" as const;
const result = prepareLocalValidation({ repository, findingId, mode, rpcUrl: process.env.FORK_RPC_URL, forkBlock: process.env.FORK_BLOCK ? Number(process.env.FORK_BLOCK) : undefined });
console.log(JSON.stringify(result, null, 2));
