import type { BountyProgram } from "./types.js";

export type PayoutRoute = {
  network: string;
  asset?: string;
  address?: string;
  configured: boolean;
  reason: string;
};

const evm = process.env.PAYOUT_EVM_ADDRESS?.trim();
const solana = process.env.PAYOUT_SOLANA_ADDRESS?.trim();
const bitcoin = process.env.PAYOUT_BITCOIN_ADDRESS?.trim();

function normalize(value: string): string {
  return value.toLowerCase().replace(/[^a-z0-9]/g, "");
}

function routeForNetwork(network: string, asset?: string): PayoutRoute | null {
  const n = normalize(network);
  const a = normalize(asset ?? "");

  if (n.includes("solana") || a === "sol" || a.includes("spl")) {
    return {
      network,
      asset,
      address: solana,
      configured: Boolean(solana),
      reason: solana ? "Configured public Solana receiving address." : "Add PAYOUT_SOLANA_ADDRESS to the VPS .env."
    };
  }

  if (n.includes("bitcoin") || n === "btc" || a === "btc" || a === "bitcoin") {
    return {
      network,
      asset,
      address: bitcoin,
      configured: Boolean(bitcoin),
      reason: bitcoin ? "Configured public Bitcoin receiving address." : "Add PAYOUT_BITCOIN_ADDRESS to the VPS .env."
    };
  }

  if (
    n.includes("ethereum") ||
    n.includes("bnb") ||
    n.includes("binance") ||
    n.includes("arbitrum") ||
    n.includes("optimism") ||
    n.includes("polygon") ||
    n.includes("base") ||
    n.includes("avalanche") ||
    n.includes("linea") ||
    n.includes("zksync") ||
    n.includes("scroll") ||
    n.includes("fantom") ||
    n.includes("evm") ||
    a === "eth" ||
    a === "usdc" ||
    a === "usdt"
  ) {
    return {
      network,
      asset,
      address: evm,
      configured: Boolean(evm),
      reason: evm ? "Configured public EVM receiving address." : "Add PAYOUT_EVM_ADDRESS to the VPS .env."
    };
  }

  return null;
}

export function payoutRoutesForProgram(program: BountyProgram): PayoutRoute[] {
  const networks = program.chains.length ? program.chains : ["Program-selected network"];
  const routes = networks.map(network => routeForNetwork(network, program.rewardCurrency)).filter((x): x is PayoutRoute => Boolean(x));

  if (routes.length) return [...new Map(routes.map(route => [route.network + "|" + (route.asset ?? ""), route])).values()];

  return [{
    network: networks[0],
    asset: program.rewardCurrency,
    address: undefined,
    configured: false,
    reason: "No supported network mapping was inferred. Confirm the bounty program's payout instructions before submitting."
  }];
}
