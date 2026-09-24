import type { BountyProgram, BountySource } from "../types.js";

const ENDPOINT = "https://immunefi.com/public-api/bounties.json";

type ImmunefiRecord = {
  project?: string; slug?: string; url?: string; status?: string;
  maxBounty?: number | string; rewardToken?: string; ecosystems?: string[];
  assetsInScope?: Array<{ name?: string; url?: string; type?: string }>;
};

function numberOrUndefined(value: unknown): number | undefined {
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (typeof value === "string") {
    const n = Number(value.replace(/[$,]/g, ""));
    return Number.isFinite(n) ? n : undefined;
  }
  return undefined;
}

export class ImmunefiBountySource implements BountySource {
  name = "immunefi";
  async discover(): Promise<BountyProgram[]> {
    const response = await fetch(ENDPOINT, { headers: { "user-agent": "ONCHAIN-HUNTER/0.1" } });
    if (!response.ok) throw new Error("Immunefi returned HTTP " + response.status);
    const data = await response.json() as unknown;
    if (!Array.isArray(data)) throw new Error("Unexpected Immunefi API response");
    const fetchedAt = new Date().toISOString();
    return (data as ImmunefiRecord[]).map((item, index) => ({
      id: "immunefi:" + (item.slug ?? String(index)),
      name: item.project ?? item.slug ?? "program-" + index,
      platform: "Immunefi",
      url: item.url ?? (item.slug ? "https://immunefi.com/bug-bounty/" + item.slug + "/" : "https://immunefi.com/bug-bounty/"),
      status: item.status === "inactive" ? "inactive" : "active",
      maxReward: numberOrUndefined(item.maxBounty), rewardCurrency: item.rewardToken,
      chains: item.ecosystems ?? [],
      inScope: (item.assetsInScope ?? []).map(asset => asset.url ?? asset.name ?? "").filter(Boolean),
      sourceRepos: [], fetchedAt
    }));
  }
}
