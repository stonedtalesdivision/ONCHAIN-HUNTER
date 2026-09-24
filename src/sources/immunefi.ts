import type { BountyProgram, BountySource } from "../types.js";
import { extractGitHubRepos, extractUrls } from "./normalize.js";

const ENDPOINT = "https://immunefi.com/public-api/bounties.json";

type ImmunefiRecord = {
  project?: string; slug?: string; url?: string; status?: string;
  maxBounty?: number | string; rewardToken?: string; ecosystems?: string[];
  assetsInScope?: unknown;
  resources?: unknown;
  [key: string]: unknown;
};

function numberOrUndefined(value: unknown): number | undefined {
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (typeof value === "string") {
    const n = Number(value.replace(/[$,]/g, ""));
    return Number.isFinite(n) ? n : undefined;
  }
  return undefined;
}

function collectStrings(value: unknown, out: string[], depth = 0): void {
  if (depth > 8 || value == null) return;
  if (typeof value === "string") {
    out.push(value);
    return;
  }
  if (Array.isArray(value)) {
    for (const item of value) collectStrings(item, out, depth + 1);
    return;
  }
  if (typeof value === "object") {
    for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
      if (/^(project|slug|status|url|assetsInScope|resources)$/i.test(key)) continue;
      collectStrings(child, out, depth + 1);
    }
  }
}

export class ImmunefiBountySource implements BountySource {
  name = "immunefi";

  async discover(): Promise<BountyProgram[]> {
    const response = await fetch(ENDPOINT, { headers: { "user-agent": "ONCHAIN-HUNTER/0.3" } });
    if (!response.ok) throw new Error("Immunefi returned HTTP " + response.status);
    const data = await response.json() as unknown;
    if (!Array.isArray(data)) throw new Error("Unexpected Immunefi API response");

    const fetchedAt = new Date().toISOString();
    return (data as ImmunefiRecord[]).map((item, index) => {
      const rawValues: string[] = [];
      collectStrings(item.assetsInScope, rawValues);
      collectStrings(item.resources, rawValues);
      collectStrings(item, rawValues);
      const scopeValues = [...new Set(rawValues)];
      const urls = extractUrls(scopeValues);
      return {
        id: "immunefi:" + (item.slug ?? String(index)),
        name: typeof item.project === "string" ? item.project : (typeof item.slug === "string" ? item.slug : "program-" + index),
        platform: "Immunefi",
        url: typeof item.url === "string" ? item.url : (typeof item.slug === "string" ? "https://immunefi.com/bug-bounty/" + item.slug + "/" : "https://immunefi.com/bug-bounty/"),
        status: item.status === "inactive" ? "inactive" : "active",
        maxReward: numberOrUndefined(item.maxBounty),
        rewardCurrency: typeof item.rewardToken === "string" ? item.rewardToken : undefined,
        chains: Array.isArray(item.ecosystems) ? item.ecosystems.filter((x): x is string => typeof x === "string") : [],
        inScope: urls.length ? urls : scopeValues,
        sourceRepos: extractGitHubRepos(scopeValues),
        fetchedAt
      };
    });
  }
}
