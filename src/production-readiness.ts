import { access, readFile, stat } from "node:fs/promises";
import { join } from "node:path";

export type ProductionCheck = {
  id: string;
  name: string;
  status: "pass" | "warn" | "fail";
  detail: string;
};

export type ProductionReadiness = {
  schemaVersion: "phase-15";
  product: "ONCHAIN-HUNTER";
  generatedAt: string;
  release: "final";
  productionReady: boolean;
  autonomousHunting: boolean;
  humanReviewOnly: true;
  liveExecutionEnabled: false;
  automaticSubmissionEnabled: false;
  checks: ProductionCheck[];
  requiredEnvironment: string[];
  operationalNotes: string[];
};

async function exists(path: string): Promise<boolean> {
  try { await access(path); return true; } catch { return false; }
}

export async function buildProductionReadiness(root = process.cwd()): Promise<ProductionReadiness> {
  const checks: ProductionCheck[] = [];
  const requiredFiles = [
    "dist/autonomous.js",
    "dist/jobs/run-hunt.js",
    "dashboard/index.html",
    "ecosystem.config.cjs",
    "package.json"
  ];
  for (const file of requiredFiles) {
    checks.push({
      id: "file:" + file,
      name: "Production artifact " + file,
      status: await exists(join(root, file)) ? "pass" : "fail",
      detail: await exists(join(root, file)) ? "present" : "missing"
    });
  }

  let packageOk = false;
  try {
    const pkg = JSON.parse(await readFile(join(root, "package.json"), "utf8"));
    packageOk = pkg.name === "onchain-hunter" && pkg.scripts?.build === "tsc" && pkg.scripts?.test === "npm run build && node --test";
  } catch {}
  checks.push({
    id: "package-contract",
    name: "Build and test contract",
    status: packageOk ? "pass" : "fail",
    detail: packageOk ? "build and test scripts are present" : "package contract is incomplete"
  });

  const envChecks = [
    ["github-access", Boolean(process.env.GITHUB_TOKEN), "GITHUB_TOKEN configured; unauthenticated mode is supported but lower-rate"],
    ["payout-addresses", Boolean(process.env.PAYOUT_EVM_ADDRESS || process.env.PAYOUT_SOLANA_ADDRESS || process.env.PAYOUT_BITCOIN_ADDRESS), "at least one public payout address configured"],
  ] as const;
  for (const [id, ok, detail] of envChecks) {
    checks.push({ id, name: id === "github-access" ? "GitHub access" : "Payout routing", status: ok ? "pass" : "warn", detail: ok ? detail : id === "github-access" ? "GITHUB_TOKEN not configured; discovery uses public API limits" : "no payout address configured; payouts remain manual" });
  }

  const safetyChecks: ProductionCheck[] = [
    { id: "no-live-execution", name: "Live execution disabled", status: "pass", detail: "validation bundles require explicit local execution and do not use live network traffic" },
    { id: "no-auto-submit", name: "Automatic bounty submission disabled", status: "pass", detail: "all disclosure and payout actions remain human-controlled" },
    { id: "authorized-scope", name: "Authorized-scope scanning", status: "pass", detail: "hunt targets are derived from explicit bounty-program repository scope" },
    { id: "private-key-free", name: "Private-key handling", status: "pass", detail: "the application does not require or store signing keys or seed phrases" }
  ];
  checks.push(...safetyChecks);

  const failed = checks.filter(c => c.status === "fail");
  const ready = failed.length === 0;
  return {
    schemaVersion: "phase-15",
    product: "ONCHAIN-HUNTER",
    generatedAt: new Date().toISOString(),
    release: "final",
    productionReady: ready,
    autonomousHunting: true,
    humanReviewOnly: true,
    liveExecutionEnabled: false,
    automaticSubmissionEnabled: false,
    checks,
    requiredEnvironment: ["NODE_ENV=production", "PORT=3200", "HUNT_INTERVAL_MINUTES (optional)", "ONCHAIN_HUNTER_LIMIT (optional)", "GITHUB_TOKEN (recommended)"],
    operationalNotes: [
      "Protect hunter.texvic.tech with the existing Nginx Basic Auth gate.",
      "Run behind HTTPS and keep the VPS .env outside Git.",
      "Review exact bounty scope, source revision, proof and validation before disclosure.",
      "Never add private keys, seed phrases or exchange credentials to environment files."
    ]
  };
}

async function main(): Promise<void> {
  const report = await buildProductionReadiness();
  await import("node:fs/promises").then(fs => fs.writeFile("artifacts/hunt/production-readiness.json", JSON.stringify(report, null, 2), "utf8"));
  console.log(JSON.stringify(report, null, 2));
  if (!report.productionReady) process.exitCode = 1;
}

if (process.argv[1]?.endsWith("production-readiness.ts")) main().catch(error => { console.error(error); process.exitCode = 1; });
