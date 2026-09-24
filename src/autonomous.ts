import "dotenv/config";
import { createServer } from "node:http";
import { readFile, mkdir } from "node:fs/promises";
import { join } from "node:path";
import { spawn, type ChildProcess } from "node:child_process";
import { readLedger, upsertLedgerEntry, type BountyLedgerEntry } from "./ledger.js";

const port = Number(process.env.PORT ?? process.env.DASHBOARD_PORT ?? 4173);
const intervalMinutes = Math.max(15, Number(process.env.HUNT_INTERVAL_MINUTES ?? 60));
const limit = Math.max(1, Math.min(Number(process.env.ONCHAIN_HUNTER_LIMIT ?? 10), 20));
const root = process.cwd();
const artifact = join(root, "artifacts", "hunt", "latest.json");
const page = join(root, "dashboard", "index.html");
let active: ChildProcess | null = null;
let lastStartedAt: string | null = null;
let lastExitCode: number | null = null;
let lastError: string | null = null;

async function runHunt(): Promise<boolean> {
  if (active) return false;
  await mkdir(join(root, "artifacts", "hunt"), { recursive: true });
  lastStartedAt = new Date().toISOString();
  const job = join(root, "dist", "jobs", "run-hunt.js");
  active = spawn(process.execPath, [job], {
    cwd: root,
    env: { ...process.env, ONCHAIN_HUNTER_LIMIT: String(limit) },
    stdio: ["ignore", "pipe", "pipe"]
  });
  active.on("error", error => {
    lastError = error instanceof Error ? error.message : String(error);
    console.error(JSON.stringify({ event: "hunt-spawn-error", error: lastError }));
    active = null;
  });
  active.stdout?.on("data", d => process.stdout.write(d));
  active.stderr?.on("data", d => process.stderr.write(d));
  active.on("close", code => {
    lastExitCode = code;
    console.log(JSON.stringify({ event: "hunt-exit", code }));
    active = null;
  });
  return true;
}

function json(res: import("node:http").ServerResponse, status: number, value: unknown) {
  res.writeHead(status, { "content-type": "application/json", "cache-control": "no-store" });
  res.end(JSON.stringify(value));
}

async function readJsonBody(req: import("node:http").IncomingMessage): Promise<unknown> {
  const chunks: Buffer[] = [];
  for await (const chunk of req) chunks.push(Buffer.from(chunk));
  if (Buffer.concat(chunks).length > 64_000) throw new Error("Request body too large");
  return JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}");
}

createServer(async (req, res) => {
  try {
    if (req.method === "POST" && req.url === "/api/hunt") {
      const started = await runHunt();
      return json(res, started ? 202 : 409, {
        started, running: Boolean(active), lastStartedAt, lastExitCode, lastError, intervalMinutes, limit
      });
    }
    if (req.method === "GET" && req.url === "/api/health") {
      return json(res, 200, { ok: true, running: Boolean(active), lastStartedAt, lastExitCode, lastError });
    }
    if (req.method === "GET" && req.url === "/api/ledger") {
      return json(res, 200, { entries: await readLedger() });
    }
    if (req.method === "POST" && req.url === "/api/ledger") {
      const body = await readJsonBody(req) as Partial<BountyLedgerEntry>;
      if (!body.id || !body.programId || !body.title || !body.status) {
        return json(res, 400, { error: "id, programId, title and status are required" });
      }
      if (!["submitted", "accepted", "paid", "rejected"].includes(body.status)) {
        return json(res, 400, { error: "invalid status" });
      }
      const entries = await upsertLedgerEntry({
        id: String(body.id),
        opportunityId: body.opportunityId ? String(body.opportunityId) : undefined,
        programId: String(body.programId),
        programName: body.programName ? String(body.programName) : undefined,
        title: String(body.title),
        status: body.status,
        severity: body.severity ? String(body.severity) : undefined,
        amount: body.amount == null || body.amount === "" ? undefined : Number(body.amount),
        currency: body.currency ? String(body.currency) : undefined,
        network: body.network ? String(body.network) : undefined,
        walletAddress: body.walletAddress ? String(body.walletAddress) : undefined,
        reportUrl: body.reportUrl ? String(body.reportUrl) : undefined,
        payoutTxHash: body.payoutTxHash ? String(body.payoutTxHash) : undefined,
        notes: body.notes ? String(body.notes) : undefined,
        updatedAt: new Date().toISOString()
      });
      return json(res, 200, { saved: true, entries });
    }
    if (req.url?.startsWith("/api/status")) {
      let hunt: unknown = null;
      try { hunt = JSON.parse(await readFile(artifact, "utf8")); } catch {}
      return json(res, 200, { running: Boolean(active), lastStartedAt, lastExitCode, lastError, intervalMinutes, limit, hunt, ledger: await readLedger() });
    }
    if (req.url?.startsWith("/api/hunt")) {
      let body: unknown = { programsDiscovered: 0, scannedRepositories: 0, candidateFindings: 0, skippedRepositories: 0, attemptedRepositories: 0, rateLimited: false, results: [] };
      try { body = JSON.parse(await readFile(artifact, "utf8")); } catch {}
      return json(res, 200, body);
    }
    const body = await readFile(page, "utf8");
    res.writeHead(200, { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" });
    res.end(body);
  } catch (error) {
    json(res, 500, { error: error instanceof Error ? error.message : String(error) });
  }
}).listen(port, () => {
  console.log(JSON.stringify({ service: "onchain-hunter-autonomous", url: "http://localhost:" + port, intervalMinutes, limit }));
  void runHunt();
  setInterval(() => void runHunt(), intervalMinutes * 60_000);
});
