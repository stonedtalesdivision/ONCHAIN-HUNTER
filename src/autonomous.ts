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
const reviewQueueArtifact = join(root, "artifacts", "hunt", "review-queue.json");
const monitoringArtifact = join(root, "artifacts", "monitoring", "latest-events.json");
const investigationArtifact = join(root, "artifacts", "investigations", "latest.json");
const orchestrationArtifact = join(root, "artifacts", "investigations", "orchestration.json");
const validationArtifactDir = join(root, "artifacts", "validation-bundles");
const workstationArtifact = join(root, "artifacts", "hunt", "research-workstation.json");
const page = join(root, "dashboard", "index.html");
let active: ChildProcess | null = null;
let lastStartedAt: string | null = null;
let lastExitCode: number | null = null;
let lastError: string | null = null;
let retryTimer: NodeJS.Timeout | null = null;

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
    if (code !== 0) lastError = "Hunt exited with code " + code;
    if (code === 0) {
      const reportJob = join(root, "dist", "jobs", "generate-hunt-reports.js");
      const report = spawn(process.execPath, [reportJob, artifact], { cwd: root, env: { ...process.env }, stdio: ["ignore", "pipe", "pipe"] });
      report.stdout?.on("data", d => process.stdout.write(d));
      report.stderr?.on("data", d => process.stderr.write(d));
      report.on("error", error => console.error(JSON.stringify({ event: "report-generation-error", error: error instanceof Error ? error.message : String(error) })));
    }
    console.log(JSON.stringify({ event: "hunt-exit", code }));
    active = null;
    if (code !== 0 && !retryTimer) {
      retryTimer = setTimeout(() => { retryTimer = null; void runHunt(); }, 5 * 60_000);
    }
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
    if (req.method === "GET" && req.url === "/api/review-queue") {
      let queue: unknown = { schemaVersion: "phase-7", submissionEnabled: false, totalReports: 0, reports: [] };
      try { queue = JSON.parse(await readFile(reviewQueueArtifact, "utf8")); } catch {}
      return json(res, 200, queue);
    }
    if (req.method === "GET" && req.url === "/api/monitoring") {
      let monitoring: unknown = { schemaVersion: "phase-8", generatedAt: null, events: [] };
      let orchestration: unknown = { schemaVersion: "phase-10", executionEnabled: false, queue: [] };
      try { monitoring = JSON.parse(await readFile(monitoringArtifact, "utf8")); } catch {}
      return json(res, 200, monitoring);
    }
    if (req.method === "GET" && req.url === "/api/research-workstation") {
      let workstation: unknown = { schemaVersion: "phase-14", humanReviewOnly: true, submissionEnabled: false, summary: { total: 0, blocked: 0, readyForReview: 0 }, items: [], reviewQueue: [] };
      try { workstation = JSON.parse(await readFile(workstationArtifact, "utf8")); } catch {}
      return json(res, 200, workstation);
    }
    if (req.method === "GET" && req.url === "/api/bounty-intelligence") {
      let intelligence: unknown = { schemaVersion: "phase-13", total: 0, items: [] };
      try { const data = JSON.parse(await readFile(join(root, "artifacts", "hunt", "bounty-intelligence.json"), "utf8")); intelligence = data; } catch {}
      return json(res, 200, intelligence);
    }
    if (req.method === "GET" && req.url === "/api/proof") {
      let proof: unknown = { schemaVersion: "phase-11", total: 0, strong: 0 };
      try { const hunt = JSON.parse(await readFile(artifact, "utf8")); proof = hunt.proof ?? proof; } catch {}
      return json(res, 200, proof);
    }
    if (req.method === "GET" && req.url === "/api/validation-bundles") {
      return json(res, 200, { schemaVersion: "phase-12", directory: validationArtifactDir, executionEnabled: false });
    }
    if (req.method === "GET" && req.url === "/api/investigation-orchestration") {
      let orchestration: unknown = { schemaVersion: "phase-10", executionEnabled: false, queue: [] };
      try { orchestration = JSON.parse(await readFile(orchestrationArtifact, "utf8")); } catch {}
      return json(res, 200, orchestration);
    }
    if (req.method === "GET" && req.url === "/api/investigations") {
      let investigation: unknown = { schemaVersion: "phase-9", total: 0, records: [] };
      try { investigation = JSON.parse(await readFile(investigationArtifact, "utf8")); } catch {}
      return json(res, 200, investigation);
    }
    if (req.method === "GET" && req.url === "/api/ledger") {
      return json(res, 200, { entries: await readLedger() });
    }
    if (req.method === "POST" && req.url === "/api/ledger") {
      const body = await readJsonBody(req) as Record<string, unknown>;
      if (!body.id || !body.programId || !body.title || !body.status) {
        return json(res, 400, { error: "id, programId, title and status are required" });
      }
      const status = body.status;
      if (typeof status !== "string" || !["candidate", "validated", "submitted", "accepted", "paid", "rejected"].includes(status)) {
        return json(res, 400, { error: "invalid status" });
      }
      const entries = await upsertLedgerEntry({
        id: String(body.id),
        opportunityId: body.opportunityId ? String(body.opportunityId) : undefined,
        programId: String(body.programId),
        programName: body.programName ? String(body.programName) : undefined,
        title: String(body.title),
        status: status as BountyLedgerEntry["status"],
        severity: body.severity ? String(body.severity) : undefined,
        amount: typeof body.amount === "number" && Number.isFinite(body.amount) ? body.amount : undefined,
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
      let monitoring: unknown = { schemaVersion: "phase-8", generatedAt: null, events: [] };
      let orchestration: unknown = { schemaVersion: "phase-10", executionEnabled: false, queue: [] };
      try { monitoring = JSON.parse(await readFile(monitoringArtifact, "utf8")); } catch {}
      try { orchestration = JSON.parse(await readFile(orchestrationArtifact, "utf8")); } catch {}
      return json(res, 200, { running: Boolean(active), lastStartedAt, lastExitCode, lastError, intervalMinutes, limit, hunt, monitoring, orchestration, workstation, ledger: await readLedger() });
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
