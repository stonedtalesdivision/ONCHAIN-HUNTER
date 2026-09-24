import "dotenv/config";
import { createServer } from "node:http";
import { readFile, mkdir } from "node:fs/promises";
import { join } from "node:path";
import { spawn, type ChildProcess } from "node:child_process";

const port = Number(process.env.PORT ?? process.env.DASHBOARD_PORT ?? 4173);
const intervalMinutes = Math.max(15, Number(process.env.HUNT_INTERVAL_MINUTES ?? 60));
const limit = Math.max(1, Math.min(Number(process.env.ONCHAIN_HUNTER_LIMIT ?? 10), 20));
const root = process.cwd();
const artifact = join(root, "artifacts", "hunt", "latest.json");
const page = join(root, "dashboard", "index.html");
let active: ChildProcess | null = null;
let lastStartedAt: string | null = null;

async function runHunt(): Promise<boolean> {
  if (active) return false;
  await mkdir(join(root, "artifacts", "hunt"), { recursive: true });
  lastStartedAt = new Date().toISOString();
  active = spawn(process.execPath, [join(root, "dist", "jobs", "run-hunt.js")], {
    cwd: root,
    env: { ...process.env, ONCHAIN_HUNTER_LIMIT: String(limit) },
    stdio: ["ignore", "pipe", "pipe"]
  });
  active.stdout?.on("data", d => process.stdout.write(d));
  active.stderr?.on("data", d => process.stderr.write(d));
  active.on("close", code => {
    console.log(JSON.stringify({ event: "hunt-exit", code }));
    active = null;
  });
  return true;
}

function json(res: import("node:http").ServerResponse, status: number, value: unknown) {
  res.writeHead(status, { "content-type": "application/json", "cache-control": "no-store" });
  res.end(JSON.stringify(value));
}

createServer(async (req, res) => {
  try {
    if (req.method === "POST" && req.url === "/api/hunt") {
      const started = await runHunt();
      return json(res, 200, { started, running: Boolean(active), lastStartedAt, intervalMinutes, limit });
    }
    if (req.url?.startsWith("/api/status")) {
      let hunt: unknown = null;
      try { hunt = JSON.parse(await readFile(artifact, "utf8")); } catch {}
      return json(res, 200, { running: Boolean(active), lastStartedAt, intervalMinutes, limit, hunt });
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
