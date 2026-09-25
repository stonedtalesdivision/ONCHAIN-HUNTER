import { readFile, writeFile, mkdir } from "node:fs/promises";

export type MonitoringState = {
  schemaVersion: "phase-8";
  updatedAt: string;
  programs: Record<string, { status: string; url: string; maxReward?: number; chains: string[]; sourceRepos: string[] }>;
  targets: Record<string, { programId: string; repository: string; ref: string; score: number }>;
  findings: Record<string, { severity: string; repository?: string; sourceRevision?: string; title: string }>;
};

export type MonitoringEvent = {
  type: "program-added" | "program-changed" | "program-removed" | "target-added" | "target-changed" | "target-removed" | "finding-new" | "finding-changed";
  key: string;
  details: string;
  detectedAt: string;
};

const statePath = "artifacts/monitoring/state.json";

export async function loadMonitoringState(): Promise<MonitoringState | null> {
  try {
    return JSON.parse(await readFile(statePath, "utf8")) as MonitoringState;
  } catch {
    return null;
  }
}

export async function updateMonitoringState(
  programs: MonitoringState["programs"],
  targets: MonitoringState["targets"],
  findings: MonitoringState["findings"]
): Promise<{ previous: MonitoringState | null; current: MonitoringState; events: MonitoringEvent[] }> {
  const previous = await loadMonitoringState();
  const now = new Date().toISOString();
  const current: MonitoringState = {
    schemaVersion: "phase-8",
    updatedAt: now,
    programs,
    targets,
    findings
  };
  const events: MonitoringEvent[] = [];

  const compare = (
    before: Record<string, unknown> | undefined,
    after: Record<string, unknown>,
    addedType: MonitoringEvent["type"],
    changedType: MonitoringEvent["type"],
    removedType?: MonitoringEvent["type"]
  ) => {
    const old = before ?? {};
    for (const [key, value] of Object.entries(after)) {
      if (!(key in old)) {
        events.push({ type: addedType, key, details: JSON.stringify(value), detectedAt: now });
      } else if (JSON.stringify(old[key]) !== JSON.stringify(value)) {
        events.push({ type: changedType, key, details: JSON.stringify(value), detectedAt: now });
      }
    }
    if (removedType) {
      for (const key of Object.keys(old)) {
        if (!(key in after)) {
          events.push({ type: removedType, key, details: "No longer present in current snapshot", detectedAt: now });
        }
      }
    }
  };

  compare(previous?.programs, current.programs, "program-added", "program-changed", "program-removed");
  compare(previous?.targets, current.targets, "target-added", "target-changed", "target-removed");
  compare(previous?.findings, current.findings, "finding-new", "finding-changed");

  await mkdir("artifacts/monitoring", { recursive: true });
  await writeFile(statePath, JSON.stringify(current, null, 2), "utf8");
  await writeFile(
    "artifacts/monitoring/latest-events.json",
    JSON.stringify({ schemaVersion: "phase-8", generatedAt: now, events }, null, 2),
    "utf8"
  );
  return { previous, current, events };
}
