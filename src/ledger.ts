import { readFile, writeFile, mkdir } from "node:fs/promises";
import { join } from "node:path";

export type BountyLedgerStatus = "submitted" | "accepted" | "paid" | "rejected";

export type BountyLedgerEntry = {
  id: string;
  opportunityId?: string;
  programId: string;
  programName?: string;
  title: string;
  status: BountyLedgerStatus;
  severity?: string;
  amount?: number;
  currency?: string;
  network?: string;
  walletAddress?: string;
  reportUrl?: string;
  payoutTxHash?: string;
  notes?: string;
  updatedAt: string;
};

const root = process.cwd();
const ledgerPath = join(root, "artifacts", "bounties", "ledger.json");

async function ensureLedger(): Promise<void> {
  await mkdir(join(root, "artifacts", "bounties"), { recursive: true });
  try { await readFile(ledgerPath, "utf8"); }
  catch { await writeFile(ledgerPath, "[]", "utf8"); }
}

export async function readLedger(): Promise<BountyLedgerEntry[]> {
  await ensureLedger();
  try {
    const parsed = JSON.parse(await readFile(ledgerPath, "utf8"));
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

export async function upsertLedgerEntry(entry: BountyLedgerEntry): Promise<BountyLedgerEntry[]> {
  const entries = await readLedger();
  const normalized = { ...entry, updatedAt: new Date().toISOString() };
  const index = entries.findIndex(item => item.id === normalized.id);
  if (index >= 0) entries[index] = normalized;
  else entries.unshift(normalized);
  await writeFile(ledgerPath, JSON.stringify(entries, null, 2), "utf8");
  return entries;
}
