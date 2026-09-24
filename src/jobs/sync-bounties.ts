import { mkdir, writeFile } from "node:fs/promises";
import { ImmunefiBountySource } from "../sources/immunefi.js";
const source = new ImmunefiBountySource();
const programs = await source.discover();
await mkdir("data", { recursive: true });
await writeFile("data/immunefi-bounties.json", JSON.stringify({ source: source.name, fetchedAt: new Date().toISOString(), count: programs.length, programs }, null, 2));
console.log(JSON.stringify({ source: source.name, count: programs.length, output: "data/immunefi-bounties.json" }, null, 2));
