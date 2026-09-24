import "dotenv/config";
import { ImmunefiBountySource } from "./sources/immunefi.js";
import { buildOpportunityQueue } from "./pipeline.js";

const source = new ImmunefiBountySource();
const programs = await source.discover();
const opportunities = buildOpportunityQueue(programs);

console.log(JSON.stringify({
  service: "onchain-hunter",
  status: "discovery-ready",
  source: source.name,
  programs: programs.length,
  programsWithRepos: programs.filter(p => p.sourceRepos.length > 0).length,
  opportunities: opportunities.length
}, null, 2));
