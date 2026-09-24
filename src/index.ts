import "dotenv/config";
import { StaticBountySource } from "./sources/static.js";
import { buildOpportunityQueue } from "./pipeline.js";
const source = new StaticBountySource();
const programs = await source.discover();
const opportunities = buildOpportunityQueue(programs);
console.log(JSON.stringify({ service: "onchain-hunter", status: "foundation-ready", programs: programs.length, opportunities: opportunities.length }, null, 2));
