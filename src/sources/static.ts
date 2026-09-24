import type { BountyProgram, BountySource } from "../types.js";
const now = () => new Date().toISOString();
export class StaticBountySource implements BountySource {\n  name = "static";
  constructor(private readonly programs: BountyProgram[] = []) {}
  async discover(): Promise<BountyProgram[]> { return this.programs.map(program => ({ ...program, fetchedAt: now() })); }
}
