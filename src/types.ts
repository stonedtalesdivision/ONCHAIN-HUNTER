export type Severity = "critical" | "high" | "medium" | "low" | "informational";
export type ProgramRequirement = {
  pocRequired?: boolean;
  kycRequired?: boolean;
  prohibitedActivities: string[];
  impactCategories: string[];
  knownIssueNotes: string[];
  sourceUrl: string;
};
export interface BountyProgram {
  id: string; name: string; platform: string; url: string;
  status: "active" | "inactive" | "unknown"; maxReward?: number; rewardCurrency?: string;
  chains: string[]; inScope: string[]; sourceRepos: string[]; fetchedAt: string;
  requirements?: ProgramRequirement;
}
export interface Opportunity {
  id: string; programId: string; title: string; category: string; severity: Severity;
  confidence: number; evidence: string[]; status: "new" | "investigating" | "validated" | "dismissed"; createdAt: string; repository?: string; sourceRevision?: string; scopeMatch?: "yes" | "no" | "unknown";
}
export interface BountySource { name: string; discover(): Promise<BountyProgram[]>; }
