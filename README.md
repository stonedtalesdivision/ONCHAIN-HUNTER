# ONCHAIN-HUNTER

Authorized Web3 security opportunity discovery and research platform.

## Mission
Discover legitimate security-research opportunities from public bounty programs and explicitly authorized repositories, then produce evidence-backed investigation candidates.

## Safety boundary
ONCHAIN-HUNTER does not brute-force wallets, access private keys, exploit mainnet systems, or target assets outside an explicitly authorized scope.

## Foundation
- TypeScript/Node.js core
- Normalized bounty-program model
- Repository ingestion interfaces
- Deterministic opportunity pipeline
- Database-ready domain model
- Environment-safe configuration

## Architecture
```
Bounty sources
     |
     v
Normalizer -> Opportunity queue -> Code analysis -> Local validation
     |                                  |
     +------------ PostgreSQL -----------+
                         |
                     Dashboard
```

## Roadmap
1. Bounty discovery
2. Authorized repository ingestion
3. Static Solidity/EVM analysis
4. AI-assisted investigation
5. Local-only proof validation
6. Responsible disclosure report generation
7. Dashboard and continuous monitoring


## Current implementation

- **Immunefi discovery adapter**: pulls the public bounty catalog and normalizes active programs.
- **Scope extraction**: extracts GitHub repository URLs when they are explicitly present in program scope/resources.
- **Deterministic Solidity scanner**: flags candidate patterns such as `tx.origin`, `selfdestruct`, `delegatecall`, low-level calls, and timestamp dependence. Findings are candidates for human review, not automatic vulnerability claims.
- **Safety boundary**: scanning is limited to repositories/assets explicitly associated with a bounty program. The scanner does not exploit live contracts, submit transactions, brute-force keys, or access private credentials.

The next stage is authorized repository ingestion: fetch only the source repositories explicitly listed by a bounty program, scan Solidity/EVM code, attach file/line evidence, and keep findings tied to the relevant program scope.


## Private dashboard and payout configuration

The production dashboard should be protected at the Nginx layer. Nginx supports HTTP Basic Authentication using a password file; credentials are never stored in this repository. Use `scripts/secure-dashboard.sh` on the VPS to enable it for `hunter.texvic.tech`. The script creates a backup before changing the Nginx site configuration and validates the configuration before reload. See the official Nginx documentation for Basic Authentication. 

For bounty payouts, configure only your **public receiving wallet address** in the VPS `.env`:
- `PAYOUT_WALLET_ADDRESS`: your public wallet address
- `PAYOUT_NETWORK`: network the receiving address uses
- `PAYOUT_ASSET`: preferred payout asset, such as USDC

Never put a seed phrase, private key, signing key, exchange password, or other secret in `.env.example`, GitHub, or the dashboard. A configured wallet address does not force a bounty program to pay; each program's own payout and KYC rules control whether and how a reward is paid. For example, Immunefi program pages specify their own payout terms and may require KYC. 

### Enable private access on the VPS

```bash
cd /root/ONCHAIN-HUNTER
bash scripts/secure-dashboard.sh hunter.texvic.tech
```

After authentication is enabled, both the dashboard and its API endpoints are protected by the same Nginx gate.

## Phase 6 — Bounty Matching

Phase 6 matches evidence packages against active bounty-program catalog records. It requires explicit repository scope for a match; unlisted repositories are not treated as eligible. Matches include impact/severity signals, payout routes, PoC/KYC requirements when the source exposes them, prohibited activities, known-issue notes, and a human-review status.

- `npm run bounty:match` writes `artifacts/hunt/bounty-matches.json`.
- Hunt artifacts now include `bountyMatches` and `bountyMatchSummary`.
- Exact repository scope is distinguished from catalog uncertainty.
- Payout routing is surfaced but never submitted automatically.
- Program-page scope, impact, known issues, PoC requirements and disclosure rules still require human review before submission.

## Phase 7 — Human-review disclosure reports

Phase 7 turns exact-scope bounty matches and evidence packages into structured security reports for human review. It does not submit reports or transactions automatically.

- `npm run report:hunt` reads `artifacts/hunt/latest.json` and writes JSON + Markdown reports under `artifacts/reports/`.
- `artifacts/hunt/review-queue.json` records every generated report, validation state, blockers and submission status.
- Reports include attack path, transaction sequence, evidence, source revision, bounty scope, payout routes and PoC/KYC requirements when available.
- Submission is permanently marked `false` in Phase 7; program-page review and responsible disclosure remain human-controlled.


## Phase 8 — Continuous Monitoring

Phase 8 adds persistent change detection to the autonomous hunt cycle. Each successful hunt records a monitoring snapshot for active bounty programs, prioritized repositories and evidence findings, then compares it with the previous snapshot.

- `artifacts/monitoring/state.json` stores the latest monitoring state.
- `artifacts/monitoring/latest-events.json` records newly detected program, target and finding changes.
- `GET /api/monitoring` exposes the latest monitoring events.
- `GET /api/status` now includes monitoring data.
- Changed repository refs and finding revisions are surfaced for follow-up scanning/review.
- Monitoring is detection-only: it does not exploit live systems or submit bounty reports automatically.


## Phase 9 — Investigation Orchestration

Phase 9 turns evidence packages into persistent investigation records for human review. Each finding receives a deterministic fingerprint, related functions/files, validation requirements, missing-evidence checks, revision-change detection and an investigation priority.

- `artifacts/investigations/state.json` stores investigation lifecycle state.
- `artifacts/investigations/latest.json` contains the prioritized investigation queue.
- `GET /api/investigations` exposes the current investigation queue.
- A finding that appears on a new source revision is explicitly marked for revalidation.
- Review reports incorporate investigation priority and missing-evidence information.
- Phase 9 does not execute live exploits or submit bounty reports automatically.


## Phase 11 — Deep-Dive & Proof Engine

Phase 11 converts each evidence package into a deterministic proof dossier containing scope, reachability, impact and reproduction claims, evidence references, gaps and a proof score. It never declares a finding exploitable automatically; human review remains required.

Artifacts: `artifacts/validation-bundles/*.proof.json`. API: `GET /api/proof`.

## Phase 12 — Local Validation Bundles

Phase 12 prepares an isolated Foundry validation harness for each evidence package and records the proof dossier alongside it. Execution remains disabled by default and is limited to explicitly authorized local environments. No live-network traffic or automatic bounty submission is performed.

Artifacts: `artifacts/validation-bundles/` and `test/onchain-hunter/`. API: `GET /api/validation-bundles`.


## Phase 13 — Advanced Bounty Intelligence

Phase 13 adds a deterministic intelligence layer for comparing bounty-program signals without treating an intelligence score as bounty eligibility. It combines reward, exact repository scope, impact/severity signals, freshness and program requirements into a research-priority view.

- `artifacts/hunt/bounty-intelligence.json` stores the ranked intelligence records.
- `GET /api/bounty-intelligence` exposes the latest intelligence artifact.
- Unknown PoC/KYC and other unresolved requirements remain explicit review risks.
- Program-page scope, impact, known issues, payout and disclosure rules still require human verification.

## Phase 14 — Research & Disclosure Workstation

Phase 14 consolidates investigation state, proof dossiers, local validation preparation and bounty intelligence into one human-review workstation. It is a research queue, not an autonomous submission system.

- `artifacts/hunt/research-workstation.json` stores prioritized review items, blockers and next actions.
- `GET /api/research-workstation` exposes the workstation artifact.
- Each item links its finding, source revision, investigation priority, proof score, validation state and evidence completeness signals.
- Blockers and revalidation requirements are surfaced before a report can be considered ready for human review.
- `submissionEnabled` remains permanently `false`; no bounty report or transaction is submitted automatically.
- `npm run research:workstation` can regenerate the workstation from existing hunt artifacts.


## Phase 15 — Final Production Release

Phase 15 is the final product-hardening phase. ONCHAIN-HUNTER is released as a production autonomous security-research platform with a complete discovery → scoped scan → evidence → investigation → proof → local validation → bounty intelligence → human-review workstation workflow.

- `artifacts/hunt/production-readiness.json` records final production checks.
- `GET /api/production-readiness` exposes the live readiness report.
- `GET /api/status` includes the readiness report.
- `npm run production:readiness` regenerates the final readiness report and fails when a required production artifact or safety contract is broken.
- The production release is explicitly human-review-only: live execution is disabled and automatic bounty submission is disabled.
- The existing Nginx HTTPS + Basic Auth deployment, PM2 service, health check and GitHub Actions deployment remain the production operating model.
- No private keys, seed phrases or signing credentials are required by the product.

### Final operating workflow

```text
Public bounty discovery
        ↓
Exact authorized repository scope
        ↓
Target prioritization + monitoring
        ↓
Static Solidity/EVM analysis
        ↓
Correlated evidence graph
        ↓
Investigation + revision tracking
        ↓
Proof dossier
        ↓
Local validation bundle
        ↓
Bounty intelligence
        ↓
Research & disclosure workstation
        ↓
Human review / responsible disclosure
```

**Release status:** final production product. Future work is optional enhancement, not a prerequisite phase.


## Phase 15 — Signal-to-Finding Exploitability Gate

The final production pipeline now separates static signals from actionable research candidates before bounty matching, proof generation and local validation.

- `src/exploitability-gate.ts` evaluates reachability, attacker control, authorization risk, concrete impact, exploit-path completeness, revision/evidence depth and corroboration.
- `artifacts/hunt/exploitability-gate.json` records every assessment and its reason/blocker set.
- `GET /api/exploitability-gate` exposes the latest gate results.
- Only `review` and `validation` candidates proceed to the downstream investigation, bounty-intelligence, proof and validation workflow.
- Weak static signals remain recorded in the hunt evidence but are deprioritized instead of consuming the review/validation queue.
- `validation` requires a high/critical candidate with a concrete impact, attacker-controlled path and complete multi-step exploit representation. This is a prioritization gate, not an automatic vulnerability verdict.
