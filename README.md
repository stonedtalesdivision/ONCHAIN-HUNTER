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
