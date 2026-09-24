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
