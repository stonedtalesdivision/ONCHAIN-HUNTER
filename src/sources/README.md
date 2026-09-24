# Bounty sources

Each source implements the BountySource interface.

Immunefi
The Immunefi adapter reads the public bounty catalog and normalizes program metadata.

The adapter only stores public scope metadata; it does not execute target interaction.

Future adapters should:
- fetch only public bounty information;
- normalize scope and repository metadata;
- preserve source URLs;
- record retrieval time;
- never ingest secrets or private credentials.
