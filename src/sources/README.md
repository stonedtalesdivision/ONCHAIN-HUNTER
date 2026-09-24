# Bounty sources

Each source implements the `BountySource` interface.

Future adapters should fetch only public bounty information, normalize scope and repository metadata, preserve source URLs, record retrieval time, and never ingest secrets or private credentials.
