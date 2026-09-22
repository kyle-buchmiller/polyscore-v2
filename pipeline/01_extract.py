#!/usr/bin/env python3
"""Stage 01 — pull the cohort and freeze a snapshot

Query Postgres for the estimand SS1 population, with a deterministic ORDER BY before
any limit, and write one parquet plus a manifest.

The SNAPSHOT, not the query, is the unit of reproducibility. Re-running a query against
a live database tomorrow returns different rows and silently invalidates every
downstream stage.

Reads : Postgres
Writes: data/snapshots/<run>.parquet + .manifest.json

Contract: specs/04-pipeline.md
"""

from __future__ import annotations

from polyscore_v2.config import settings
from polyscore_v2.logging_setup import configure

log = configure()


def main() -> None:
    raise NotImplementedError("stage 01 — see specs/04-pipeline.md")


if __name__ == "__main__":
    main()
