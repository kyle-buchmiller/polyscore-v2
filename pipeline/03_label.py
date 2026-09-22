#!/usr/bin/env python3
"""Stage 03 — attach the answer column

Apply the specs/03-labels.md rules at T+horizon: cluster-adjusted counts, family
specificity, stability. Keep UNDECIDABLE rows in the file but flagged, so they can be
excluded from training and still counted in the report.

Requires the horizon to have elapsed. Freeze the cohort first, bulk-enqueue its rescans,
and run this after T+30.

Reads : data/snapshots/<run>.parquet
Writes: data/labels/<run>.parquet

Contract: specs/04-pipeline.md
"""

from __future__ import annotations

from polyscore_v2.config import settings
from polyscore_v2.logging_setup import configure

log = configure()


def main() -> None:
    raise NotImplementedError("stage 03 — see specs/04-pipeline.md")


if __name__ == "__main__":
    main()
