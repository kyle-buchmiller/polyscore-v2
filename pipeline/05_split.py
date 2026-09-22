#!/usr/bin/env python3
"""Stage 05 — temporal and family-grouped split

Sort by time, cut at the estimand SS5 percentages, enforce the horizon gap, and ensure
no family cluster straddles a boundary.

Also writes the naive random split, clearly named optimistic. The gap between the two is
the pilot's single most valuable number.

Reads : data/features/<run>.parquet
Writes: data/splits/{train,validate,test}.parquet (+ *_random.parquet)

Contract: specs/04-pipeline.md
"""

from __future__ import annotations

from polyscore_v2.config import settings
from polyscore_v2.logging_setup import configure

log = configure()


def main() -> None:
    raise NotImplementedError("stage 05 — see specs/04-pipeline.md")


if __name__ == "__main__":
    main()
