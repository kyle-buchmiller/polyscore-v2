#!/usr/bin/env python3
"""Stage 02 — print the composition table

Every count from specs/02-data.md, to stdout and to a file. No modelling.

READ THE OUTPUT BEFORE CONTINUING. If distinct family clusters come back at 200, the
real sample size is 200 -- not 10,000 -- and every confidence interval downstream should
be read accordingly.

Reads : data/snapshots/<run>.parquet
Writes: data/reports/composition.txt

Contract: specs/04-pipeline.md
"""

from __future__ import annotations

from polyscore_v2.config import settings
from polyscore_v2.logging_setup import configure

log = configure()


def main() -> None:
    raise NotImplementedError("stage 02 — see specs/04-pipeline.md")


if __name__ == "__main__":
    main()
