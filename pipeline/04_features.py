#!/usr/bin/env python3
"""Stage 04 — build the feature matrix

Assemble the ~120 numeric columns from specs/02-data.md.

THE AS-OF RULE IS ENFORCED HERE. Every field carries a timestamp and the builder refuses
anything stamped later than the scoring moment. Do not add a feature that bypasses
polyscore_v2.features.assert_as_of.

Reads : snapshot + labels
Writes: data/features/<run>.parquet

Contract: specs/04-pipeline.md
"""

from __future__ import annotations

from polyscore_v2.config import settings
from polyscore_v2.logging_setup import configure

log = configure()


def main() -> None:
    raise NotImplementedError("stage 04 — see specs/04-pipeline.md")


if __name__ == "__main__":
    main()
