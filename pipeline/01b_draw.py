#!/usr/bin/env python3
"""Stage 01b — the run draw: a stratified cohort from the base snapshot, locally.

THIS STAGE NEVER TOUCHES THE DATABASE. It reads the base Parquet that 01a produced and
draws `settings.cohort_size` artifacts stratified per estimand SS9, seeded by
`settings.random_seed`, recording pi per row. That is what makes:

    scaling         a change to POLYSCORE_COHORT_SIZE and nothing else
    retraining      seconds, not a replica query
    concurrency     free -- N runs read one immutable file
    reproducibility a true sentence: same base + same seed => identical cohort

Reads : settings.base_snapshot       (data/base/<window>.parquet + manifest)
Writes: data/runs/<run_id>/cohort.parquet + cohort.manifest.json

The stratum is computed HERE from n_malicious / n_definite with the edges in config,
not read from the base. The base is edge-agnostic so revising the bands after stage 02
reports on them never requires a re-pull; the manifest records which edges this run used.

Contract: specs/04-pipeline.md stage 01b, decisions/0010.
"""

from __future__ import annotations

import dataclasses
import sys
from pathlib import Path

from polyscore_v2.config import (
    CONTESTED_LOWER, CONTESTED_UPPER, MIN_ANSWERING_ENGINES, STRATUM_TARGETS, settings)
from polyscore_v2.draw import check_draw, stratified_draw
from polyscore_v2.io import read_snapshot, write_snapshot
from polyscore_v2.logging_setup import configure
from polyscore_v2.sql import base_query_drift

log = configure()
SQL = Path("pipeline/sql")


def main() -> None:
    if settings.base_snapshot is None:
        raise SystemExit("POLYSCORE_BASE_SNAPSHOT is unset — a run draws from a base, never the database")
    base, base_manifest = read_snapshot(Path(settings.base_snapshot))
    log.info("base loaded", extra={"rows": len(base), "base_sha256": base_manifest.get("content_sha256")})

    # The base is only as current as the query that pulled it, and nothing downstream can
    # tell: the stage rehearsal base predated decision 0010 and drew without complaint.
    drift = base_query_drift(base_manifest, SQL)
    if drift and not settings.allow_stale_base:
        raise SystemExit(drift)
    if drift:
        log.warning("drawing from a STALE base (POLYSCORE_ALLOW_STALE_BASE=1)", extra={"reason": drift})

    cohort, reports = stratified_draw(
        base,
        cohort_size=settings.cohort_size,
        seed=settings.random_seed,
        min_definite=MIN_ANSWERING_ENGINES,
    )
    problems = check_draw(cohort, reports)
    for r in reports:
        log.info("stratum", extra=dataclasses.asdict(r))
    if problems:
        for p in problems:
            log.error("draw check failed", extra={"problem": p})
        sys.exit(2)

    underfilled = [r.stratum for r in reports if r.underfilled]
    if underfilled:
        log.warning("under-filled strata (reported, NOT back-filled)", extra={"strata": underfilled})

    out = settings.path("runs", settings.run_id, "cohort.parquet")
    write_snapshot(
        cohort, out, stage="01b_draw",
        run_id=settings.run_id,
        base_snapshot=str(settings.base_snapshot),
        base_content_sha256=base_manifest.get("content_sha256"),
        base_window=base_manifest.get("window"),
        horizon_max_days=base_manifest.get("horizon_max_days", settings.horizon_max_days),
        cohort_size_requested=settings.cohort_size,
        band_edges={"lower": CONTESTED_LOWER, "upper": CONTESTED_UPPER},
        min_definite=MIN_ANSWERING_ENGINES,
        targets=STRATUM_TARGETS,
        strata=[dataclasses.asdict(r) for r in reports],
        underfilled=underfilled,
    )
    log.info("cohort written", extra={"path": str(out), "rows": len(cohort)})


if __name__ == "__main__":
    main()
