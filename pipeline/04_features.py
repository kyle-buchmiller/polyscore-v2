#!/usr/bin/env python3
"""Stage 04 — build the feature matrix

Everything learnable comes from the T scan's assertions (scan_role = 'feature'): two
columns per engine keyed on address, the aggregates, the family scalars -- and the old
one-column encoding beside them, so stage 07 can price the encoding change. The PE static
block is merged when a parquet is given (--static-block: sha256, pe_as_of, columns) and
checked row by row against the scoring moment; nothing fetches it yet.

THE AS-OF RULE IS ENFORCED HERE, in features.build_matrix: the deny-lists refuse the
regenerated fields, the incumbent, and the sampling bookkeeping; the static block is
refused if stamped after T. The manifest records the column groups the later stages
select from -- meta, bookkeeping, features_new, features_old -- so no stage guesses.

Reads : data/runs/<run_id>/cohort.parquet + the base's assertions
Writes: data/runs/<run_id>/features.parquet (+ manifest)

Contract: specs/04-pipeline.md (04 · features), specs/02-data.md.
"""

from __future__ import annotations

import argparse
from pathlib import Path

import pandas as pd

from polyscore_v2.features import build_matrix
from polyscore_v2.io import write_snapshot
from polyscore_v2.logging_setup import configure
from polyscore_v2.runs import fresh, load_run

log = configure()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--overwrite", action="store_true")
    ap.add_argument("--static-block", type=Path, default=None,
                    help="parquet of time-invariant PE fields: sha256, pe_as_of, <fields>")
    a = ap.parse_args()
    run = load_run()
    out = fresh(run.dir / "features.parquet", a.overwrite)

    static = pd.read_parquet(a.static_block) if a.static_block else None
    matrix, groups = build_matrix(run.cohort, run.assertions, static_block=static)
    if len(matrix) != len(run.cohort):
        raise SystemExit(f"{len(matrix)} feature rows for {len(run.cohort)} cohort rows")
    n_engines = sum(c.startswith("engine_") and c.endswith("_responded") for c in groups["features_new"])
    log.info("matrix built", extra={"rows": len(matrix), "engines": n_engines,
                                    "features_new": len(groups["features_new"]),
                                    "features_old": len(groups["features_old"])})
    write_snapshot(matrix, out, stage="04_features", run_id=run.run_id, groups=groups,
                   n_engines=n_engines, static_block=str(a.static_block) if a.static_block else None,
                   base_content_sha256=run.base_manifest.get("content_sha256"))
    print(f"features -- run {run.run_id}: {len(matrix)} rows, {n_engines} engines, "
          f"{len(groups['features_new'])} new-encoding columns, {len(groups['features_old'])} old-encoding columns"
          + (", static block merged" if static is not None else ", no static block"))


if __name__ == "__main__":
    main()
