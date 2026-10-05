#!/usr/bin/env python3
"""Stage 01a — the base pull: everything eligible in the window, no sampling.

Tier one of the two-tier extraction (estimand SS11, decisions/0010). ONE heavy query
against the replica that runs rarely and is the reproducibility unit; every run draw
samples from the Parquet this writes, locally, never from the database again.

Runs pipeline/sql/02_base_pull.sql, then 03_assertions_pull.sql for both scans of every
artifact it returned, and writes:

    data/base/<window>.parquet            one row per artifact, edge-agnostic
    data/base/<window>.manifest.json      query hash, window, bound, content hash
    data/base/<window>.assertions.parquet one row per (sha256, scan_role, author)

pi_base = 1 by construction. The content hash goes into every run manifest.

The PE gate is applied HERE, in pandas, after the pull and before the base is written:
the replica is a hot standby and refuses CREATE TEMP TABLE (measured 2026-10-01), so the
OpenSearch-confirmed set (runbook step 3) cannot be joined in SQL. Pass --pe-confirmed
<file>. Filtering before the base is written keeps the run draw's pi computed over
confirmed-PE band populations, which is the property that matters. For a REHEARSAL on
stage, where the CLI pod is not reachable from this box, --no-pe-gate skips the filter;
the manifest records that, and such a base is for exercising the pipeline, never for
training.

Contract: specs/04-pipeline.md stage 01a, specs/09-extraction-runbook.md steps 4-5.
"""

from __future__ import annotations

import argparse
from pathlib import Path

import pandas as pd
import psycopg

from polyscore_v2.config import settings
from polyscore_v2.io import write_snapshot
from polyscore_v2.logging_setup import configure
from polyscore_v2.sql import dsn_from_env, load_sql, statements_sha256

log = configure()
SQL = Path("pipeline/sql")

CHUNK = 5_000   # instance numbers per assertions query; ~2M at 1M artifacts => ~400 queries


def _pull_assertions(cur, assert_sql: str, base: pd.DataFrame) -> pd.DataFrame:
    """Both scans of every base artifact, chunked, with sha256 and scan_role attached."""
    roles = pd.concat([
        base[["sha256", "instance_number"]].assign(scan_role="feature"),
        base[["sha256", "label_instance_number"]].rename(columns={"label_instance_number": "instance_number"}).assign(scan_role="label"),
    ], ignore_index=True)
    roles["instance_number"] = roles["instance_number"].astype("int64")
    keys = roles["instance_number"].tolist()
    frames: list[pd.DataFrame] = []
    for i in range(0, len(keys), CHUNK):
        cur.execute(assert_sql, {"instance_numbers": keys[i : i + CHUNK]})
        cols = [d.name for d in cur.description]
        frames.append(pd.DataFrame(cur.fetchall(), columns=cols))
        log.info("assertions chunk", extra={"chunk": i // CHUNK + 1, "of": -(-len(keys) // CHUNK)})
    out = pd.concat(frames, ignore_index=True)
    out["instance_number"] = out["instance_number"].astype("int64")
    out = roles.merge(out, on="instance_number", how="inner")
    out["verdict"] = out["verdict"].astype("boolean")   # keep NULL as the 3rd state
    return out[["sha256", "scan_role", "instance_number", "author", "verdict", "bid",
                "malware_family", "scanner_version"]].sort_values(["sha256", "scan_role", "author"]).reset_index(drop=True)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--window-start", required=True)
    ap.add_argument("--window-end", required=True)
    ap.add_argument("--pe-confirmed", type=Path, help="newline sha256 from the OpenSearch pass")
    ap.add_argument("--no-pe-gate", action="store_true", help="REHEARSAL ONLY: skip the PE gate")
    ap.add_argument("--horizon-max-days", type=int, default=settings.horizon_max_days)
    ap.add_argument("--timeout", default="1800s")
    args = ap.parse_args()
    if bool(args.pe_confirmed) == args.no_pe_gate:
        raise SystemExit("exactly one of --pe-confirmed or --no-pe-gate")

    window = f"{args.window_start}_{args.window_end}"
    overrides = {"window_start": args.window_start, "window_end": args.window_end,
                 "horizon_days": str(settings.horizon_days),
                 "horizon_max_days": str(args.horizon_max_days)}
    base_stmts, variables = load_sql(SQL / "02_base_pull.sql", overrides)
    assert_sql = (SQL / "03_assertions_pull.sql").read_text()      # psycopg-parameterized, not \set
    query_hash = statements_sha256(base_stmts)   # what 01b_draw verifies the base against

    with psycopg.connect(dsn_from_env(), connect_timeout=15) as conn:
        conn.read_only = True                     # belt and braces; the replica enforces it anyway
        cur = conn.cursor()
        cur.execute(f"SET statement_timeout = '{args.timeout}'")
        for stmt in base_stmts[:-1]:
            cur.execute(stmt)
        cur.execute(base_stmts[-1])
        cols = [d.name for d in cur.description]
        base = pd.DataFrame(cur.fetchall(), columns=cols)
        log.info("base pulled (pre-gate)", extra={"artifacts": len(base)})

        # THE PE GATE, applied before the base is written so pi is over confirmed-PE bands
        if args.no_pe_gate:
            log.warning("PE GATE SKIPPED — rehearsal base, not for training")
        else:
            confirmed = {h.strip() for h in args.pe_confirmed.read_text().splitlines() if h.strip()}
            before = len(base)
            base = base[base["sha256"].isin(confirmed)].reset_index(drop=True)
            log.info("PE gate applied", extra={"before": before, "after": len(base)})
        if base.empty:
            raise SystemExit("base is empty: widen the window or check the survey")

        assertions = _pull_assertions(cur, assert_sql, base)
        log.info("assertions pulled", extra={"rows": len(assertions)})

    for col in ("label_gap",):
        base[col] = base[col].astype(str)
    out = settings.path("base", f"{window}.parquet")
    write_snapshot(
        base, out, stage="01a_base_pull",
        window=window, window_start=args.window_start, window_end=args.window_end,
        horizon_days=settings.horizon_days, horizon_max_days=args.horizon_max_days,
        pe_gate="skipped-REHEARSAL" if args.no_pe_gate else "opensearch",
        query_sha256=query_hash, variables=variables,
        assertion_rows=int(len(assertions)),
    )
    assertions.to_parquet(out.with_suffix(".assertions.parquet"), index=False)
    log.info("base written", extra={"path": str(out)})


if __name__ == "__main__":
    main()
