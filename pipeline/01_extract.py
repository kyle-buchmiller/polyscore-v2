#!/usr/bin/env python3
"""Stage 01a — the base pull: every labellable artifact in the window, chunked, pi = 1

Tier one of decision 0010. Three kinds of statement, none of them large, every one of
them resumable:

  frame   02a_frame_chunk.sql, once per week of `created` from window_start - slack to
          window_end: every artifact whose FIRST-EVER reveal falls in the window, with
          its T scan. Index-driven; an anti-join finds "first ever".
  labels  02b_label_chunk.sql, once per 5,000 frame rows carried in as unnest() arrays:
          the nearest natural later scan inside [horizon, horizon_max] and the verdict
          counts at T. Rows that get no label are UNLABELLABLE: counted, drawn into the
          control sample, never in the base.
  assertions  03_assertions_pull.sql, once per 5,000 instance numbers: both scans of
          every base artifact, plus the T scan of every control artifact.

Why not one statement: the monolithic form was a second full scan of artifactinstance
hash-joined to the whole frame through a disk-spilling aggregate, and every per-artifact
step a nested loop over the whole population. On stage (1.2M revealed artifacts) it blew
a 30-minute statement timeout, then a 78-minute port-forward. Chunked, no statement is
near a timeout and a killed run resumes where it stopped (data/base/.cache/).

THE SURVEY IS A MODE OF THIS SCRIPT. `--sample-pct 10 --survey` walks the same frame and
label chunks over a deterministic 10% of artifacts (hashtext(sha256)), prints the band
histogram, gaps, coverage and the SS1 share, writes the sampled frame, and stops before
any assertion is pulled. Shares and percentiles are as good from 10% as from all; counts
scale by 100/pct. The base pull never samples unless told to -- pi needs every labellable
row -- and a sampled base records `frame_sample_pct` in its manifest.

THE PE GATE is applied to the frame before the label chunks (less work) and before the
base is written (so pi is over confirmed-PE bands). The gate itself is step 3's file.

Writes: data/base/<window>.parquet (+ manifest), .assertions.parquet,
        .control.parquet (+ manifest), .control.assertions.parquet,
        data/reports/survey_<window>_p<pct>.txt

Contract: specs/09-extraction-runbook.md steps 2, 4, 5; specs/04-pipeline.md stage 01a.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import time
from pathlib import Path

import numpy as np
import pandas as pd
import psycopg

from polyscore_v2.config import STRATUM_TARGETS, settings
from polyscore_v2.draw import DRAWN_STRATA, assign_stratum
from polyscore_v2.io import write_snapshot
from polyscore_v2.logging_setup import configure
from polyscore_v2.sql import dsn_from_env, query_sha256

log = configure()
SQL = Path("pipeline/sql")
QUERY_FILES = ["02a_frame_chunk.sql", "02b_label_chunk.sql", "03_assertions_pull.sql"]
CHUNK = 5_000
FRAME_COLS = ["sha256", "instance_number", "scoring_moment", "scan_config", "incumbent_polyscore"]
LABEL_COLS = ["sha256", "label_instance_number", "label_moment", "label_gap", "n_definite", "n_malicious", "n_responded"]


def _frame(cur, df_cache: Path, sql: str, start: dt.datetime, end: dt.datetime, *, slack_days: int,
           chunk_days: int, sample_pct: int, use_cache: bool) -> pd.DataFrame:
    edges = [start - dt.timedelta(days=slack_days)]
    while edges[-1] < end:
        edges.append(min(edges[-1] + dt.timedelta(days=chunk_days), end))
    frames = []
    for i, (a, b) in enumerate(zip(edges, edges[1:])):
        cache = df_cache / f"frame_{i:04d}.parquet"
        if use_cache and cache.exists():
            frames.append(pd.read_parquet(cache)); continue
        t0 = time.time()
        cur.execute(sql, {"created_from": a, "created_to": b, "window_start": start, "window_end": end,
                          "sample_pct": sample_pct})
        chunk = pd.DataFrame(cur.fetchall(), columns=FRAME_COLS)
        chunk.to_parquet(cache, index=False)
        frames.append(chunk)
        log.info("frame chunk", extra={"chunk": i + 1, "of": len(edges) - 1, "created_from": str(a.date()),
                                       "rows": len(chunk), "secs": round(time.time() - t0, 1)})
    frame = pd.concat(frames, ignore_index=True) if frames else pd.DataFrame(columns=FRAME_COLS)
    if frame["sha256"].duplicated().any():
        raise SystemExit("an artifact landed in two frame chunks: the first-ever rule failed")
    return frame


def _labels(cur, df_cache: Path, sql: str, frame: pd.DataFrame, *, horizon_days: int,
            horizon_max_days: int, use_cache: bool) -> pd.DataFrame:
    out = []
    n = -(-len(frame) // CHUNK)
    for i in range(n):
        cache = df_cache / f"labels_{i:04d}.parquet"
        if use_cache and cache.exists():
            out.append(pd.read_parquet(cache)); continue
        part = frame.iloc[i * CHUNK:(i + 1) * CHUNK]
        t0 = time.time()
        cur.execute(sql, {"sha256s": part["sha256"].tolist(),
                          "instance_numbers": [int(x) for x in part["instance_number"]],
                          "moments": [pd.Timestamp(x).to_pydatetime() for x in part["scoring_moment"]],
                          "horizon_days": int(horizon_days), "horizon_max_days": int(horizon_max_days)})
        chunk = pd.DataFrame(cur.fetchall(), columns=LABEL_COLS)
        chunk["label_gap"] = chunk["label_gap"].astype(str).where(chunk["label_gap"].notna(), None)
        chunk.to_parquet(cache, index=False)
        out.append(chunk)
        log.info("label chunk", extra={"chunk": i + 1, "of": n, "labellable": int(chunk["label_instance_number"].notna().sum()),
                                       "secs": round(time.time() - t0, 1)})
    return pd.concat(out, ignore_index=True) if out else pd.DataFrame(columns=LABEL_COLS)


def _assertions(cur, sql: str, roles: pd.DataFrame) -> pd.DataFrame:
    """Long form for every (sha256, scan_role, instance_number) in `roles`, chunked."""
    keys = roles["instance_number"].astype("int64").tolist()
    frames = []
    for i in range(0, len(keys), CHUNK):
        cur.execute(sql, {"instance_numbers": keys[i:i + CHUNK]})
        frames.append(pd.DataFrame(cur.fetchall(), columns=[d.name for d in cur.description]))
        log.info("assertions chunk", extra={"chunk": i // CHUNK + 1, "of": -(-len(keys) // CHUNK)})
    out = pd.concat(frames, ignore_index=True) if frames else pd.DataFrame(
        columns=["instance_number", "author", "verdict", "bid", "malware_family", "scanner_version"])
    out["instance_number"] = out["instance_number"].astype("int64")
    out = roles.merge(out, on="instance_number", how="inner")
    out["verdict"] = out["verdict"].astype("boolean")
    return out[["sha256", "scan_role", "instance_number", "author", "verdict", "bid",
                "malware_family", "scanner_version"]].sort_values(["sha256", "scan_role", "author"]).reset_index(drop=True)


def _survey(merged: pd.DataFrame, pct: int, horizon_days: int, horizon_max_days: int) -> str:
    lab = merged[merged["label_instance_number"].notna()].copy()
    scale = 100 / pct
    cust = merged["provenance"] == "customer"
    lines = [f"survey -- {len(merged)} frame artifacts" + (f" (a {pct}% sample: multiply counts by {scale:g})" if pct < 100 else ""),
             f"horizon [{horizon_days}, {horizon_max_days}) days",
             f"labellable {len(lab)} ({100 * len(lab) / max(len(merged), 1):.1f}%)   customer {int(cust.sum())}   "
             f"customer labellable {int((cust & merged['label_instance_number'].notna()).sum())}", ""]
    if lab.empty:
        return "\n".join(lines + ["no labellable artifacts"]) + "\n"
    lab["stratum"] = assign_stratum(lab["n_malicious"].fillna(0), lab["n_definite"].fillna(0))
    lab["gap_days"] = pd.to_timedelta(lab["label_gap"]).dt.total_seconds() / 86400.0
    g = lab.groupby("stratum").agg(labellable=("sha256", "size"),
                                   gap_p50=("gap_days", "median"), gap_p90=("gap_days", lambda x: x.quantile(0.9)),
                                   gap_max=("gap_days", "max"), def_min=("n_definite", "min"),
                                   def_p10=("n_definite", lambda x: x.quantile(0.1)), def_med=("n_definite", "median"),
                                   customer=("provenance", lambda x: int((x == "customer").sum())))
    g = g.reindex([s for s in list(DRAWN_STRATA) + ["below_floor"] if s in g.index])
    g["share_%"] = (100 * g["labellable"] / len(lab)).round(1)
    g["target_%"] = [round(100 * STRATUM_TARGETS.get(s, 0), 1) for s in g.index]
    g["fills_up_to"] = [int(n / STRATUM_TARGETS[s]) if STRATUM_TARGETS.get(s) else None
                        for s, n in zip(g.index, g["labellable"])]
    lines.append(g.round(1).to_string())
    drawn = g.loc[[s for s in DRAWN_STRATA if s in g.index], "fills_up_to"]
    lines += ["", f"largest cohort every drawn band can fill at the SS9 shares: "
                  f"{int(drawn.min() * scale) if len(drawn) else 0}" + (" (scaled)" if pct < 100 else ""),
              "horizon_max_days should be read off gap_p90 per band -- not guessed."]
    return "\n".join(lines) + "\n"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--window-start", required=True)
    ap.add_argument("--window-end", required=True)
    ap.add_argument("--pe-confirmed", type=Path, help="newline sha256 from the OpenSearch pass (step 3)")
    ap.add_argument("--no-pe-gate", action="store_true", help="REHEARSAL ONLY: skip the PE gate")
    ap.add_argument("--horizon-max-days", type=int, default=settings.horizon_max_days)
    ap.add_argument("--sample-pct", type=int, default=100, help="deterministic artifact sample, by hashtext(sha256)")
    ap.add_argument("--survey", action="store_true", help="stop after the label chunks: print the survey, write the frame")
    ap.add_argument("--control-size", type=int, default=settings.control_size)
    ap.add_argument("--chunk-days", type=int, default=7)
    ap.add_argument("--slack-days", type=int, default=7, help="created-range lead before window_start; completed >= created")
    ap.add_argument("--timeout", default="600s", help="statement_timeout per chunk")
    ap.add_argument("--no-cache", action="store_true", help="ignore cached chunks and re-run them")
    ap.add_argument("--overwrite", action="store_true")
    args = ap.parse_args()
    if not args.survey and bool(args.pe_confirmed) == args.no_pe_gate:
        raise SystemExit("exactly one of --pe-confirmed or --no-pe-gate (a survey needs neither)")

    start, end = dt.datetime.fromisoformat(args.window_start), dt.datetime.fromisoformat(args.window_end)
    window = f"{args.window_start}_{args.window_end}"
    variables = {"window_start": args.window_start, "window_end": args.window_end,
                 "horizon_days": settings.horizon_days, "horizon_max_days": args.horizon_max_days,
                 "sample_pct": args.sample_pct, "slack_days": args.slack_days}
    sql = {name: (SQL / name).read_text() for name in QUERY_FILES}
    # The cache is keyed by the query hash as well as the parameters, so a changed SQL file
    # can never silently replay chunks the old one produced.
    qhash = query_sha256(SQL, QUERY_FILES, variables)[:12]
    cache_dir = settings.path("base", ".cache", f"{window}_p{args.sample_pct}_h{args.horizon_max_days}_{qhash}")
    cache_dir.mkdir(parents=True, exist_ok=True)

    with psycopg.connect(dsn_from_env(), connect_timeout=15) as conn:
        conn.read_only = True
        cur = conn.cursor()
        cur.execute(f"SET statement_timeout = '{args.timeout}'")

        frame = _frame(cur, cache_dir, sql["02a_frame_chunk.sql"], start, end, slack_days=args.slack_days,
                       chunk_days=args.chunk_days, sample_pct=args.sample_pct, use_cache=not args.no_cache)
        frame["provenance"] = np.where(frame["scan_config"] == "feed", "feed", "customer")
        n_frame = len(frame)
        log.info("frame complete", extra={"artifacts": n_frame})

        if args.pe_confirmed:
            confirmed = {h.strip() for h in args.pe_confirmed.read_text().splitlines() if h.strip()}
            frame = frame[frame["sha256"].isin(confirmed)].reset_index(drop=True)
            pe_gate = "opensearch"
            log.info("PE gate applied", extra={"before": n_frame, "after": len(frame)})
        else:
            pe_gate = "skipped-SURVEY" if args.survey else "skipped-REHEARSAL"
            log.warning("PE GATE SKIPPED", extra={"mode": pe_gate})
        if frame.empty:
            raise SystemExit("frame is empty after the gate: widen the window or check step 3")

        labels = _labels(cur, cache_dir, sql["02b_label_chunk.sql"], frame, horizon_days=settings.horizon_days,
                         horizon_max_days=args.horizon_max_days, use_cache=not args.no_cache)
        merged = frame.merge(labels, on="sha256", how="left")
        if len(merged) != len(frame):
            raise SystemExit(f"{len(merged)} rows after labelling {len(frame)} frame rows")

        survey = _survey(merged, args.sample_pct, settings.horizon_days, args.horizon_max_days)
        rep = settings.path("reports", f"survey_{window}_p{args.sample_pct}.txt")
        rep.parent.mkdir(parents=True, exist_ok=True); rep.write_text(survey)
        print(survey)
        if args.survey:
            fp = settings.path("base", f"{window}.sample{args.sample_pct}.frame.parquet")
            merged.to_parquet(fp, index=False)
            log.info("survey written", extra={"report": str(rep), "frame": str(fp), "rows": len(merged)})
            return

        labellable = merged["label_instance_number"].notna()
        base = merged[labellable].sort_values("sha256").reset_index(drop=True)
        base["label_instance_number"] = base["label_instance_number"].astype("int64")
        for c in ("n_definite", "n_malicious", "n_responded"):
            # A labellable artifact with no assertion rows at T has NULL counts: a real row,
            # with zero responses, that assign_stratum puts below the floor.
            base[c] = base[c].fillna(0).astype("int64")
        base["label_gap"] = base["label_gap"].astype(str)
        base = base[["sha256", "instance_number", "scoring_moment", "label_instance_number", "label_moment",
                     "label_gap", "n_definite", "n_malicious", "n_responded", "scan_config", "provenance",
                     "incumbent_polyscore"]]
        if base.empty:
            raise SystemExit("no labellable artifacts: nothing to write")

        pool = merged[~labellable]
        key = pool["sha256"].map(lambda s: hashlib.md5(f"{s}{settings.random_seed}".encode()).hexdigest())
        control = pool.assign(_key=key).sort_values(["_key", "sha256"]).head(args.control_size).drop(columns="_key")
        control = control[["sha256", "instance_number", "scoring_moment", "scan_config", "provenance",
                           "incumbent_polyscore"]].reset_index(drop=True)
        control_pi = len(control) / len(pool) if len(pool) else float("nan")

        roles = pd.concat([
            base[["sha256", "instance_number"]].assign(scan_role="feature"),
            base[["sha256", "label_instance_number"]].rename(columns={"label_instance_number": "instance_number"}).assign(scan_role="label"),
        ], ignore_index=True)
        assertions = _assertions(cur, sql["03_assertions_pull.sql"], roles)
        log.info("assertions pulled", extra={"rows": len(assertions)})
        control_assertions = _assertions(cur, sql["03_assertions_pull.sql"],
                                         control[["sha256", "instance_number"]].assign(scan_role="feature"))

    out = settings.path("base", f"{window}.parquet")
    for p in (out, out.with_suffix(".manifest.json"), out.with_suffix(".assertions.parquet"),
              out.with_suffix(".control.parquet"), out.with_suffix(".control.manifest.json"),
              out.with_suffix(".control.assertions.parquet")):
        if p.exists():
            if not args.overwrite:
                raise SystemExit(f"{p} exists; pass --overwrite to replace the base deliberately")
            p.unlink()
    write_snapshot(
        base, out, stage="01a_base_pull",
        window=window, window_start=args.window_start, window_end=args.window_end,
        horizon_days=settings.horizon_days, horizon_max_days=args.horizon_max_days,
        pe_gate=pe_gate, query_sha256=query_sha256(SQL, QUERY_FILES, variables), query_files=QUERY_FILES,
        variables=variables, frame_sample_pct=args.sample_pct, slack_days=args.slack_days,
        frame_rows=n_frame, frame_pe_rows=int(len(frame)), labellable_rows=int(len(base)),
        unlabellable_rows=int(len(pool)), assertion_rows=int(len(assertions)),
        control_rows=int(len(control)), control_pi=control_pi, control_assertion_rows=int(len(control_assertions)),
    )
    assertions.to_parquet(out.with_suffix(".assertions.parquet"), index=False)
    write_snapshot(control, out.with_suffix(".control.parquet"), stage="01a_control", window=window,
                   control_pi=control_pi, drawn_from_unlabellable=int(len(pool)))
    control_assertions.to_parquet(out.with_suffix(".control.assertions.parquet"), index=False)
    log.info("base written", extra={"path": str(out), "rows": len(base), "control": len(control)})
    print(json.dumps({"base": str(out), "rows": len(base), "frame": n_frame, "after_pe_gate": int(len(frame)),
                      "control": len(control), "assertions": len(assertions)}, indent=2))


if __name__ == "__main__":
    main()
