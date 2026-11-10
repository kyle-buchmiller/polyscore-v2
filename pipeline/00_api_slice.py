#!/usr/bin/env python3
"""Stage 00 — the API slice: a sha256-prefix sample of the public metadata index, and its survey.

The pilot's source while the read replica is out of reach (decisions/0013). One Lucene
query per slice -- PE gate, first scan inside [start, end), sha256 under a hex prefix --
paged through /v3/search/metadata/query and cached page by page, so a killed walk resumes
from its last cursor. Every document is one file with its FIRST and LATEST scan: instance
ids, times, verdict counts, name-keyed assertions. That is enough to find the labellable
files, band them at T, and draw.

THE SURVEY is the point of the first run: the unscanned-first share, the rescan share,
the labellable share per horizon, the band histogram at T -- the numbers that decide how
wide a slice must be for a 10k cohort. `--history-sample N` spends N cheap history calls
to measure what the index cannot say: how many files have more than two scans, and how
often the latest scan is the label the estimand would have picked.

Writes: data/api_slice/<start>_<end>_<prefix>.parquet (+ manifest), raw pages under
        data/api_slice/.cache/<key>/, data/reports/api_slice_<key>.txt

Contract: specs/12-api-slice-pilot.md; specs/04-pipeline.md stage 00.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import sys
import time
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from polyscore_v2.api_source import (
    ApiClient,
    flatten,
    inclusion_probability,
    slice_query,
    to_frame,
    walk_slice,
)  # noqa: E402
from polyscore_v2.config import STRATUM_TARGETS, settings  # noqa: E402
from polyscore_v2.draw import DRAWN_STRATA, assign_stratum  # noqa: E402
from polyscore_v2.io import write_snapshot  # noqa: E402
from polyscore_v2.logging_setup import configure  # noqa: E402

HORIZON_MAX_LADDER = (90, 180, 365, 1000)


def _derived_prefix(n: int) -> str:
    # The seed's own hash: a run is reproducible from the seed alone, like the draw.
    return hashlib.md5(str(settings.random_seed).encode()).hexdigest()[:n]


def _survey(
    df: pd.DataFrame,
    *,
    prefix: str,
    start: str,
    end: str,
    horizon_days: int,
    horizon_max_days: int,
    cohort_size: int,
) -> str:
    pi = inclusion_probability(prefix)
    n = len(df)
    scale = 1 / pi
    first_def = df["first_definite"].fillna(0).astype(int)
    unscanned_first = first_def == 0
    scanned = ~unscanned_first
    rescanned = scanned & (df["latest_instance"] != df["first_instance"]).fillna(False).astype(bool)
    gap = (df["latest_created"] - df["first_created"]).dt.total_seconds() / 86400.0
    latest_def = df["latest_definite"].fillna(0).astype(int)

    def labellable_at(hmax: int) -> pd.Series:
        return rescanned & (gap >= horizon_days) & (gap < hmax) & (latest_def > 0)

    lab = labellable_at(horizon_max_days)
    pct = lambda m: f"{100 * m.sum() / max(n, 1):.1f}%"  # noqa: E731
    lines = [
        f"api slice -- prefix {prefix!r} (pi = 1/{int(scale)}), first scan in [{start}, {end})",
        f"{n} documents  ->  about {int(n * scale):,} files in the full frame for this window",
        "",
        f"unscanned first instance   {unscanned_first.sum():6d}  {pct(unscanned_first)}"
        f"   (of which scanned later: {int((unscanned_first & (latest_def > 0)).sum())})",
        f"scanned at first instance  {scanned.sum():6d}  {pct(scanned)}",
        f"rescanned at least once    {rescanned.sum():6d}  {pct(rescanned)}   (among scanned: "
        f"{100 * rescanned.sum() / max(scanned.sum(), 1):.1f}%)",
        "",
        f"labellable, horizon [{horizon_days}, hmax) days, by hmax:",
    ]
    for hmax in sorted(set(HORIZON_MAX_LADDER) | {horizon_max_days}):
        m = labellable_at(hmax)
        lines.append(
            f"  hmax {hmax:5d}   {m.sum():6d}  {pct(m)}   -> about {int(m.sum() * scale):,} in the full frame"
        )
    if rescanned.any():
        q = gap[rescanned].quantile([0.1, 0.5, 0.9])
        lines += [
            "",
            "gap to the latest scan, rescanned files (days): "
            f"p10 {q.iloc[0]:.1f}  p50 {q.iloc[1]:.1f}  p90 {q.iloc[2]:.1f}  max {gap[rescanned].max():.0f}",
        ]
    if scanned.any():
        q = first_def[scanned].quantile([0.1, 0.5, 0.9])
        lines += [
            "definite verdicts at the first scan, scanned files: "
            f"p10 {q.iloc[0]:.0f}  p50 {q.iloc[1]:.0f}  p90 {q.iloc[2]:.0f}"
        ]
    lines += [
        "",
        "mimetypes: " + ", ".join(f"{k}={v}" for k, v in df["mimetype"].value_counts().head(5).items()),
        "",
    ]

    if not lab.any():
        return "\n".join(lines + [f"no labellable files at hmax {horizon_max_days}"]) + "\n"
    L = df[lab].copy()
    L["stratum"] = assign_stratum(L["first_malicious"].fillna(0).astype(int), first_def[lab])
    g = L.groupby("stratum").agg(
        labellable=("sha256", "size"),
        gap_p50=("latest_created", lambda s: float(np.median(gap[s.index]))),
        def_med=("first_definite", "median"),
    )
    g = g.reindex([s for s in list(DRAWN_STRATA) + ["below_floor"] if s in g.index])
    g["share_%"] = (100 * g["labellable"] / lab.sum()).round(1)
    g["target_%"] = [round(100 * STRATUM_TARGETS.get(s, 0), 1) for s in g.index]
    g["fills_up_to"] = [
        int(k / STRATUM_TARGETS[s]) if STRATUM_TARGETS.get(s) else None
        for s, k in zip(g.index, g["labellable"], strict=True)
    ]
    lines += [
        f"bands at T among the {lab.sum()} labellable (hmax {horizon_max_days}), edges per decisions/0012:",
        g.round(1).to_string(),
        "",
    ]
    drawn = g.loc[[s for s in DRAWN_STRATA if s in g.index], "fills_up_to"]
    fill = int(drawn.min()) if len(drawn) else 0
    lines.append(f"largest cohort every drawn band fills at the SS9 shares, in THIS slice: {fill}")
    if fill:
        need = cohort_size / (fill * scale)  # the inclusion probability this window needs
        if need < 1:
            chars = max(1, math.floor(-math.log(need, 16)))
            lines.append(
                f"for a {cohort_size:,} cohort from this window alone: pi >= 1/{int(1 / need):,}"
                f" -> a {chars}-character prefix"
            )
        else:
            lines.append(
                f"a {cohort_size:,} cohort needs about {math.ceil(need)}x this window's months at pi = 1"
                f" (this window's whole frame fills {int(fill * scale):,})"
            )
    return "\n".join(lines) + "\n"


def _history_sample(
    client: ApiClient, df: pd.DataFrame, n: int, *, horizon_days: int, horizon_max_days: int, log
) -> str:
    """Spend n history calls on labellable files: scans per file, and is the latest scan the label?"""
    gap = (df["latest_created"] - df["first_created"]).dt.total_seconds() / 86400.0
    rescanned = (df["latest_instance"] != df["first_instance"]).fillna(False).astype(bool)
    lab = df[
        (df["first_definite"].fillna(0) > 0) & rescanned & (gap >= horizon_days) & (gap < horizon_max_days)
    ]
    if lab.empty:
        return "history sample: nothing labellable to sample\n"
    take = lab.sample(n=min(n, len(lab)), random_state=settings.random_seed)
    n_scans, latest_is_label, extra_scans = [], 0, 0
    for row in take.itertuples():
        hist = client.scan_history(row.sha256)
        scans = [h for h in hist if h.get("window_closed") and not h.get("failed")]
        n_scans.append(len(scans))
        t0 = pd.Timestamp(row.first_created)
        times = [pd.to_datetime(h["created"], utc=True) for h in scans]
        later = [t for t in times if (t - t0).total_seconds() >= horizon_days * 86400]
        if later:
            nearest = min(later)
            latest_is_label += int(abs((nearest - pd.Timestamp(row.latest_created)).total_seconds()) < 1)
        extra_scans += int(len(scans) > 2)
    k = len(take)
    s = pd.Series(n_scans)
    log.info("history sample done", extra={"files": k, "calls": client.calls})
    return (
        f"history sample over {k} labellable files ({client.calls} API calls so far):\n"
        f"  scans per file: p50 {s.median():.0f}  p90 {s.quantile(0.9):.0f}  max {s.max()}"
        f"   more than two scans: {extra_scans} ({100 * extra_scans / k:.0f}%)\n"
        f"  latest scan == nearest scan at least {horizon_days} days after T: "
        f"{latest_is_label} of {k} ({100 * latest_is_label / k:.0f}%)\n"
    )


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--start", required=True, help="first-scan window start, YYYY-MM-DD (inclusive)")
    ap.add_argument("--end", required=True, help="first-scan window end, YYYY-MM-DD (exclusive)")
    ap.add_argument("--prefix", help="lowercase hex sha256 prefix; default derives one from the seed")
    ap.add_argument("--prefix-len", type=int, default=3, help="length of the derived prefix (pi = 16^-len)")
    ap.add_argument("--no-pe-gate", action="store_true", help="REHEARSAL ONLY: drop the pefile gate")
    ap.add_argument("--limit", type=int, default=300, help="documents per page (the server caps it)")
    ap.add_argument("--horizon-max-days", type=int, default=settings.horizon_max_days)
    ap.add_argument(
        "--history-sample", type=int, default=0, help="labellable files to check with /search/instances"
    )
    ap.add_argument("--overwrite", action="store_true")
    a = ap.parse_args()
    log = configure()

    prefix = a.prefix or _derived_prefix(a.prefix_len)
    query = slice_query(prefix, a.start, a.end, pe_gate=not a.no_pe_gate)
    key = f"{a.start}_{a.end}_{prefix}" + ("_nogate" if a.no_pe_gate else "")
    out = settings.path("api_slice", f"{key}.parquet")
    if out.exists() and not a.overwrite:
        sys.exit(f"{out} exists; pass --overwrite to replace it (the page cache is kept)")
    for p in (out, out.with_suffix(".manifest.json")):
        p.unlink(missing_ok=True)
    cache_dir = settings.path("api_slice", ".cache", key, "x").parent
    cache_dir.mkdir(parents=True, exist_ok=True)

    client = ApiClient()
    t0 = time.monotonic()
    docs, pages = walk_slice(client, query, cache_dir, limit=a.limit)
    df = to_frame([flatten(d) for d in docs]) if docs else to_frame([flatten({})]).iloc[0:0]
    if df["sha256"].duplicated().any():
        raise SystemExit("duplicate sha256 across pages: the cursor walk is not sound")
    seconds = time.monotonic() - t0

    write_snapshot(
        df,
        out,
        stage="00_api_slice",
        source="public-api",
        query=query,
        prefix=prefix,
        inclusion_probability=inclusion_probability(prefix),
        window_start=a.start,
        window_end=a.end,
        pe_gate=not a.no_pe_gate,
        pages=pages,
        api_calls=client.calls,
        seconds=round(seconds, 1),
        community=client.community,
        api_url=client.base_url,
    )
    report = _survey(
        df,
        prefix=prefix,
        start=a.start,
        end=a.end,
        horizon_days=settings.horizon_days,
        horizon_max_days=a.horizon_max_days,
        cohort_size=settings.cohort_size,
    )
    if a.history_sample and len(df):
        report += "\n" + _history_sample(
            client,
            df,
            a.history_sample,
            horizon_days=settings.horizon_days,
            horizon_max_days=a.horizon_max_days,
            log=log,
        )
    rep = settings.path("reports", f"api_slice_{key}.txt")
    rep.write_text(report)
    print(report)
    print(
        json.dumps(
            {
                "slice": str(out),
                "rows": len(df),
                "pages": pages,
                "api_calls": client.calls,
                "seconds": round(seconds, 1),
                "report": str(rep),
            }
        )
    )


if __name__ == "__main__":
    main()
