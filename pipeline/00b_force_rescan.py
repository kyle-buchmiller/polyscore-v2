#!/usr/bin/env python3
"""Stage 00b — forced rescans: draw the cohort at T from API slices, rescan it, collect labels.

Natural rescans cannot label a 10k cohort from the public community (specs/12 § Measured),
so the pilot forces them (decisions/0014). Three phases, each resumable:

  draw     band every scanned-first file of the slices at T, draw the cohort stratified per
           SS9 with the seed (pi_draw recorded beside the slices' pi_base), write it.
  submit   POST one rescan per drawn file through /v3/consumer/submission/<community>/rescan
           in a seeded random order, so a partial run is a random subsample; one line per
           file in rescans.jsonl, so a killed run continues where it stopped.
  collect  fetch the full render of every forced instance and of its T instance (the index's
           document can be written before the reveal, with every verdict still hidden), keep
           the files whose forced window has closed, and write what the rest of the pipeline
           reads: a base + its assertions (01a's shape) and the run cohort (01b's shape), so
           02 -> 09 run unchanged.

Writes: data/forced/<run_id>/{draw.parquet, rescans.jsonl, renders.jsonl, collect.report.txt}
        data/base/forced_<run_id>.parquet (+ .assertions.parquet, manifest)
        data/runs/<run_id>/cohort.parquet (+ manifest)
Contract: specs/12-api-slice-pilot.md § Forced rescans; specs/04-pipeline.md stage 00b.
"""

from __future__ import annotations

import argparse
import dataclasses
import datetime as dt
import hashlib
import json
import sys
import time
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from polyscore_v2.api_source import ApiClient  # noqa: E402
from polyscore_v2.config import (  # noqa: E402
    CONSENSUS_MALICIOUS,
    CONTESTED_LOWER,
    CONTESTED_UPPER,
    MIN_ANSWERING_ENGINES,
    STRATUM_TARGETS,
    settings,
)
from polyscore_v2.draw import check_draw, stratified_draw  # noqa: E402
from polyscore_v2.io import read_snapshot, write_snapshot  # noqa: E402
from polyscore_v2.logging_setup import configure  # noqa: E402
from polyscore_v2.runs import fresh  # noqa: E402

VERDICT = {"malicious": True, "benign": False}
#: The API renders no scan_config, so no row can be told apart as feed or customer (specs/12).
PROVENANCE_UNKNOWN = "unknown"
DEVIATIONS = [
    "T is the index's first instance (scanned-first files only)",
    "the label is a forced rescan at T + age, not a natural later scan",
    "assertions come from the full render: engine id, name, bid, mask, family; scanner_version when rendered",
    "provenance is unknown for every row: no calibration from this base",
    "bands at draw time used the index's detections.total; the base's n_definite is the render's"
    " count of non-null verdicts, which can differ by one or two",
    "files over the rescan route's size cap are out of frame: the public API refuses them under this key",
]
STOP_STATUSES = (401, 402, 403)


def _out(run_id: str, name: str) -> Path:
    return settings.path("forced", run_id, name)


def _now() -> pd.Timestamp:
    return pd.Timestamp(dt.datetime.now(dt.UTC))


# ----------------------------------------------------------------------------- draw


def cmd_draw(a: argparse.Namespace, log) -> None:
    slices = [read_snapshot(Path(p)) for p in a.slice]
    windows = {(m["window_start"], m["window_end"]) for _, m in slices}
    if len(windows) != 1:
        sys.exit(f"slices must share one window, got {sorted(windows)}")
    prefixes = [m["prefix"] for _, m in slices]
    for i, p in enumerate(prefixes):
        for q in prefixes[i + 1 :]:
            if p.startswith(q) or q.startswith(p):
                sys.exit(f"prefixes overlap, the union's pi would be wrong: {p!r} {q!r}")
    pi_base = float(sum(m["inclusion_probability"] for _, m in slices))
    df = pd.concat([d for d, _ in slices], ignore_index=True)
    if df["sha256"].duplicated().any():
        sys.exit("duplicate sha256 across slices")

    now = _now()
    age = (now - df["first_created"]).dt.total_seconds() / 86400.0
    scanned = df["first_definite"].fillna(0) > 0
    in_age = (age >= a.min_age_days) & (age < a.max_age_days)
    # The rescan route refuses a file over the key's size cap, so such a file is out of frame
    # rather than drawn and lost; an unknown size stays in.
    under_cap = ~(df["size"] > a.max_size_bytes)
    keep = scanned & in_age & under_cap
    over_cap = int((scanned & in_age & ~under_cap).sum())
    frame = pd.DataFrame(
        {
            "sha256": df.loc[keep, "sha256"],
            "instance_number": df.loc[keep, "first_instance"].astype("int64"),
            "scoring_moment": df.loc[keep, "first_created"],
            "n_definite": df.loc[keep, "first_definite"].fillna(0).astype("int64"),
            "n_malicious": df.loc[keep, "first_malicious"].fillna(0).astype("int64"),
            "n_responded": df.loc[keep, "first_responded"].fillna(0).astype("int64"),
            "incumbent_polyscore": df.loc[keep, "first_polyscore"].astype("float64"),
            "first_assertions": df.loc[keep, "first_assertions"],
            "age_days": age[keep].round(2),
            "natural_rescan": (df.loc[keep, "latest_instance"] != df.loc[keep, "first_instance"])
            .fillna(False)
            .astype(bool),
        }
    ).reset_index(drop=True)

    cohort, reports = stratified_draw(
        frame, cohort_size=a.cohort_size, seed=settings.random_seed, min_definite=MIN_ANSWERING_ENGINES
    )
    problems = check_draw(cohort, reports)
    for r in reports:
        log.info("stratum", extra=dataclasses.asdict(r))
    if problems:
        for p in problems:
            log.error("draw check failed", extra={"problem": p})
        sys.exit(2)
    underfilled = [r.stratum for r in reports if r.underfilled]
    cohort = cohort.rename(columns={"pi": "pi_draw"})
    cohort["pi_base"] = pi_base
    cohort["pi"] = cohort["pi_draw"] * pi_base
    # Submission order: a seeded permutation, so a run cut short is still a random subsample
    # of every band. Salted differently from the draw's own key, which the drawn rows of a
    # thinly-sampled band all have at the low end: that key would send the band out first.
    order = cohort["sha256"].map(
        lambda s: hashlib.md5(f"submit:{s}:{settings.random_seed}".encode()).hexdigest()
    )
    cohort = cohort.assign(_o=order).sort_values("_o").drop(columns="_o").reset_index(drop=True)

    out = fresh(_out(a.run_id, "draw.parquet"), a.overwrite)
    (w0, w1) = next(iter(windows))
    write_snapshot(
        cohort,
        out,
        stage="00b_draw",
        run_id=a.run_id,
        source="public-api",
        slices=[str(p) for p in a.slice],
        slice_content_sha256=[m["content_sha256"] for _, m in slices],
        window_start=w0,
        window_end=w1,
        pi_base=pi_base,
        min_age_days=a.min_age_days,
        max_age_days=a.max_age_days,
        max_size_bytes=a.max_size_bytes,
        over_cap_rows=over_cap,
        slice_rows=int(len(df)),
        frame_rows=int(len(frame)),
        cohort_size_requested=a.cohort_size,
        band_edges={"lower": CONTESTED_LOWER, "upper": CONTESTED_UPPER, "consensus": CONSENSUS_MALICIOUS},
        min_definite=MIN_ANSWERING_ENGINES,
        targets=STRATUM_TARGETS,
        strata=[dataclasses.asdict(r) for r in reports],
        underfilled=underfilled,
        drawn_at=now.isoformat(),
        deviations=DEVIATIONS,
    )
    lines = [
        f"forced draw -- run {a.run_id}: {len(df)} slice rows, {int(scanned.sum())} scanned first,"
        f" {len(frame)} in age [{a.min_age_days}, {a.max_age_days}) days and under {a.max_size_bytes} bytes"
        f" ({over_cap} over the cap); pi_base = {pi_base:.6g}",
        f"{'stratum':20s} {'available':>9s} {'target':>7s} {'drawn':>6s} {'pi_draw':>8s}",
    ]
    for r in reports:
        lines.append(
            f"{r.stratum:20s} {r.n_available:9d} {r.n_target:7d} {r.n_draw:6d} {r.pi:8.4f}"
            + ("  UNDER-FILLED" if r.underfilled else "")
        )
    lines.append(f"cohort: {len(cohort)} files to rescan; written {out}")
    print("\n".join(lines))


# ----------------------------------------------------------------------------- submit


def _read_log(path: Path) -> dict[str, dict]:
    done: dict[str, dict] = {}
    if path.exists():
        for line in path.read_text().splitlines():
            if line.strip():
                rec = json.loads(line)
                done[rec["sha256"]] = rec  # the last record of a file wins
    return done


def cmd_submit(a: argparse.Namespace, log) -> None:
    cohort, _ = read_snapshot(_out(a.run_id, "draw.parquet"))
    logp = _out(a.run_id, "rescans.jsonl")
    done = _read_log(logp)
    todo = [
        r
        for r in cohort.itertuples(index=False)
        if r.sha256 not in done or (a.retry_errors and done[r.sha256].get("error"))
    ]
    if a.limit:
        todo = todo[: a.limit]
    log.info(
        "submit", extra={"cohort": len(cohort), "already": len(done), "todo": len(todo), "rate_per_s": a.rate}
    )
    if a.dry_run:
        for r in todo[:20]:
            print(r.sha256, r.stratum)
        print(f"dry run: {len(todo)} rescans would be submitted")
        return

    client = ApiClient(min_interval=1.0 / a.rate)
    ok = err = streak = 0
    t0 = time.monotonic()
    with logp.open("a") as fh:
        for i, r in enumerate(todo, 1):
            resp = client.post(
                f"/consumer/submission/{client.community}/rescan/sha256/{r.sha256}",
                {"community": client.community},
            )
            rec = {
                "sha256": r.sha256,
                "instance_number": int(r.instance_number),
                "stratum": r.stratum,
                "submitted_at": _now().isoformat(),
            }
            if "error" in resp:
                rec["error"] = resp["error"]
                rec["http_status"] = resp.get("http_status")
                err += 1
                streak += 1
            else:
                res = resp.get("result") or {}
                rec["rescan_instance"] = int(res["id"]) if res.get("id") is not None else None
                rec["rescan_created"] = res.get("created")
                ok += 1
                streak = 0
            fh.write(json.dumps(rec) + "\n")
            fh.flush()
            if i % 100 == 0 or i == len(todo):
                log.info("submitting", extra={"done": i, "of": len(todo), "ok": ok, "errors": err})
            if rec.get("http_status") in STOP_STATUSES or streak >= a.max_error_streak:
                log.error("stopping", extra={"last_error": rec.get("error"), "streak": streak})
                break
    print(
        json.dumps(
            {
                "run_id": a.run_id,
                "submitted_ok": ok,
                "errors": err,
                "seconds": round(time.monotonic() - t0, 1),
                "log": str(logp),
            }
        )
    )


# ----------------------------------------------------------------------------- collect


def _extract_render(res: dict) -> dict:
    """The facts the pipeline keeps from one full instance render; everything else is dropped."""
    rows = []
    for x in res.get("assertions") or []:
        meta = x.get("metadata") or {}
        scanner = meta.get("scanner") if isinstance(meta.get("scanner"), dict) else {}
        rows.append(
            {
                "author": str(x.get("author")),
                "author_name": x.get("author_name"),
                "verdict": x.get("verdict"),
                "bid": x.get("bid"),
                "mask": x.get("mask"),
                "malware_family": meta.get("malware_family"),
                "scanner_version": scanner.get("version"),
            }
        )
    return {
        "instance": int(res["id"]),
        "created": res.get("created"),
        "state": res.get("state"),
        "window_closed": bool(res.get("window_closed")),
        "failed": bool(res.get("failed")),
        "polyscore": res.get("polyscore"),
        "result": res.get("result"),
        "assertions": rows,
    }


def _fetch_renders(client: ApiClient, ids: list[int], cache: Path, log) -> dict[int, dict]:
    """Full renders by instance id, cached as JSONL; an unsettled or missing one is fetched again."""
    have: dict[int, dict] = {}
    if cache.exists():
        for line in cache.read_text().splitlines():
            if line.strip():
                rec = json.loads(line)
                have[rec["instance"]] = rec
    todo = [i for i in dict.fromkeys(ids) if i not in have or not have[i].get("window_closed")]
    log.info(
        "renders", extra={"wanted": len(set(ids)), "cached": len(set(ids)) - len(todo), "to_fetch": len(todo)}
    )
    with cache.open("a") as fh:
        for n, iid in enumerate(todo, 1):
            res = (client.get("/instance", [("id", str(iid)), ("community", client.community)]) or {}).get(
                "result"
            )
            rec = (
                _extract_render(res)
                if res and res.get("id")
                else {
                    "instance": iid,
                    "missing": True,
                    "window_closed": False,
                    "failed": False,
                    "assertions": [],
                }
            )
            have[iid] = rec
            fh.write(json.dumps(rec) + "\n")
            fh.flush()
            if n % 250 == 0:
                log.info("renders", extra={"done": n, "of": len(todo), "api_calls": client.calls})
    return have


def _status(row, renders: dict[int, dict]) -> str:
    if pd.isna(row.rescan_instance):
        return "not_submitted"
    lab = renders.get(int(row.rescan_instance), {})
    t = renders.get(int(row.instance_number), {})
    if lab.get("missing") or t.get("missing"):
        return "missing_render"
    if lab.get("failed"):
        return "failed"
    if not lab.get("window_closed"):
        return "pending"
    if not lab["assertions"] or not t.get("assertions"):
        return "no_assertions"
    return "labelled"


def _bid(value) -> int:
    """The render's bid is a decimal string of NCT-wei; 01a's column is int64, 0 when absent."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _assertion_rows(sha: str, role: str, rec: dict) -> list[dict]:
    return [
        {"sha256": sha, "scan_role": role, "instance_number": rec["instance"], **a, "bid": _bid(a.get("bid"))}
        for a in rec["assertions"]
    ]


def _counts(rec: dict) -> tuple[int, int, int]:
    verdicts = [a["verdict"] for a in rec["assertions"]]
    return (
        sum(1 for v in verdicts if v is not None),
        sum(1 for v in verdicts if v is True),
        len(verdicts),
    )


def cmd_collect(a: argparse.Namespace, log) -> None:
    cohort, cm = read_snapshot(_out(a.run_id, "draw.parquet"))
    # Through Python ints, never a float column: a 17-digit instance id does not survive
    # float64, and a frame built from records with a missing key becomes one.
    ok = [
        r for r in _read_log(_out(a.run_id, "rescans.jsonl")).values() if r.get("rescan_instance") is not None
    ]
    if not ok:
        sys.exit("nothing submitted yet")
    sub = pd.DataFrame(
        {
            "sha256": [r["sha256"] for r in ok],
            "rescan_instance": pd.array([int(r["rescan_instance"]) for r in ok], dtype="Int64"),
            "submitted_at": [r["submitted_at"] for r in ok],
        }
    )
    m = cohort.merge(sub, on="sha256", how="left")

    client = ApiClient(min_interval=1.0 / a.rate)
    submitted = m[m["rescan_instance"].notna()]
    if a.limit:
        submitted = submitted.head(a.limit)
    ids = [int(x) for x in submitted["rescan_instance"]] + [int(x) for x in submitted["instance_number"]]
    renders = _fetch_renders(client, ids, _out(a.run_id, "renders.jsonl"), log)
    m["status"] = [_status(r, renders) for r in m.itertuples(index=False)]
    counts = m["status"].value_counts()
    lab = m[m["status"] == "labelled"].copy()
    log.info("collected", extra={**{k: int(v) for k, v in counts.items()}, "api_calls": client.calls})

    lines = [
        f"forced collect -- run {a.run_id}: {len(m)} drawn, "
        f"{int((m['status'] != 'not_submitted').sum())} submitted, {client.calls} API calls this run",
        "status: " + ", ".join(f"{k}={v}" for k, v in counts.items()),
    ]
    per = m.groupby("stratum")["status"].value_counts().unstack(fill_value=0)
    lines += ["", per.to_string(), ""]
    if lab.empty:
        rep = _out(a.run_id, "collect.report.txt")
        rep.write_text("\n".join(lines) + "\n")
        print("\n".join(lines))
        print("no labelled files yet: run collect again once the rescans have closed their windows")
        return

    t_recs = [renders[int(i)] for i in lab["instance_number"]]
    l_recs = [renders[int(i)] for i in lab["rescan_instance"]]
    t_counts = pd.DataFrame(
        [_counts(r) for r in t_recs], columns=["n_definite", "n_malicious", "n_responded"]
    )
    l_counts = pd.DataFrame(
        [_counts(r) for r in l_recs], columns=["l_definite", "l_malicious", "l_responded"]
    )
    label_moment = pd.to_datetime([r["created"] for r in l_recs], utc=True)
    gap = label_moment - pd.DatetimeIndex(lab["scoring_moment"])
    gd = pd.Series(gap.total_seconds() / 86400.0)
    # The slice's counts at T came from the index; the render is authoritative. Report any drift.
    drift = int((t_counts["n_definite"].values != lab["n_definite"].values).sum())
    lines += [
        f"label gap (days): p10 {gd.quantile(0.1):.1f}  p50 {gd.median():.1f}  p90 {gd.quantile(0.9):.1f}"
        f"  min {gd.min():.1f}  max {gd.max():.1f}",
        f"definite verdicts at T: p50 {t_counts['n_definite'].median():.0f}; at the label scan:"
        f" p10 {l_counts['l_definite'].quantile(0.1):.0f}  p50 {l_counts['l_definite'].median():.0f}"
        f"  p90 {l_counts['l_definite'].quantile(0.9):.0f}",
        f"files whose definite count at T differs between the index and the render: {drift}",
    ]

    base = pd.DataFrame(
        {
            "sha256": lab["sha256"].values,
            "instance_number": lab["instance_number"].astype("int64").values,
            "scoring_moment": lab["scoring_moment"].values,
            "label_instance_number": lab["rescan_instance"].astype("int64").values,
            "label_moment": label_moment.tz_convert(None),
            "label_gap": [str(pd.Timedelta(x)) for x in gap],
            "n_definite": t_counts["n_definite"].astype("int64").values,
            "n_malicious": t_counts["n_malicious"].astype("int64").values,
            "n_responded": t_counts["n_responded"].astype("int64").values,
            "scan_config": pd.array([None] * len(lab), dtype="string"),
            "provenance": PROVENANCE_UNKNOWN,
            "incumbent_polyscore": lab["incumbent_polyscore"].astype("float64").values,
            "label_polyscore": [r["polyscore"] for r in l_recs],
        }
    )
    rows: list[dict] = []
    for sha, t, lr in zip(lab["sha256"], t_recs, l_recs, strict=True):
        rows += _assertion_rows(sha, "feature", t)
        rows += _assertion_rows(sha, "label", lr)
    assertions = pd.DataFrame(rows)
    assertions["verdict"] = assertions["verdict"].astype("boolean")
    assertions["instance_number"] = assertions["instance_number"].astype("int64")
    assertions["bid"] = assertions["bid"].astype("int64")
    assertions = assertions.sort_values(["sha256", "scan_role", "author"]).reset_index(drop=True)

    window = f"{cm['window_start']}_{cm['window_end']}"
    base_out = fresh(settings.path("base", f"forced_{a.run_id}.parquet"), a.overwrite)
    base_out.with_suffix(".assertions.parquet").unlink(missing_ok=True)
    # The run cohort's pi is the realized share per band, labelled over available: a file lost
    # after the draw (size cap, failed scan) lowers its band's pi instead of vanishing from it.
    # The design's pi_draw stays beside it; pi_base is a column, not a factor, as 01b's base pi
    # of 1 is not.
    realized = lab["stratum"].map(lab["stratum"].value_counts()).astype("int64")
    lab = lab.assign(n_draw=realized, pi=(realized / lab["n_available"]).astype("float64"))
    excluded = m[m["status"] != "labelled"].groupby("stratum")["status"].value_counts()
    excluded_after_draw = {f"{band}:{status}": int(n) for (band, status), n in excluded.items()}
    strata = [
        {**r, "n_drawn": r["n_draw"], "n_draw": int(lab["stratum"].eq(r["stratum"]).sum())}
        for r in cm["strata"]
    ]
    draw_cols = lab[["sha256", "stratum", "pi", "pi_draw", "pi_base", "n_available", "n_draw"]]
    base = base.merge(draw_cols[["sha256"]], on="sha256").sort_values("sha256").reset_index(drop=True)
    write_snapshot(
        base,
        base_out,
        stage="00b_collect",
        source="forced_rescan_api",
        run_id=a.run_id,
        window=window,
        window_start=cm["window_start"],
        window_end=cm["window_end"],
        horizon_days=settings.horizon_days,
        horizon_max_days=cm["max_age_days"],
        pi_base=cm["pi_base"],
        draw_content_sha256=cm["content_sha256"],
        statuses={k: int(v) for k, v in counts.items()},
        excluded_after_draw=excluded_after_draw,
        assertion_rows=int(len(assertions)),
        engine_key="author = engine id from the full render; author_name beside it",
        deviations=DEVIATIONS,
    )
    assertions.to_parquet(base_out.with_suffix(".assertions.parquet"), index=False)
    base_manifest = json.loads(base_out.with_suffix(".manifest.json").read_text())

    # 01b's cohort carries every base column plus the draw's; 02_compose reads n_definite and
    # n_responded off the cohort itself, so the run cohort is the base rows with the draw columns.
    run_cohort = (
        base.merge(draw_cols, on="sha256", how="inner")
        .sort_values(["stratum", "sha256"])
        .reset_index(drop=True)
    )
    run_out = fresh(settings.path("runs", a.run_id, "cohort.parquet"), a.overwrite)
    write_snapshot(
        run_cohort,
        run_out,
        stage="00b_collect",
        run_id=a.run_id,
        source="forced_rescan_api",
        base_snapshot=str(base_out),
        base_content_sha256=base_manifest["content_sha256"],
        base_window=window,
        horizon_max_days=cm["max_age_days"],
        cohort_size_requested=cm["cohort_size_requested"],
        band_edges=cm["band_edges"],
        min_definite=cm["min_definite"],
        targets=cm["targets"],
        strata=strata,
        underfilled=cm["underfilled"],
        excluded_after_draw=excluded_after_draw,
        deviations=DEVIATIONS,
    )
    lines += [
        "",
        f"base: {base_out} ({len(base)} rows, {len(assertions)} assertion rows)",
        f"run cohort: {run_out} ({len(run_cohort)} rows); next: make compose RUN={a.run_id}, then label",
    ]
    rep = _out(a.run_id, "collect.report.txt")
    rep.write_text("\n".join(lines) + "\n")
    print("\n".join(lines))


# ----------------------------------------------------------------------------- main


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--run-id", default=settings.run_id)
    ap.add_argument("--overwrite", action="store_true")
    sub = ap.add_subparsers(dest="cmd", required=True)

    d = sub.add_parser("draw", help="band the slices at T and draw the cohort")
    d.add_argument("--slice", action="append", required=True, help="an API slice parquet; repeat for a union")
    d.add_argument("--cohort-size", type=int, default=settings.cohort_size)
    d.add_argument(
        "--min-age-days", type=int, default=settings.horizon_days, help="first scan at least this old"
    )
    d.add_argument(
        "--max-size-bytes",
        type=int,
        default=33554432,
        help="the rescan route's artifact-size limit under this key; larger files are out of frame",
    )
    d.add_argument(
        "--max-age-days", type=int, default=settings.horizon_max_days, help="and younger than this"
    )

    s = sub.add_parser("submit", help="POST the rescans, resumably")
    s.add_argument("--rate", type=float, default=1.0, help="rescans per second")
    s.add_argument("--limit", type=int, default=0, help="submit at most this many (a canary)")
    s.add_argument("--retry-errors", action="store_true", help="re-POST the files whose last attempt failed")
    s.add_argument("--max-error-streak", type=int, default=10)
    s.add_argument("--dry-run", action="store_true")

    c = sub.add_parser("collect", help="read the forced scans back and write the base and run cohort")
    c.add_argument("--rate", type=float, default=3.0, help="render fetches per second")
    c.add_argument("--limit", type=int, default=0, help="collect at most this many submitted files (a test)")

    a = ap.parse_args()
    log = configure()
    {"draw": cmd_draw, "submit": cmd_submit, "collect": cmd_collect}[a.cmd](a, log)


if __name__ == "__main__":
    main()
