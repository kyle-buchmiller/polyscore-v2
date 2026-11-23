#!/usr/bin/env python3
"""Stage 03b — draw the gold slice

The 200 files a human adjudicates against estimand SS3 (decisions/0004; specs/03-labels.md,
"Why the gold slice matters"): drawn at RANDOM from the contested band at T -- never by a
model's score -- in two equal groups, files whose detections accrued (label malicious,
reason `grew` or `consensus`) and files that stayed contested (the provisional negatives),
so both outcomes of the cheap label get checked. Every row's inclusion probability is
recorded at draw time (R3: it cannot be added later): the gold draw's own, and its product
with the cohort's pi.

Two outputs, deliberately separate. draw.parquet carries everything -- group, cheap label,
reason, movement -- and is for the import step, not the adjudicator. review.csv is the
adjudicator's sheet: the hash, a portal link and empty verdict columns, in a shuffled order
with no group, so the judgement is blind to what we think the answer is.

`--continues <run>` tops that run's slice up instead of drawing a new one: its files that are
still eligible stay, each group is filled back up at random, and every row's probability
counts both ways into the slice.

Reads : data/runs/<run_id>/{cohort,labels}.parquet; with --continues, the earlier run's
        cohort and labels and its data/gold/<run>/draw.parquet
Writes: data/gold/<run_id>/draw.parquet (+ manifest), review.csv, hashes.txt; with
        --continues, new_hashes.txt (the files that were not in the earlier slice)

Contract: specs/04-pipeline.md (03b · gold draw), specs/03-labels.md, decisions/0004.
"""

from __future__ import annotations

import argparse

import numpy as np
import pandas as pd

from polyscore_v2.config import settings
from polyscore_v2.gold import GROUPS, Earlier, draw, pools
from polyscore_v2.io import read_snapshot, write_snapshot
from polyscore_v2.logging_setup import configure
from polyscore_v2.runs import fresh, load_run

log = configure()
PORTAL = "https://polyswarm.network/scan/results/file/{sha256}"
RUBRIC = ("estimand SS3: malicious if, run as intended in a typical environment, it does things a "
          "fully-informed owner of that machine would not agree to, for someone else's benefit, "
          "as of a stated date; verdicts malicious | benign | unwanted | undecidable")
COLUMNS = ["sha256", "group", "carried_from", "instance_number", "label_instance_number", "scoring_moment",
           "label_moment", "horizon_days", "label", "reason", "provisional", "band_t", "stratum", "m_t", "m",
           "delta_m", "n_definite_t", "n_definite", "n_both", "pi", "pi_gold", "pi_overall", "n_eligible"]


def _earlier(run_id: str, band: str) -> Earlier:
    """An earlier run's gold draw and the pools it was drawn from, rebuilt from that run's labels."""
    drawn, dm = read_snapshot(settings.path("gold", run_id, "draw.parquet"))
    labels, lm = read_snapshot(settings.path("runs", run_id, "labels.parquet"))
    cohort, _ = read_snapshot(settings.path("runs", run_id, "cohort.parquet"))
    if dm.get("band") != band:
        raise SystemExit(f"the gold slice of run {run_id} is of band {dm.get('band')!r}, not {band!r}")
    if dm.get("continues"):
        raise SystemExit(f"the gold slice of run {run_id} is itself a top-up; only a plain draw continues")
    if lm.get("content_sha256") != dm.get("labels_content_sha256"):
        raise SystemExit(f"the labels of run {run_id} changed after its gold draw: no pool to rebuild")
    before = pools(labels.merge(cohort[["sha256"]], on="sha256"), band)
    for group, pool in before.items():
        if len(pool) != dm["groups"][group]["eligible"]:
            raise SystemExit(f"run {run_id}, group {group!r}: the rebuilt pool is not the one its draw saw")
    was = {s: g for g, pool in before.items() for s in pool["sha256"]}
    return Earlier(run_id, frozenset(drawn["sha256"]), was)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--per-group", type=int, default=100)
    ap.add_argument("--band", default="contested", help="the band at T the slice is drawn from")
    ap.add_argument("--continues", metavar="RUN", help="top that run's gold slice up instead of drawing anew")
    ap.add_argument("--overwrite", action="store_true")
    a = ap.parse_args()
    run = load_run()
    labels, lm = read_snapshot(run.dir / "labels.parquet")
    out = fresh(settings.path("gold", run.run_id, "draw.parquet"), a.overwrite)
    out_dir = out.parent

    keep = ["sha256", "instance_number", "label_instance_number", "scoring_moment", "label_moment"]
    df = labels.merge(run.cohort[keep], on="sha256")
    rng = np.random.default_rng(settings.random_seed)
    earlier = _earlier(a.continues, a.band) if a.continues else None
    try:
        gold, report = draw(pools(df, a.band), a.per_group, rng, earlier)
    except ValueError as e:
        raise SystemExit(str(e)) from e
    groups = {g: {"label": str(GROUPS[g][0]), "reasons": list(GROUPS[g][1]), **r} for g, r in report.items()}
    if earlier is None:
        for v in groups.values():   # a plain draw has one share per group
            v["pi_gold"] = v["pi_new"]
    gold["pi_overall"] = gold["pi"] * gold["pi_gold"]
    gold = gold[COLUMNS]
    if gold["sha256"].duplicated().any():   # the groups are disjoint by construction
        raise SystemExit("a file was drawn into both groups")

    write_snapshot(gold, out, stage="03b_gold_draw", run_id=run.run_id, band=a.band, per_group=a.per_group,
                   continues=a.continues, groups=groups,
                   labels_content_sha256=lm.get("content_sha256"), portal=PORTAL,
                   rubric=RUBRIC,
                   blind="review.csv carries no group or label; the adjudicator reads that file only")
    # The adjudicator's sheet: a shuffled order and nothing that says what we think.
    order = rng.permutation(len(gold))
    shas = gold["sha256"].to_numpy()[order]
    review = pd.DataFrame({"sha256": shas, "portal": [PORTAL.format(sha256=s) for s in shas],
                           "verdict": "", "confidence": "", "notes": "", "adjudicator": "",
                           "adjudicated_at": ""})
    review.to_csv(out_dir / "review.csv", index=False)
    (out_dir / "hashes.txt").write_text("\n".join(shas) + "\n")
    carried = set(gold.loc[gold["carried_from"] != "", "sha256"])
    if earlier is not None:
        (out_dir / "new_hashes.txt").write_text("".join(f"{s}\n" for s in shas if s not in carried))

    h = gold["horizon_days"]
    kept = f"; {len(carried)} carried from run {a.continues}, {len(gold) - len(carried)} new"
    lines = [f"gold draw -- run {run.run_id}, band {a.band}: {len(gold)} files, seed {settings.random_seed}"
             + (kept if earlier else ""),
             *(f"  {g:8s} {v['drawn']:4d} of {v['eligible']:5d} eligible ({v['label']}: "
               f"{', '.join(v['reasons'])}), carried {v['carried']}, new {v['new']} at pi {v['pi_new']:.4f}"
               for g, v in groups.items()),
             f"horizon at the label scan (days): p50 {h.median():.0f}  min {h.min():.0f}  max {h.max():.0f}",
             f"rubric: {RUBRIC}",
             f"adjudicator's sheet: {out_dir / 'review.csv'}  (hashes alone: {out_dir / 'hashes.txt'})",
             f"the draw with its groups and probabilities, not for the adjudicator: {out}"]
    print("\n".join(lines))
    log.info("gold draw written", extra={"path": str(out), "rows": len(gold)})


if __name__ == "__main__":
    main()
