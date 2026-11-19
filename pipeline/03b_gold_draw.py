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

Reads : data/runs/<run_id>/{cohort,labels}.parquet
Writes: data/gold/<run_id>/draw.parquet (+ manifest), review.csv, hashes.txt

Contract: specs/04-pipeline.md (03b · gold draw), specs/03-labels.md, decisions/0004.
"""

from __future__ import annotations

import argparse

import numpy as np
import pandas as pd

from polyscore_v2.config import settings
from polyscore_v2.io import read_snapshot, write_snapshot
from polyscore_v2.labels import Label
from polyscore_v2.logging_setup import configure
from polyscore_v2.runs import fresh, load_run

log = configure()
PORTAL = "https://polyswarm.network/scan/results/file/{sha256}"
#: group -> (the cheap label, its reasons) that make a file eligible
GROUPS = {
    "accrued": (Label.MALICIOUS, ("grew", "consensus")),
    "stayed": (Label.BENIGN, ("stayed_contested",)),
}
RUBRIC = ("estimand SS3: malicious if, run as intended in a typical environment, it does things a "
          "fully-informed owner of that machine would not agree to, for someone else's benefit, "
          "as of a stated date; verdicts malicious | benign | unwanted | undecidable")
COLUMNS = ["sha256", "group", "instance_number", "label_instance_number", "scoring_moment", "label_moment",
           "horizon_days", "label", "reason", "provisional", "band_t", "stratum", "m_t", "m", "delta_m",
           "n_definite_t", "n_definite", "n_both", "pi", "pi_gold", "pi_overall", "n_eligible"]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--per-group", type=int, default=100)
    ap.add_argument("--band", default="contested", help="the band at T the slice is drawn from")
    ap.add_argument("--overwrite", action="store_true")
    a = ap.parse_args()
    run = load_run()
    labels, lm = read_snapshot(run.dir / "labels.parquet")
    out = fresh(settings.path("gold", run.run_id, "draw.parquet"), a.overwrite)
    out_dir = out.parent

    keep = ["sha256", "instance_number", "label_instance_number", "scoring_moment", "label_moment"]
    df = labels.merge(run.cohort[keep], on="sha256")
    df = df[df["band_t"] == a.band]
    rng = np.random.default_rng(settings.random_seed)
    parts, groups = [], {}
    for group, (label, reasons) in GROUPS.items():
        pool = df[(df["label"] == str(label)) & df["reason"].isin(reasons)].sort_values("sha256")
        if len(pool) < a.per_group:
            raise SystemExit(f"{len(pool)} eligible files in group {group!r}, {a.per_group} asked")
        take = pool.iloc[np.sort(rng.choice(len(pool), size=a.per_group, replace=False))].copy()
        take["group"], take["n_eligible"], take["pi_gold"] = group, len(pool), a.per_group / len(pool)
        parts.append(take)
        groups[group] = {"label": str(label), "reasons": list(reasons), "eligible": int(len(pool)),
                         "drawn": a.per_group, "pi_gold": a.per_group / len(pool)}
    gold = pd.concat(parts, ignore_index=True)
    gold["pi_overall"] = gold["pi"] * gold["pi_gold"]
    gold = gold[COLUMNS]
    if gold["sha256"].duplicated().any():   # the groups are disjoint by construction
        raise SystemExit("a file was drawn into both groups")

    write_snapshot(gold, out, stage="03b_gold_draw", run_id=run.run_id, band=a.band, per_group=a.per_group,
                   groups=groups, labels_content_sha256=lm.get("content_sha256"), portal=PORTAL,
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

    h = gold["horizon_days"]
    lines = [f"gold draw -- run {run.run_id}, band {a.band}: {len(gold)} files, seed {settings.random_seed}",
             *(f"  {g:8s} {v['drawn']:4d} of {v['eligible']:5d} eligible ({v['label']}: "
               f"{', '.join(v['reasons'])}), pi_gold {v['pi_gold']:.4f}" for g, v in groups.items()),
             f"horizon at the label scan (days): p50 {h.median():.0f}  min {h.min():.0f}  max {h.max():.0f}",
             f"rubric: {RUBRIC}",
             f"adjudicator's sheet: {out_dir / 'review.csv'}  (hashes alone: {out_dir / 'hashes.txt'})",
             f"the draw with its groups and probabilities, not for the adjudicator: {out}"]
    print("\n".join(lines))
    log.info("gold draw written", extra={"path": str(out), "rows": len(gold)})


if __name__ == "__main__":
    main()
