#!/usr/bin/env python3
"""Stage 05 — temporal and family-grouped split

Trainable rows only (labels.trainable: malicious / benign); the rate-only rows are
counted and left out. Sort by scoring moment, cut at the estimand SS5 fractions, enforce
the horizon gap between the end of train and the start of test, and let no family group
straddle a boundary -- groups are ordered by their earliest row and cut whole.

The group is PROVISIONAL (decisions/0011): the modal family string from the T scan,
standing in for a TLSH cluster; rows with no family are their own group.

Also writes the naive random split, named optimistic. The gap between the two is the
pilot's single most valuable number. Nothing is rebalanced here: the SS9 draw already
supplied balance, and 1/pi travels with every row so validate and test keep natural
prevalence.

Reads : data/runs/<run_id>/features.parquet + labels.parquet
Writes: data/runs/<run_id>/splits/{train,validate,test}.parquet (+ *_random.parquet) + splits.manifest.json

Contract: specs/04-pipeline.md (05 · split), estimand SS5.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json

import pandas as pd

from polyscore_v2.config import settings
from polyscore_v2.io import read_snapshot
from polyscore_v2.labels import Label
from polyscore_v2.logging_setup import configure
from polyscore_v2.runs import load_run, read_manifest
from polyscore_v2.splits import (FOLDS, grouping_key, horizon_gap, prevalence, random_split,
                                 straddling_groups, temporal_grouped)

log = configure()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--overwrite", action="store_true")
    a = ap.parse_args()
    run = load_run()
    out_dir = run.dir / "splits"
    if out_dir.exists() and not a.overwrite:
        raise SystemExit(f"{out_dir} exists; pass --overwrite to replace it")
    out_dir.mkdir(parents=True, exist_ok=True)

    features, fm = read_snapshot(run.dir / "features.parquet")
    labels, _ = read_snapshot(run.dir / "labels.parquet")
    df = features.merge(labels[["sha256", "label", "grade", "reason", "trainable", "horizon_days"]], on="sha256")
    if len(df) != len(features):
        raise SystemExit(f"{len(df)} rows after joining labels to {len(features)} feature rows")
    excluded = df[~df["trainable"]]
    df = df[df["trainable"]].copy()
    df["y"] = (df["label"] == str(Label.MALICIOUS)).astype("int8")
    df["scoring_moment"] = pd.to_datetime(df["scoring_moment"])
    df["group"] = grouping_key(df)

    df["fold"] = temporal_grouped(df, train_frac=settings.train_frac, validate_frac=settings.validate_frac)
    in_gap, train_end, gap_start = horizon_gap(df, df["fold"], horizon_days=settings.horizon_days)
    dropped = df[in_gap]
    df = df[~in_gap]
    straddle = straddling_groups(df, df["fold"])
    if straddle:
        raise SystemExit(f"{straddle} family groups straddle a fold boundary")
    df["fold_random"] = random_split(df, seed=settings.random_seed, train_frac=settings.train_frac,
                                     validate_frac=settings.validate_frac)

    manifest = {"stage": "05_split", "run_id": run.run_id, "written_at": dt.datetime.now(dt.UTC).isoformat(),
                "fractions": {"train": settings.train_frac, "validate": settings.validate_frac,
                              "test": round(1 - settings.train_frac - settings.validate_frac, 4)},
                "horizon_gap_days": settings.horizon_days, "train_end": str(train_end), "test_not_before": str(gap_start),
                "dropped_in_gap": int(len(dropped)), "excluded_rate_only": int(len(excluded)),
                "excluded_by_label": excluded["label"].value_counts().to_dict(),
                "group": "tlsh_cluster, else imphash, else modal_family (provisional, decisions/0011), else sha256",
                "groups": {f: int(df.loc[df["fold"] == f, "group"].nunique()) for f in FOLDS},
                "folds": {f: prevalence(df[df["fold"] == f]) for f in FOLDS},
                "folds_random": {f: prevalence(df[df["fold_random"] == f]) for f in FOLDS},
                "feature_groups": fm.get("groups"), "random_seed": settings.random_seed}
    total = sum(manifest["folds"][f]["n"] for f in FOLDS) + len(dropped) + len(excluded)
    if total != len(features):   # row-count assertion: every row is in a fold, the gap, or excluded
        raise SystemExit(f"{total} rows accounted for out of {len(features)}")
    for f in FOLDS:
        df[df["fold"] == f].drop(columns=["fold", "fold_random"]).to_parquet(out_dir / f"{f}.parquet", index=False)
        df[df["fold_random"] == f].drop(columns=["fold", "fold_random"]).to_parquet(out_dir / f"{f}_random.parquet", index=False)
    (out_dir / "splits.manifest.json").write_text(json.dumps(manifest, indent=2, default=str))
    print(json.dumps({k: manifest[k] for k in ("folds", "folds_random", "groups", "dropped_in_gap", "excluded_by_label",
                                                 "train_end", "test_not_before")}, indent=2, default=str))
    log.info("splits written", extra={"dir": str(out_dir), **{f: manifest["folds"][f]["n"] for f in FOLDS}})


if __name__ == "__main__":
    main()
