#!/usr/bin/env python3
"""Stage 07b — the seed-reshuffle noise band

SS8 proceeds only when the model beats baseline 3 by more than the noise band, and SS11
makes the band a measured number: the runbook run N times with different seeds, every
model scored on one shared validation set, the spread reported. On a base that IS its
cohort -- the forced rescans, every row drawn with pi = 1 -- a new seed draws the same
cohort and the temporal split is deterministic, so the designed form would measure only
LightGBM's own randomness. This is the same measurement in the form the base allows:
`stability_runs` repeats of a family-grouped, label-stratified K-fold over every trainable
row outside the test fold, (b) and (c) refit per fold with 07's tuned parameters, and
every number read PER BAND AT T on the out-of-fold scores.

Per band and per scorer -- the count at T, (b), (c) -- the per-repeat AUC's mean, sd, min
and max; the fold-level swing, which is what a single validate fold inherits; the gap over
the count; and, as SS11 asks, the per-artifact agreement of the scores across repeats
(pairwise Spearman and mean absolute difference). The count is not fitted, so it has one
number per band and a swing. A model CLEARS the band when its mean gap over the count is
wider than its own min..max across repeats and its worst repeat still beats the count.

Reads : data/runs/<run_id>/{features,labels}.parquet, splits/test.parquet (its rows are left
        out), models/models.manifest.json (07's parameters)
Writes: data/runs/<run_id>/reports/noise_band.txt (+ .json)

Contract: specs/04-pipeline.md (07b · noise band), specs/05-evaluation.md (Process stability).
"""

from __future__ import annotations

import argparse
import datetime as dt
import itertools
import json
import math

import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

from polyscore_v2.config import settings
from polyscore_v2.io import read_snapshot
from polyscore_v2.labels import BANDS_AT_T, GATED_BANDS, Label
from polyscore_v2.logging_setup import configure
from polyscore_v2.metrics import auc, fmt
from polyscore_v2.modelling import design, raw_score
from polyscore_v2.runs import load_run, read_manifest
from polyscore_v2.splits import grouping_key

log = configure()
MODELS = ("b", "c")
SCORERS = ("count", *MODELS)


def fit_b(train: pd.DataFrame, columns: list[str], C: float):
    m = make_pipeline(StandardScaler(), LogisticRegression(C=C, max_iter=5000))
    return m.fit(design(train, columns, impute=True), train["y"].to_numpy())


def fit_c(train: pd.DataFrame, columns: list[str], params: dict, seed: int):
    import lightgbm as lgb
    p = {**params, "random_state": seed}
    return lgb.LGBMClassifier(**p).fit(design(train, columns, impute=False), train["y"].to_numpy())


def oof_scores(df: pd.DataFrame, columns: list[str], params_b: dict, params_c: dict, *,
               n_splits: int, seed: int) -> tuple[dict[str, np.ndarray], np.ndarray]:
    """Out-of-fold raw scores for (b) and (c), and each row's fold."""
    cv = StratifiedGroupKFold(n_splits=n_splits, shuffle=True, random_state=seed)
    y, groups = df["y"].to_numpy(), df["group"].to_numpy()
    out = {m: np.full(len(df), np.nan) for m in MODELS}
    fold = np.full(len(df), -1)
    for k, (tr, te) in enumerate(cv.split(df, y, groups)):
        a, b = df.iloc[tr], df.iloc[te]
        out["b"][te] = raw_score(fit_b(a, columns, params_b["C"]), design(b, columns, impute=True))
        out["c"][te] = raw_score(fit_c(a, columns, params_c, seed), design(b, columns, impute=False))
        fold[te] = k
    return out, fold


def stats(values) -> dict:
    v = np.asarray([x for x in values if not (isinstance(x, float) and math.isnan(x))], dtype="float64")
    if len(v) == 0:
        return {"n": 0, "mean": math.nan, "sd": math.nan, "min": math.nan, "max": math.nan}
    return {"n": int(len(v)), "mean": float(v.mean()), "sd": float(v.std(ddof=1)) if len(v) > 1 else 0.0,
            "min": float(v.min()), "max": float(v.max())}


def clears(model: dict, count: dict) -> bool:
    """The model's mean gap over the count is wider than its own spread, and its worst
    repeat still beats the count. False whenever a number is missing."""
    if any(math.isnan(x) for x in (model["mean"], model["min"], model["max"], count["mean"])):
        return False
    return (model["mean"] - count["mean"]) > (model["max"] - model["min"]) and model["min"] > count["mean"]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--repeats", type=int, default=settings.stability_runs,
                    help="how many seeds; the SS11 stability_runs")
    ap.add_argument("--folds", type=int, default=5)
    a = ap.parse_args()
    run = load_run()
    features, fm = read_snapshot(run.dir / "features.parquet")
    labels, _ = read_snapshot(run.dir / "labels.parquet")
    columns = fm["groups"]["features_new"]
    fitted = read_manifest(run.dir / "models" / "models")["models"]
    params_b, params_c = fitted["b"]["params"], fitted["c"]["params"]

    df = features.merge(labels[["sha256", "label", "trainable", "band_t"]], on="sha256")
    if len(df) != len(features):
        raise SystemExit(f"{len(df)} rows after joining labels to {len(features)} feature rows")
    # 06's coverage probe decides which band's number may be quoted; this stage never overrides it.
    baselines = run.dir / "reports" / "baselines.json"
    held_out = set(json.loads(baselines.read_text()).get("gate", {}).get("coverage_held_out_bands", [])
                   if baselines.exists() else [])
    df = df[df["trainable"]].copy()
    test_path = run.dir / "splits" / "test.parquet"
    n_test = 0
    if test_path.exists():
        in_test = df["sha256"].isin(set(pd.read_parquet(test_path, columns=["sha256"])["sha256"]))
        n_test = int(in_test.sum())
        df = df[~in_test]
    df["y"] = (df["label"] == str(Label.MALICIOUS)).astype("int8")
    df["group"] = grouping_key(df)
    df = df.reset_index(drop=True)
    y = df["y"].to_numpy()
    count = df["n_malicious"].fillna(0).to_numpy(dtype="float64")
    bands = [b for b in BANDS_AT_T if (df["band_t"] == b).any()]

    per_repeat = {b: {s: [] for s in SCORERS} for b in bands}
    per_fold = {b: {s: [] for s in SCORERS} for b in bands}
    oof = {m: [] for m in MODELS}
    for r in range(a.repeats):
        seed = settings.random_seed + r
        scores, fold = oof_scores(df, columns, params_b, params_c, n_splits=a.folds, seed=seed)
        scores["count"] = count
        for m in MODELS:
            oof[m].append(scores[m])
        for band in bands:
            mask = (df["band_t"] == band).to_numpy()
            for s in SCORERS:
                per_repeat[band][s].append(auc(y[mask], scores[s][mask]))
                for k in range(a.folds):
                    mk = mask & (fold == k)
                    per_fold[band][s].append(auc(y[mk], scores[s][mk]))
        log.info("repeat done", extra={"repeat": r, "seed": seed})

    out = {"stage": "07b_noise_band", "run_id": run.run_id, "written_at": dt.datetime.now(dt.UTC).isoformat(),
           "repeats": a.repeats, "folds": a.folds, "rows": int(len(df)), "test_rows_left_out": n_test,
           "groups": int(df["group"].nunique()), "params": {"b": params_b, "c": params_c},
           "per_band": {}, "clears": {}, "agreement": {}}
    lines = [f"noise band -- run {run.run_id}: {a.repeats} repeats x {a.folds} folds, family-grouped and "
             f"label-stratified, over {len(df)} trainable rows in {out['groups']} groups outside the test "
             f"fold ({n_test} test rows left out); (b) C={params_b['C']}, (c) {params_c.get('num_leaves')} "
             f"leaves x {params_c.get('n_estimators')} trees, refit per fold",
             "read per band at T on the out-of-fold scores. A model clears the band when its mean gap over "
             "the count is wider than its own min..max across repeats and its worst repeat still beats "
             "the count.", "",
             f"{'band at T':22s} {'scorer':7s} {'mean':>6s} {'sd':>6s} {'min':>6s} {'max':>6s}   "
             f"{'fold swing':>13s}   {'gap mean':>8s} {'gap min':>8s}   clears"]
    for band in bands:
        out["per_band"][band] = {}
        c_stats = stats(per_repeat[band]["count"])
        for s in SCORERS:
            st = stats(per_repeat[band][s])
            sw = stats(per_fold[band][s])
            entry = {"per_repeat": st, "per_fold": sw}
            verdict = ""
            if s != "count":
                gaps = [m - c for m, c in zip(per_repeat[band][s], per_repeat[band]["count"], strict=True)]
                entry["gap"] = stats(gaps)
                ok = clears(st, c_stats)
                out["clears"].setdefault(band, {})[s] = ok
                if band not in GATED_BANDS:
                    verdict = "reported, not gated"
                elif band in held_out:
                    verdict = ("clears, " if ok else "does not clear, ") + "HELD OUT by 06's coverage probe"
                else:
                    verdict = "clears" if ok else "does not clear"
            out["per_band"][band][s] = entry
            gap_s = " " * 17
            if s != "count":
                gap_s = f"{entry['gap']['mean']:+8.3f} {entry['gap']['min']:+8.3f}"
            lines.append(f"{band:22s} {('(' + s + ')') if s != 'count' else 'count':7s} {fmt(st['mean'])} "
                         f"{fmt(st['sd'])} {fmt(st['min'])} {fmt(st['max'])}   "
                         f"{fmt(sw['min']).strip():>6s}..{fmt(sw['max']).strip():<6s}   {gap_s}   {verdict}")
        lines.append("")
    for m in MODELS:
        pairs = list(itertools.combinations(range(a.repeats), 2))
        rho = [float(pd.Series(oof[m][i]).corr(pd.Series(oof[m][j]), method="spearman")) for i, j in pairs]
        mad = [float(np.mean(np.abs(oof[m][i] - oof[m][j]))) for i, j in pairs]
        out["agreement"][m] = {"spearman_mean": float(np.mean(rho)) if rho else math.nan,
                               "spearman_min": float(np.min(rho)) if rho else math.nan,
                               "score_mad_mean": float(np.mean(mad)) if mad else math.nan}
        ag = out["agreement"][m]
        lines.append(f"per-artifact agreement across repeats, ({m}): Spearman mean "
                     f"{fmt(ag['spearman_mean'])} min {fmt(ag['spearman_min'])}, "
                     f"score MAD {fmt(ag['score_mad_mean'])}")
    gated = {b: out["clears"].get(b, {}) for b in GATED_BANDS if b in out["clears"]}
    out["held_out_bands"] = sorted(held_out)
    lines += ["", "SS8 reading: " + "; ".join(
        f"{b}: " + ", ".join(f"({m}) {'clears' if ok else 'does not clear'}" for m, ok in v.items())
        + (" -- held out, not quoted" if b in held_out else "")
        for b, v in gated.items())]

    out_dir = run.dir / "reports"
    out_dir.mkdir(exist_ok=True)
    text = "\n".join(lines) + "\n"
    (out_dir / "noise_band.txt").write_text(text)
    (out_dir / "noise_band.json").write_text(json.dumps(out, indent=2, default=str))
    print(text)
    log.info("noise band written", extra={"path": str(out_dir / "noise_band.txt"), "clears": out["clears"]})


if __name__ == "__main__":
    main()
