#!/usr/bin/env python3
"""Stage 06 — the four baselines, before any model

The most informative half hour in the project, and it costs no model at all.

Baseline 3 -- a plain count of engines asserting malicious at T -- is the diagnostic, and
it is read PER BAND AT T (estimand SS6, SS8; decisions/0016): pooled, the two consensus
bands own the number and a hash lookup had already answered them. The contested band
decides:
  0.5-0.8 AUC   proceed, if the trained model beats it by more than the noise band
  > ~0.9        in any gated band: the label restates the features there; STOP, fix the labels
  < 0.5         inverted; check the plumbing
The pooled table is printed after the bands and quoted nowhere.

Then the probes on the feature set (estimand SS4, SS8, SS9, SS10):
  coverage, per band: the response pattern alone (who answered at T, verdicts ignored)
                                   REPORT -- above ~0.75 the band's coverage features are held out
  provenance: injected vs organic  GATE -- blocking above ~0.6 AUC   (no injected arm in the run yet: n/a)
  provenance: feed vs customer     GATE -- blocking above ~0.6 AUC
  rescan: cohort vs control        REPORT -- needs the 01a control sample (not yet pulled: n/a)

Every baseline is on VALIDATE, raw and x 1/pi, pooled and on the SS1 slice; the coverage
probe is 5-fold CV on train + validate within the band. Does NOT read the test split.

Reads : data/runs/<run_id>/splits/{train,validate}.parquet
Writes: data/runs/<run_id>/reports/baselines.txt (+ .json)

Contract: specs/04-pipeline.md (06 · baselines), estimand SS7 / SS8.
"""

from __future__ import annotations

import argparse
import json
import math
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import StratifiedKFold, cross_val_score

from polyscore_v2.config import (
    BASELINE3_PROCEED,
    BASELINE3_STOP,
    COVERAGE_PROBE_MAX_AUC,
    PROVENANCE_PROBE_MAX_AUC,
    settings,
)
from polyscore_v2.features import coverage_columns
from polyscore_v2.io import read_snapshot
from polyscore_v2.labels import BANDS_AT_T, GATED_BANDS
from polyscore_v2.logging_setup import configure
from polyscore_v2.metrics import CUSTOMER, fmt, metrics_table
from polyscore_v2.modelling import design
from polyscore_v2.runs import load_run, read_manifest

log = configure()


def out_dir_for(run) -> Path:
    d = run.dir / "reports"
    d.mkdir(exist_ok=True)
    return d


def verdict(b3: float, band: str) -> str:
    """Estimand SS8, read in one band."""
    if math.isnan(b3):
        return "undefined (one class on validate)"
    if band not in GATED_BANDS:
        return "reported, not gated"
    lo, hi = BASELINE3_PROCEED
    if b3 > BASELINE3_STOP:
        return "STOP: the label restates the features in this band (SS8)"
    if lo <= b3 <= hi:
        return "proceed if the model beats it by more than the noise band (SS8)"
    if b3 < lo:
        return "inverted: check the plumbing (SS8)"
    return "above the proceed range: read the composition before trusting the gap"


def band_lines(on_both: dict, on_val: dict) -> tuple[list[str], dict]:
    """The per-band table and the SS8 reading of each gated band.

    The baselines are not fitted, so the reading uses train + validate, the largest frame
    this stage may see; the validate column is the frame the models are compared on in 07,
    and a family-grouped fold of a few hundred rows can sit far from the larger number."""
    per_band = on_both["3_engine_count"].get("per_band")
    if not per_band:
        return ["  no band_t column in the splits: re-run 05 on labels written under 0016"], {}
    lines = [f"{'band at T':22s} {'n':>5s} {'pos':>5s} {'3 count':>7s} {'x1/pi':>6s} {'3b m':>6s} "
             f"{'4 inc':>6s} {'| 3 on validate':>16s}   verdict (train + validate, raw)"]
    readings = {}
    for b in [b for b in BANDS_AT_T if b in per_band]:
        c = per_band[b]
        s = on_both["3b_engine_share"]["per_band"][b]["auc"]
        inc = on_both.get("4_incumbent", {}).get("per_band", {}).get(b, {}).get("auc", math.nan)
        v = on_val["3_engine_count"].get("per_band", {}).get(b)
        val_s = f"{fmt(v['auc'])} (n={v['n']}, pos={v['positives']})" if v else "absent"
        readings[b] = verdict(c["auc"], b)
        lines.append(f"{b:22s} {c['n']:5d} {c['positives']:5d} {fmt(c['auc']):>7s} "
                     f"{fmt(c['auc_reweighted'])} {fmt(s)} {fmt(inc)} | {val_s:>14s}   {readings[b]}")
    return lines, readings


def overall(readings: dict, per_band: dict) -> str:
    stops = [b for b in GATED_BANDS if b in per_band and not math.isnan(per_band[b]["auc"])
             and per_band[b]["auc"] > BASELINE3_STOP]
    if stops:
        return f"STOP: baseline 3 above {BASELINE3_STOP} in {', '.join(stops)} -- fix the labels (SS8)"
    if "contested" not in readings:
        return "undefined: no contested band on validate"
    return f"the contested band decides: {readings['contested']}"


def coverage_probe(both: pd.DataFrame, columns: list[str], band: str, seed: int) -> float | str:
    """AUC of the response pattern alone against the label, 5-fold CV inside one band."""
    sel = (both["band_t"] == band).to_numpy()
    y = both.loc[sel, "y"].to_numpy()
    n, p = int(sel.sum()), int(y.sum())
    if n < 30 or p < 10 or n - p < 10:
        return f"n/a: {n} rows, {p} positives"
    X = design(both[sel], columns, impute=True)
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=seed)
    clf = LogisticRegression(C=0.3, max_iter=3000)
    return float(np.mean(cross_val_score(clf, X, y, cv=cv, scoring="roc_auc")))


def row(name: str, m: dict) -> str:
    return (f"{name:34s} {fmt(m['pooled_raw'])} {fmt(m['pooled_reweighted'])}   "
            f"{fmt(m['s1_raw'])} {fmt(m['s1_reweighted'])}  (n={m['s1_n']})")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--no-gate", action="store_true", help="report a failed probe instead of exiting 2")
    a = ap.parse_args()
    run = load_run()
    splits = run.dir / "splits"
    train = pd.read_parquet(splits / "train.parquet")
    val = pd.read_parquet(splits / "validate.parquet")
    groups = read_manifest(splits / "splits")["feature_groups"]
    rng = np.random.default_rng(settings.random_seed)

    results = {}
    results["1_constant"] = {"pooled_raw": 0.5, "pooled_reweighted": 0.5, "s1_raw": 0.5, "s1_reweighted": 0.5,
                             "s1_n": int((val["provenance"] == CUSTOMER).sum())}
    p = train["y"].mean() if len(train) else 0.5
    results["2_prevalence_random"] = metrics_table(val, rng.random(len(val)) < p)
    results["3_engine_count"] = metrics_table(val, val["n_malicious"].to_numpy(dtype="float64"))
    results["3b_engine_share"] = metrics_table(val, val["m"].fillna(0).to_numpy(dtype="float64"))
    has_incumbent = "incumbent_polyscore" in val.columns and val["incumbent_polyscore"].notna().any()
    if has_incumbent:
        results["4_incumbent"] = metrics_table(val, val["incumbent_polyscore"].fillna(0).to_numpy(dtype="float64"))
    both = pd.concat([train, val], ignore_index=True)
    on_both = {"3_engine_count": metrics_table(both, both["n_malicious"].to_numpy(dtype="float64")),
               "3b_engine_share": metrics_table(both, both["m"].fillna(0).to_numpy(dtype="float64"))}
    if has_incumbent:
        on_both["4_incumbent"] = metrics_table(both,
                                               both["incumbent_polyscore"].fillna(0).to_numpy(dtype="float64"))

    lines = [f"baselines -- run {run.run_id}, validate n={len(val)}, train n={len(train)}", "",
             "PER BAND AT T, train + validate (SS6; SS8 reads the contested band; "
             "consensus_malicious is reported, not gated)"]
    band_table, readings = band_lines(on_both, results)
    lines += band_table
    per_band = on_both["3_engine_count"].get("per_band", {})
    gate = {"per_band": readings, "overall": overall(readings, per_band)}
    lines += ["", f"baseline 3 verdict: {gate['overall']}", "",
              "POOLED on validate, after the bands (owned by the consensus bands; quoted nowhere)",
              f"{'':34s} {'pooled':>6s} {'x1/pi':>6s}   {'SS1':>6s} {'x1/pi':>6s}",
              row("1 constant (by definition)", results["1_constant"]),
              row("2 prevalence-random", results["2_prevalence_random"]),
              row("3 malicious-engine count at T", results["3_engine_count"]),
              row("3b malicious share m at T", results["3b_engine_share"])]
    if has_incumbent:
        lines.append(row("4 incumbent PolyScore at T", results["4_incumbent"]))
    else:
        lines.append(f"{'4 incumbent PolyScore at T':34s} not in this base (pull with the current 02_base_pull.sql)")
    lines.append("")

    # --- probes ---
    X = design(both, groups["features_new"], impute=True)
    probes = {}
    held_out = []
    if "band_t" in both.columns:
        cov = coverage_columns(groups["features_new"])
        for b in GATED_BANDS:
            v = coverage_probe(both, cov, b, settings.random_seed)
            probes[f"coverage_{b}"] = v
            if isinstance(v, float) and v > COVERAGE_PROBE_MAX_AUC:
                held_out.append(b)
    probes["injected_vs_organic"] = "n/a: no injected known-good arm in this base"
    prov = (both["provenance"] == CUSTOMER).astype(int)
    if prov.nunique() < 2 or prov.sum() < 5 or (len(prov) - prov.sum()) < 5:
        probes["feed_vs_customer"] = f"n/a: provenance has {prov.sum()} customer / {len(prov) - prov.sum()} feed rows"
    else:
        folds = min(5, int(prov.sum()), int(len(prov) - prov.sum()))
        cv = StratifiedKFold(n_splits=folds, shuffle=True, random_state=settings.random_seed)
        scores = cross_val_score(LogisticRegression(C=1.0, max_iter=2000), X, prov, cv=cv, scoring="roc_auc")
        probes["feed_vs_customer"] = float(np.mean(scores))
    control_path = run.dir / "control_features.parquet"
    if not control_path.exists():
        probes["rescan_cohort_vs_control"] = "n/a: no control sample beside this base (01a writes <window>.control.parquet)"
    else:
        # Was-rescanned, from the T features: the cohort (every labellable row, not just the
        # modelling folds) against 01a's control sample. A REPORT, not a gate: high AUC is
        # covariate shift, which conditioning handles; the propensity is an optional weight.
        features, fm = read_snapshot(run.dir / "features.parquet")
        control, _ = read_snapshot(control_path)
        cols = fm["groups"]["features_new"]
        Xc = design(features, cols, impute=True)
        Xk = control.reindex(columns=cols, fill_value=0).pipe(design, cols, impute=True)
        Xp = pd.concat([Xc, Xk], ignore_index=True)
        yp = np.r_[np.ones(len(Xc)), np.zeros(len(Xk))]
        if len(Xc) < 5 or len(Xk) < 5:
            probes["rescan_cohort_vs_control"] = f"n/a: {len(Xc)} cohort vs {len(Xk)} control rows"
        else:
            folds = min(5, len(Xc), len(Xk))
            cv = StratifiedKFold(n_splits=folds, shuffle=True, random_state=settings.random_seed)
            clf = LogisticRegression(C=1.0, max_iter=2000)
            auc_p = float(np.mean(cross_val_score(clf, Xp, yp, cv=cv, scoring="roc_auc")))
            clf.fit(Xp, yp)
            prop = pd.DataFrame({"sha256": features["sha256"], "stratum": features.get("stratum"),
                                 "p_rescanned": clf.predict_proba(Xc)[:, 1]})
            prop.to_parquet(out_dir_for(run) / "rescan_propensity.parquet", index=False)
            per_stratum = (prop.groupby("stratum")["p_rescanned"].mean().round(3).to_dict()
                           if "stratum" in prop else {})
            probes["rescan_cohort_vs_control"] = auc_p
            probes["rescan_propensity_by_stratum"] = per_stratum
    lines.append(f"probes on the feature set (coverage probe reports per band, held out above "
                 f"{COVERAGE_PROBE_MAX_AUC:.2f}; provenance probes gate above "
                 f"{PROVENANCE_PROBE_MAX_AUC:.2f}; the rescan probe reports):")
    failed = []
    for name, v in probes.items():
        if isinstance(v, dict):
            lines.append(f"  {name:28s} " + ", ".join(f"{k}={x}" for k, x in v.items()))
        elif isinstance(v, float) and name.startswith("coverage_"):
            state = ("HELD OUT: who answered predicts the label here; the band's coverage features "
                     "are not trained on and its number is not quoted (SS8)"
                     if v > COVERAGE_PROBE_MAX_AUC else "ok")
            lines.append(f"  {name:28s} {v:.3f}  {state}")
        elif isinstance(v, float) and name.startswith("rescan"):
            lines.append(f"  {name:28s} {v:.3f}  report only -- near 0.5: the labellable subset looks random in feature space; "
                         f"high: covariate shift, see rescan_propensity.parquet")
        elif isinstance(v, float):
            state = "GATE FAILED" if v > PROVENANCE_PROBE_MAX_AUC else "ok"
            lines.append(f"  {name:28s} {v:.3f}  {state}")
            if state == "GATE FAILED":
                failed.append(name)
        else:
            lines.append(f"  {name:28s} {v}")
    probes["coverage_held_out_bands"] = held_out
    gate["coverage_held_out_bands"] = held_out

    out_dir = out_dir_for(run)
    text = "\n".join(lines) + "\n"
    (out_dir / "baselines.txt").write_text(text)
    (out_dir / "baselines.json").write_text(json.dumps(
        {"baselines": results, "baselines_train_validate": on_both, "gate": gate, "probes": probes},
        indent=2, default=str))
    print(text)
    log.info("baselines written", extra={"path": str(out_dir / "baselines.txt"), "probes_failed": failed,
                                         "coverage_held_out": held_out})
    if failed and not a.no_gate:
        sys.exit(2)


if __name__ == "__main__":
    main()
