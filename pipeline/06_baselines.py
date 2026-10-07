#!/usr/bin/env python3
"""Stage 06 — the four baselines, before any model

The most informative half hour in the project, and it costs no model at all.

Baseline 3 -- a plain count of engines asserting malicious at T -- is the diagnostic:
  ~0.85-0.95 AUC  healthy, proceed
  >0.97           the label is a restatement of the features; STOP and fix the labels
  ~0.50           something is disconnected

Then the probes on the feature set (estimand SS4, SS9, SS10):
  provenance: injected vs organic   GATE -- blocking above ~0.6 AUC   (no injected arm yet: n/a)
  provenance: feed vs customer      GATE -- blocking above ~0.6 AUC
  rescan: cohort vs control         REPORT -- needs the 01a control sample (not yet pulled: n/a)

Every number is on VALIDATE, raw and x 1/pi, pooled and on the SS1 slice. Does NOT read
the test split.

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

from polyscore_v2.config import PROVENANCE_PROBE_MAX_AUC, settings
from polyscore_v2.logging_setup import configure
from polyscore_v2.metrics import CUSTOMER, fmt, metrics_table
from polyscore_v2.modelling import design
from polyscore_v2.io import read_snapshot
from polyscore_v2.runs import load_run, read_manifest

log = configure()


def out_dir_for(run) -> Path:
    d = run.dir / "reports"; d.mkdir(exist_ok=True); return d


def verdict(b3: float) -> str:
    if math.isnan(b3):
        return "undefined on this validate fold (one class)"
    if b3 > 0.97:
        return "STOP: the label is a restatement of the features -- fix the labels (SS8)"
    if 0.85 <= b3 <= 0.95:
        return "healthy: proceed (SS8)"
    if abs(b3 - 0.5) < 0.1:
        return "disconnected: check the plumbing (SS8)"
    return "outside the SS8 bands: read the composition before proceeding"


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

    lines = [f"baselines -- run {run.run_id}, validate n={len(val)}, train n={len(train)}",
             f"{'':34s} {'pooled':>6s} {'x1/pi':>6s}   {'SS1':>6s} {'x1/pi':>6s}", ""]
    results = {}
    results["1_constant"] = {"pooled_raw": 0.5, "pooled_reweighted": 0.5, "s1_raw": 0.5, "s1_reweighted": 0.5,
                             "s1_n": int((val["provenance"] == CUSTOMER).sum())}
    lines.append(row("1 constant (by definition)", results["1_constant"]))
    p = train["y"].mean() if len(train) else 0.5
    results["2_prevalence_random"] = metrics_table(val, rng.random(len(val)) < p)
    lines.append(row("2 prevalence-random", results["2_prevalence_random"]))
    results["3_engine_count"] = metrics_table(val, val["n_malicious"].to_numpy(dtype="float64"))
    lines.append(row("3 malicious-engine count at T", results["3_engine_count"]))
    results["3b_engine_share"] = metrics_table(val, val["m"].fillna(0).to_numpy(dtype="float64"))
    lines.append(row("3b malicious share m at T", results["3b_engine_share"]))
    if "incumbent_polyscore" in val.columns and val["incumbent_polyscore"].notna().any():
        results["4_incumbent"] = metrics_table(val, val["incumbent_polyscore"].fillna(0).to_numpy(dtype="float64"))
        lines.append(row("4 incumbent PolyScore at T", results["4_incumbent"]))
    else:
        lines.append(f"{'4 incumbent PolyScore at T':34s} not in this base (pull with the current 02_base_pull.sql)")
    b3 = results["3_engine_count"]["s1_reweighted"]
    if math.isnan(b3):
        b3 = results["3_engine_count"]["pooled_reweighted"]
    lines += ["", f"baseline 3 verdict: {verdict(b3)}", ""]

    # --- probes ---
    both = pd.concat([train, val], ignore_index=True)
    X = design(both, groups["features_new"], impute=True)
    probes = {}
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
            per_band = prop.groupby("stratum")["p_rescanned"].mean().round(3).to_dict() if "stratum" in prop else {}
            probes["rescan_cohort_vs_control"] = auc_p
            probes["rescan_propensity_by_stratum"] = per_band
    lines.append("probes on the feature set (provenance probes gate above %.2f AUC; the rescan probe reports):" % PROVENANCE_PROBE_MAX_AUC)
    failed = []
    for name, v in probes.items():
        if isinstance(v, dict):
            lines.append(f"  {name:28s} " + ", ".join(f"{k}={x}" for k, x in v.items()))
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

    out_dir = run.dir / "reports"; out_dir.mkdir(exist_ok=True)
    text = "\n".join(lines) + "\n"
    (out_dir / "baselines.txt").write_text(text)
    (out_dir / "baselines.json").write_text(json.dumps({"baselines": results, "probes": probes}, indent=2, default=str))
    print(text)
    log.info("baselines written", extra={"path": str(out_dir / "baselines.txt"), "probes_failed": failed})
    if failed and not a.no_gate:
        sys.exit(2)


if __name__ == "__main__":
    main()
