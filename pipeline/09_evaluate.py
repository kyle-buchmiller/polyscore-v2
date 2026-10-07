#!/usr/bin/env python3
"""Stage 09 — open the test set, once

Load the frozen models AND the fitted calibrators/combiner from stage 08, score the test
split, print the primary metric beside all four baselines, and draw the reliability
diagram with bootstrap bands. FITS NOTHING.

THE LOOK-ONCE RULE. This is the only stage permitted to read splits/test.parquet. Every
access is appended to reports/test_access.log; when the count exceeds two it is printed
next to the metric, because after twenty looks the number carries the optimism of a
best-of-twenty draw.

The headline is ROC-AUC on the SS1 slice, reweighted by 1/pi; pooled AUC is printed and
quoted nowhere. Also: grouped vs random split (model b vs b_random -- the memorisation
gap), the shuffled-label control (must be ~0.5), per-stratum and per-provenance slices,
Brier against the base-rate Brier, and the width of the reliability bands -- which is the
finding that sizes the adjudication budget.

--compare-runs r1 r2 ...: score each run's model (b) on THIS run's test fold and report
the spread -- AUC, per-artifact score MAD, pairwise Spearman. The spec's shared set is
the forced validation tranche; until it exists this fold stands in, and the report says so.

Reads : data/runs/<run_id>/models/* + splits/test[_random].parquet
Writes: data/runs/<run_id>/reports/evaluation.txt (+ .json), reliability.png, test_access.log

Contract: specs/04-pipeline.md (09 · evaluate), specs/05-evaluation.md.
"""

from __future__ import annotations

import argparse
import datetime as dt
import itertools
import json
import math

import joblib
import numpy as np
import pandas as pd

from polyscore_v2.calibration import Combiner
from polyscore_v2.config import settings
from polyscore_v2.logging_setup import configure
from polyscore_v2.metrics import auc, fmt, metrics_table, prob_metrics, reliability
from polyscore_v2.modelling import design, raw_score
from polyscore_v2.runs import load_run

log = configure()


def log_access(run_dir, what: str) -> int:
    p = run_dir / "reports" / "test_access.log"
    p.parent.mkdir(exist_ok=True)
    with p.open("a") as f:
        f.write(f"{dt.datetime.now(dt.UTC).isoformat()} {what}\n")
    return sum(1 for _ in p.open())


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--compare-runs", nargs="*", default=[], help="other run_ids whose model b is scored on this test fold")
    a = ap.parse_args()
    run = load_run()
    n_access = log_access(run.dir, "09_evaluate")
    test = pd.read_parquet(run.dir / "splits" / "test.parquet")
    test_r = pd.read_parquet(run.dir / "splits" / "test_random.parquet")
    models_dir = run.dir / "models"
    comb_json = json.loads((models_dir / "combiner.json").read_text())
    combiner = Combiner(weights=comb_json["weights"], provisional=comb_json["provisional"])
    cal_manifest = json.loads((models_dir / "calibration.manifest.json").read_text())
    rng = np.random.default_rng(settings.random_seed)

    out = {"run_id": run.run_id, "test_n": int(len(test)), "test_accesses": n_access,
           "calibration": cal_manifest.get("calibration"), "baselines": {}, "models": {}}
    L = [f"evaluate -- run {run.run_id}: test n={len(test)}, calibration={out['calibration']}"
         + (f"   ** test set opened {n_access} times **" if n_access > 2 else ""),
         "", "BASELINES on test                    pooled  x1/pi    SS1   x1/pi"]

    def row(name, m):
        return f"{name:34s} {fmt(m['pooled_raw'])} {fmt(m['pooled_reweighted'])}   {fmt(m['s1_raw'])} {fmt(m['s1_reweighted'])}  (n={m['s1_n']})"
    out["baselines"]["3_engine_count"] = metrics_table(test, test["n_malicious"].to_numpy(dtype="float64"))
    L.append(row("3 malicious-engine count at T", out["baselines"]["3_engine_count"]))
    if "incumbent_polyscore" in test.columns and test["incumbent_polyscore"].notna().any():
        out["baselines"]["4_incumbent"] = metrics_table(test, test["incumbent_polyscore"].fillna(0).to_numpy(dtype="float64"))
        L.append(row("4 incumbent PolyScore at T", out["baselines"]["4_incumbent"]))
    L += ["", "MODELS on test (raw score ranks; calibrated probability for Brier)"]

    scores = {}
    for path in sorted(models_dir.glob("*.joblib")):
        if path.name.startswith("calibrator_"):
            continue
        b = joblib.load(path); key = b["key"]
        fold = test_r if key == "b_random" else test
        s = raw_score(b["model"], design(fold, b["columns"], impute=b["impute"]))
        scores[key] = (fold, s)
        m = metrics_table(fold, s)
        entry = {"auc": m}
        cal_path = models_dir / f"calibrator_{key}.joblib"
        if cal_path.exists():
            cal = joblib.load(cal_path)
            prob, _ = combiner.apply(cal.predict_proba(s))
            entry["prob"] = prob_metrics(fold, prob)
            if key == "c" or (key == "b" and not (models_dir / "calibrator_c.joblib").exists()):
                entry["reliability"] = reliability(fold["y"].to_numpy(dtype="float64"), prob, (1.0 / fold["pi"]).to_numpy(),
                                                   run.dir / "reports" / "reliability.png", seed=settings.random_seed)
        out["models"][key] = entry
        L.append(row(f"({key})", m)
                 + (f"   Brier {entry['prob']['brier']:.3f} vs base-rate {entry['prob']['brier_base_rate']:.3f}" if "prob" in entry else ""))
        if m["per_stratum"]:
            L.append("      per stratum: " + ", ".join(f"{k}={fmt(v).strip()}" for k, v in m["per_stratum"].items())
                     + "   per provenance: " + ", ".join(f"{k}={fmt(v).strip()}" for k, v in m["per_provenance"].items()))

    L.append("")
    if "b" in scores and "b_random" in scores:
        g = out["models"]["b"]["auc"]["pooled_reweighted"]; r = out["models"]["b_random"]["auc"]["pooled_reweighted"]
        out["memorisation_gap"] = {"grouped_temporal": g, "random_optimistic": r, "gap": (r - g) if not (math.isnan(g) or math.isnan(r)) else None}
        L.append(f"grouped-temporal vs random split, model b: {fmt(g)} vs {fmt(r)}  -> gap {fmt(out['memorisation_gap']['gap'])}  (the gap is the finding)")
    if "b" in scores:
        fold, s = scores["b"]
        y_shuf = rng.permutation(fold["y"].to_numpy())
        out["shuffled_label_control"] = auc(y_shuf, s)
        L.append(f"shuffled-label control, model b: {fmt(out['shuffled_label_control'])}  (must be ~0.5; above ~0.55 is leakage)")
    if "reliability" in out["models"].get("c", out["models"].get("b", {})):
        rel = out["models"].get("c", out["models"].get("b"))["reliability"]
        L.append(f"reliability band width (mean, 90% bootstrap, {rel['bins']} bins): {fmt(rel['band_width_mean'])}  -> reports/reliability.png")

    if a.compare_runs:
        L += ["", f"STABILITY across runs, model b scored on THIS run's test fold (stand-in for the forced validation set):"]
        per = {}
        for rid in [run.run_id] + list(a.compare_runs):
            p = settings.path("runs", rid, "models", "b.joblib")
            if not p.exists():
                L.append(f"  {rid}: no model b"); continue
            b = joblib.load(p)
            per[rid] = raw_score(b["model"], design(test, b["columns"], impute=b["impute"]))
        aucs = {rid: auc(test["y"].to_numpy(), s) for rid, s in per.items()}
        pairs = list(itertools.combinations(per, 2))
        mad = [float(np.mean(np.abs(per[x] - per[y]))) for x, y in pairs]
        rho = [float(pd.Series(per[x]).corr(pd.Series(per[y]), method="spearman")) for x, y in pairs]
        out["stability"] = {"auc": aucs, "auc_spread": (max(aucs.values()) - min(aucs.values())) if aucs else None,
                            "score_mad_pairwise_mean": float(np.mean(mad)) if mad else None,
                            "spearman_pairwise_mean": float(np.mean(rho)) if rho else None}
        L.append("  AUC per run: " + ", ".join(f"{k}={fmt(v).strip()}" for k, v in aucs.items()))
        L.append(f"  AUC spread {fmt(out['stability']['auc_spread'])}   score MAD {fmt(out['stability']['score_mad_pairwise_mean'])}   Spearman {fmt(out['stability']['spearman_pairwise_mean'])}")

    text = "\n".join(L) + "\n"
    (run.dir / "reports" / "evaluation.txt").write_text(text)
    (run.dir / "reports" / "evaluation.json").write_text(json.dumps(out, indent=2, default=str))
    print(text)
    log.info("evaluation written", extra={"dir": str(run.dir / "reports"), "test_accesses": n_access})


if __name__ == "__main__":
    main()
