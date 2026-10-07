#!/usr/bin/env python3
"""Stage 07 — the three comparisons

Exactly three, tuned on validate only, against log loss -- never a threshold metric:

  (a) logistic regression, OLD one-column encoding
  (b) logistic regression, NEW two-column encoding
  (c) gradient-boosted trees (LightGBM), new encoding

plus (b_random): (b) refitted on the random split, so stage 09 can price memorisation.

Prediction on record: (b) lands close to (c), and the gap between (a) and (b) -- an
ENCODING change, not a model change -- dwarfs both.

No class_weight. No synthetic oversampling. The SS9 draw supplied balance reversibly;
what it costs is paid back explicitly: the manifest records logit(pi_p) with pi_p the
validate fold's reweighted prevalence -- PROVISIONAL, since the true pi_p comes from an
adjudicated sample (R3) -- and stage 08 refits intercepts on held-out data regardless.

Reads : data/runs/<run_id>/splits/{train,validate}[_random].parquet
Writes: data/runs/<run_id>/models/{a,b,c,b_random}.joblib + models.manifest.json

Contract: specs/04-pipeline.md (07 · train).
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
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import log_loss

from polyscore_v2.config import settings
from polyscore_v2.logging_setup import configure
from polyscore_v2.metrics import metrics_table
from polyscore_v2.modelling import design, raw_score
from polyscore_v2.runs import load_run, read_manifest

log = configure()


def val_loss(model, X, y, w):
    p = np.clip(model.predict_proba(X)[:, 1], 1e-6, 1 - 1e-6)
    return float(log_loss(y, p, sample_weight=w)) if len(np.unique(y)) > 1 else math.nan


def fit_lr(train, val, columns):
    Xt, Xv = design(train, columns, impute=True), design(val, columns, impute=True)
    yt, yv, wv = train["y"].to_numpy(), val["y"].to_numpy(), (1.0 / val["pi"]).to_numpy()
    best = None
    for C in (0.01, 0.1, 1.0, 10.0):
        m = LogisticRegression(C=C, max_iter=5000).fit(Xt, yt)      # no class_weight, by design
        loss = val_loss(m, Xv, yv, wv)
        if best is None or (not math.isnan(loss) and loss < best[1]):
            best = (m, loss, {"C": C})
    return best


def fit_lgbm(train, val, columns):
    import lightgbm as lgb
    Xt, Xv = design(train, columns, impute=False), design(val, columns, impute=False)
    yt, yv, wv = train["y"].to_numpy(), val["y"].to_numpy(), (1.0 / val["pi"]).to_numpy()
    mcs = max(1, min(20, len(train) // 10))
    best = None
    for leaves, n_est in itertools.product((7, 15), (100, 300)):
        params = {"num_leaves": leaves, "n_estimators": n_est, "learning_rate": 0.05,
                  "min_child_samples": mcs, "random_state": settings.random_seed, "verbose": -1}
        m = lgb.LGBMClassifier(**params).fit(Xt, yt)
        loss = val_loss(m, Xv, yv, wv)
        if best is None or (not math.isnan(loss) and loss < best[1]):
            best = (m, loss, params)
    return best


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--overwrite", action="store_true")
    a = ap.parse_args()
    run = load_run()
    splits = run.dir / "splits"
    out_dir = run.dir / "models"
    if out_dir.exists() and not a.overwrite:
        raise SystemExit(f"{out_dir} exists; pass --overwrite to replace it")
    out_dir.mkdir(exist_ok=True)
    groups = read_manifest(splits / "splits")["feature_groups"]
    train, val = pd.read_parquet(splits / "train.parquet"), pd.read_parquet(splits / "validate.parquet")
    train_r, val_r = pd.read_parquet(splits / "train_random.parquet"), pd.read_parquet(splits / "validate_random.parquet")

    specs = {
        "a": ("logistic regression, old one-column encoding", fit_lr, groups["features_old"], True, train, val),
        "b": ("logistic regression, new two-column encoding", fit_lr, groups["features_new"], True, train, val),
        "c": ("LightGBM, new two-column encoding", fit_lgbm, groups["features_new"], False, train, val),
        "b_random": ("(b) on the random split -- optimistic", fit_lr, groups["features_new"], True, train_r, val_r),
    }
    manifest = {"stage": "07_train", "run_id": run.run_id, "written_at": dt.datetime.now(dt.UTC).isoformat(),
                "random_seed": settings.random_seed, "class_weight": None, "oversampling": None, "models": {}}
    w_val = (1.0 / val["pi"]).to_numpy()
    pi_p = float(np.sum(w_val * val["y"].to_numpy()) / np.sum(w_val)) if len(val) else math.nan
    manifest["intercept_shift_provisional"] = {
        "pi_p_reweighted_validate": pi_p,
        "logit": float(np.log(pi_p / (1 - pi_p))) if 0 < pi_p < 1 else None,
        "note": "pi_p must come from an adjudicated sample (R3); this is the validate fold's reweighted prevalence",
    }
    lines = [f"train -- run {run.run_id}: train n={len(train)}, validate n={len(val)}", ""]
    for key, (desc, fitter, columns, impute, tr, va) in specs.items():
        entry = {"description": desc, "n_features": len(columns), "n_train": int(len(tr)), "n_validate": int(len(va))}
        if tr["y"].nunique() < 2:
            entry["skipped"] = "training fold has one class"
        else:
            try:
                model, loss, params = fitter(tr, va, columns)
                joblib.dump({"model": model, "columns": columns, "impute": impute, "key": key, "params": params},
                            out_dir / f"{key}.joblib")
                entry.update({"params": params, "validate_log_loss": loss,
                              "validate_auc": metrics_table(va, raw_score(model, design(va, columns, impute=impute)))})
            except Exception as exc:  # noqa: BLE001 -- a draft on tiny folds; the manifest says what failed
                entry["failed"] = f"{type(exc).__name__}: {exc}"
        manifest["models"][key] = entry
        auc = entry.get("validate_auc", {})
        lines.append(f"({key:8s}) {desc:48s} " + (
            f"val log loss {entry['validate_log_loss']:.3f}  AUC pooled {auc.get('pooled_reweighted', math.nan):.3f}"
            if "validate_log_loss" in entry else entry.get("skipped") or entry.get("failed", "")))
    lines += ["", f"provisional intercept shift logit(pi_p) = {manifest['intercept_shift_provisional']['logit']}"]
    (out_dir / "models.manifest.json").write_text(json.dumps(manifest, indent=2, default=str))
    print("\n".join(lines))
    log.info("models written", extra={"dir": str(out_dir), "models": list(manifest["models"])})


if __name__ == "__main__":
    main()
