#!/usr/bin/env python3
"""Stage 08 — fit the calibrator and the combiner, on the SS1 subset of held-out data

Two artefacts, versioned separately from the base model because they refit on a
different cadence (specs/06-signals.md):

  calibrator_<key>.joblib   Platt: base score -> probability. Two floats, and they ARE the
                            base rate. Not isotonic at pilot volumes.
  combiner.json             expert log-odds weights over signal indicators (decision 0005)
                            until grade-3 labels let it be fitted; `logit += w`, never `x k`.

Fitted on VALIDATE, filtered to provenance == customer (estimand SS1) and reweighted by
1/pi -- this is the line that keeps feeds out of the base rate. When the fold has no SS1
rows (stage, today) it falls back to the pooled fold and says so, loudly.

GRADE GATE. The pilot's labels are grade 1, and labels.assert_calibration_eligible
refuses them. This stage runs only with --provisional, which records
`calibration: provisional` in the manifest: a rehearsal of the mechanism, not a
probability anyone may quote.

SEPARATE FROM STAGE 09 ON PURPOSE: this stage fits; 09 measures under look-once.

Reads : data/runs/<run_id>/splits/validate.parquet + models/*.joblib
Writes: data/runs/<run_id>/models/calibrator_<key>.joblib, combiner.json, calibration.manifest.json

Contract: specs/04-pipeline.md (08 · calibrate), specs/06-signals.md, decision 0005.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

from polyscore_v2.calibration import fit_calibrator, provisional_combiner
from polyscore_v2.labels import assert_calibration_eligible
from polyscore_v2.logging_setup import configure
from polyscore_v2.modelling import CUSTOMER, design, prob_metrics, raw_score
from polyscore_v2.runs import load_run

log = configure()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--provisional", action="store_true",
                    help="fit on grade < 3 labels and mark the result provisional (required until adjudicated labels exist)")
    ap.add_argument("--signal-weights", type=Path, default=None, help="JSON {signal: log-odds weight} for the combiner")
    a = ap.parse_args()
    run = load_run()
    val = pd.read_parquet(run.dir / "splits" / "validate.parquet")
    models_dir = run.dir / "models"

    grades = val["grade"]
    try:
        assert_calibration_eligible(grades)
        provisional = False
    except ValueError as exc:
        if not a.provisional:
            raise SystemExit(f"{exc}\n--provisional fits anyway and marks the result as such")
        provisional = True
        log.warning("calibrating on grade < 3 labels: PROVISIONAL", extra={"grades": grades.value_counts().to_dict()})

    cust = val["provenance"] == CUSTOMER
    if cust.sum() >= 2 and val.loc[cust, "y"].nunique() == 2:
        cal_set, which = val[cust], "SS1 (customer) rows of validate"
    else:
        cal_set, which = val, "POOLED validate -- no usable SS1 rows; the base rate here includes feeds"
        log.warning("no usable SS1 rows in validate; calibrating on the pooled fold", extra={"customer_rows": int(cust.sum())})
    w = (1.0 / cal_set["pi"]).to_numpy()

    manifest = {"stage": "08_calibrate", "run_id": run.run_id, "written_at": dt.datetime.now(dt.UTC).isoformat(),
                "calibration": "provisional" if provisional else "adjudicated", "calibration_set": which,
                "n_calibration": int(len(cal_set)), "calibrators": {}}
    lines = [f"calibrate -- run {run.run_id}: {which}, n={len(cal_set)}, calibration={manifest['calibration']}", ""]
    for path in sorted(models_dir.glob("*.joblib")):
        if path.name.startswith("calibrator_"):
            continue
        bundle = joblib.load(path)
        s = raw_score(bundle["model"], design(cal_set, bundle["columns"], impute=bundle["impute"]))
        try:
            cal = fit_calibrator(s, cal_set["y"].to_numpy(), sample_weight=w, provisional=provisional)
        except ValueError as exc:
            manifest["calibrators"][bundle["key"]] = {"failed": str(exc)}
            lines.append(f"({bundle['key']:8s}) not fitted: {exc}")
            continue
        joblib.dump(cal, models_dir / f"calibrator_{bundle['key']}.joblib")
        pm = prob_metrics(cal_set, cal.predict_proba(s))
        manifest["calibrators"][bundle["key"]] = {"a": cal.a, "b": cal.b, "n_fit": cal.n_fit, **pm}
        lines.append(f"({bundle['key']:8s}) a={cal.a:+.3f} b={cal.b:+.3f}  Brier {pm['brier']:.3f} vs base-rate {pm['brier_base_rate']:.3f}")

    weights = json.loads(a.signal_weights.read_text()) if a.signal_weights else {}
    comb = provisional_combiner(weights)
    (models_dir / "combiner.json").write_text(json.dumps({"weights": comb.weights, "provisional": comb.provisional,
                                                          "note": "logit += w per signal; no signals in the pilot's feature set yet"}, indent=2))
    manifest["combiner"] = {"weights": comb.weights, "provisional": True}
    (models_dir / "calibration.manifest.json").write_text(json.dumps(manifest, indent=2, default=str))
    lines.append(f"combiner: {len(weights)} signal weight(s), provisional")
    print("\n".join(lines))
    log.info("calibration written", extra={"dir": str(models_dir), "calibration": manifest["calibration"]})


if __name__ == "__main__":
    main()
