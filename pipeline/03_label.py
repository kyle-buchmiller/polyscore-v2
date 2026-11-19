#!/usr/bin/env python3
"""Stage 03 — attach the answer column

One of the four pilot labels per artifact, with its grade, reason, source and realized
horizon, from the movement between the T scan and the label scan via
labels.label_by_movement (decisions/0016, estimand SS3): growth toward malicious is the
positive class, no growth the negative class -- firm when the file stayed clean or fell,
PROVISIONAL (`stayed_contested`) when it stayed contested. The band at T each file sits in
is written beside the label, because the metric and the gate are read per band (SS6, SS8).

UNDECIDABLE and UNWANTED rows stay in the file, flagged `trainable = False`, so they are
excluded from training and still counted. Their rates are reported three ways -- raw over
the cohort, reweighted by 1/pi, and per stratum -- because the contested band is
over-weighted by design (specs/03-labels.md).

No waiting: the training arm's label scan already happened (decision 0010).

Reads : data/runs/<run_id>/cohort.parquet + the base it names (+ .assertions.parquet)
Writes: data/runs/<run_id>/labels.parquet (+ manifest), labels.report.txt

Contract: specs/04-pipeline.md (03 · label), specs/03-labels.md.
"""

from __future__ import annotations

import argparse

import pandas as pd

from polyscore_v2.config import (
    LABEL_CLEAN_MAX,
    LABEL_CLEAN_MIN_DEFINITE,
    LABEL_GROWTH,
    LABEL_MIN_BOTH,
    LABEL_MIN_DEFINITE,
)
from polyscore_v2.io import write_snapshot
from polyscore_v2.labels import (
    BANDS_AT_T,
    NEGATIVE,
    POSITIVE,
    PROVISIONAL_REASONS,
    RATE_REPORTED,
    Grade,
    Label,
    assert_pilot_labels,
    label_by_movement,
)
from polyscore_v2.logging_setup import configure
from polyscore_v2.runs import fresh, load_run

log = configure()
RULE = "decisions/0016 movement"


def rates(labels: pd.DataFrame) -> str:
    w = 1.0 / labels["pi"]
    lines = [f"{'label':12s} {'raw':>7s} {'x 1/pi':>7s}   per stratum"]
    for lab in [str(x) for x in Label]:
        hit = labels["label"] == lab
        per = labels[hit].groupby("stratum").size()
        per_s = ", ".join(f"{s}={n}" for s, n in per.items()) or "-"
        lines.append(f"{lab:12s} {hit.mean():7.3f} {(w * hit).sum() / w.sum():7.3f}   {per_s}")
    return "\n".join(lines)


def per_band(labels: pd.DataFrame) -> str:
    """Labels by the band at T: where the positives and the provisional negatives sit."""
    lines = [f"{'band at T':20s} {'n':>6s} {'malicious':>10s} {'benign':>7s} {'(provisional)':>14s} "
             f"{'unwanted':>9s} {'undecidable':>12s}"]
    bands = [b for b in BANDS_AT_T if (labels["band_t"] == b).any()]
    if labels["band_t"].isna().any():
        bands.append(None)
    for b in bands:
        rows = labels[labels["band_t"].isna()] if b is None else labels[labels["band_t"] == b]
        n = len(rows)
        lab = rows["label"]
        prov = int(((lab == str(Label.BENIGN)) & rows["reason"].isin(PROVISIONAL_REASONS)).sum())
        n_mal, n_ben, n_unw, n_und = (int((lab == str(x)).sum())
                                      for x in (Label.MALICIOUS, Label.BENIGN, Label.UNWANTED, Label.UNDECIDABLE))
        lines.append(f"{(b or 'no definite verdict at T'):20s} {n:6d} {n_mal:10d} {n_ben:7d} {prov:14d} "
                     f"{n_unw:9d} {n_und:12d}")
    return "\n".join(lines)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--overwrite", action="store_true")
    a = ap.parse_args()
    run = load_run()
    out = fresh(run.dir / "labels.parquet", a.overwrite)

    hist = run.assertions[run.assertions["sha256"].isin(run.cohort["sha256"])]
    by_sha = {sha: h for sha, h in hist.groupby("sha256")}
    rows = []
    for sha in run.cohort["sha256"]:
        h = by_sha.get(sha)
        if h is None or not (h["scan_role"] == "label").any():
            rows.append({"sha256": sha, "label": str(Label.UNDECIDABLE), "grade": int(Grade.TIME_SEPARATED),
                         "reason": "no_label_scan_assertions"})
            continue
        r = label_by_movement(h)
        rows.append({"sha256": sha, "label": str(r.label), "grade": int(r.grade), "reason": r.reason, **r.evidence})
    labels = pd.DataFrame(rows).merge(
        run.cohort[["sha256", "label_gap", "stratum", "pi", "provenance"]], on="sha256", how="left")
    labels["source"] = "label_scan"
    labels["horizon_days"] = pd.to_timedelta(labels["label_gap"]).dt.total_seconds() / 86400.0
    labels["trainable"] = labels["label"].isin([str(x) for x in POSITIVE | NEGATIVE])
    labels["provisional"] = labels["reason"].isin(PROVISIONAL_REASONS)
    assert_pilot_labels(labels["label"])
    if len(labels) != len(run.cohort):   # row-count assertion at the boundary
        raise SystemExit(f"{len(labels)} labels for {len(run.cohort)} cohort rows")

    w = 1.0 / labels["pi"]
    pos = labels["label"] == str(Label.MALICIOUS)
    train = labels[labels["trainable"]]
    d = labels["delta_m"]
    report = "\n".join([
        f"labels -- run {run.run_id}, {len(labels)} artifacts, rule {RULE} (estimand SS3)",
        f"floor {LABEL_MIN_DEFINITE} definite at the label scan and {LABEL_MIN_BOTH} definite at both scans; "
        f"growth is a move of {LABEL_GROWTH:+.2f} in m over the engines definite at both; "
        f"stayed clean is m <= {LABEL_CLEAN_MAX} on >= {LABEL_CLEAN_MIN_DEFINITE} definite verdicts",
        "", rates(labels), "",
        "reasons: " + ", ".join(f"{k}={v}" for k, v in labels["reason"].value_counts().items()),
        "", "by the band at T (m over the definite verdicts at T; the gate reads clean, contested and "
        "leaning_malicious):", per_band(labels), "",
        f"movement among the trainable rows: delta m p10 {d[labels['trainable']].quantile(0.1):+.3f}  "
        f"p50 {d[labels['trainable']].median():+.3f}  p90 {d[labels['trainable']].quantile(0.9):+.3f};  "
        f"grew {int((d >= LABEL_GROWTH).sum())}, fell {int((d <= -LABEL_GROWTH).sum())}, "
        f"crossed 0.5 {int(((labels['m_t'] < 0.5) & (labels['m'] >= 0.5)).sum())}",
        f"trainable: {len(train)} of {len(labels)}  (malicious {int(pos.sum())}, benign "
        f"{int((labels['label'] == str(Label.BENIGN)).sum())}, of which provisional "
        f"{int(labels['provisional'].sum())})",
        f"prevalence among trainable: raw {pos[labels['trainable']].mean():.3f}   "
        f"x 1/pi {(w[labels['trainable']] * pos[labels['trainable']]).sum() / w[labels['trainable']].sum():.3f}",
        f"rate-only share ({', '.join(str(x) for x in RATE_REPORTED)}): raw {(~labels['trainable']).mean():.3f}   "
        f"x 1/pi {(w * ~labels['trainable']).sum() / w.sum():.3f}",
        f"realized horizon (days): p50 {labels['horizon_days'].median():.0f}  p90 {labels['horizon_days'].quantile(0.9):.0f}  "
        f"max {labels['horizon_days'].max():.0f}",
    ]) + "\n"
    (run.dir / "labels.report.txt").write_text(report)
    print(report)
    write_snapshot(labels, out, stage="03_label", run_id=run.run_id, rule=RULE,
                   min_definite=LABEL_MIN_DEFINITE, min_both=LABEL_MIN_BOTH, growth=LABEL_GROWTH,
                   clean_max=LABEL_CLEAN_MAX, clean_min_definite=LABEL_CLEAN_MIN_DEFINITE,
                   counts=labels["label"].value_counts().to_dict(),
                   reasons=labels["reason"].value_counts().to_dict(),
                   base_content_sha256=run.base_manifest.get("content_sha256"))
    log.info("labels written", extra={"path": str(out), "rows": len(labels)})


if __name__ == "__main__":
    main()
