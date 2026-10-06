#!/usr/bin/env python3
"""Stage 03 — attach the answer column

One of the four pilot labels per artifact, with its grade, reason, source and realized
horizon, from the label scan's verdicts via labels.label_at_horizon. The rule is
PROVISIONAL (decisions/0011): engines stand in for clusters, family_class for the
specificity model, and stability is not assessed -- each stand-in is named in `reason`.

UNDECIDABLE and UNWANTED rows stay in the file, flagged `trainable = False`, so they are
excluded from training and still counted. Their rates are reported three ways -- raw over
the cohort, reweighted by 1/pi, and per stratum -- because the contested band is
over-weighted by design and `undecidable` concentrates there (specs/03-labels.md).

No waiting: the training arm's label scan already happened (decision 0010).

Reads : data/runs/<run_id>/cohort.parquet + the base it names (+ .assertions.parquet)
Writes: data/runs/<run_id>/labels.parquet (+ manifest), labels.report.txt

Contract: specs/04-pipeline.md (03 · label), specs/03-labels.md.
"""

from __future__ import annotations

import argparse

import pandas as pd

from polyscore_v2.config import LABEL_MIN_DEFINITE, settings
from polyscore_v2.io import write_snapshot
from polyscore_v2.labels import POSITIVE, NEGATIVE, RATE_REPORTED, Grade, Label, assert_pilot_labels, label_at_horizon
from polyscore_v2.logging_setup import configure
from polyscore_v2.runs import fresh, load_run

log = configure()


def rates(labels: pd.DataFrame) -> str:
    w = 1.0 / labels["pi"]
    lines = [f"{'label':12s} {'raw':>7s} {'x 1/pi':>7s}   per stratum"]
    for lab in [str(x) for x in Label]:
        hit = labels["label"] == lab
        per = labels[hit].groupby("stratum").size()
        per_s = ", ".join(f"{s}={n}" for s, n in per.items()) or "-"
        lines.append(f"{lab:12s} {hit.mean():7.3f} {(w * hit).sum() / w.sum():7.3f}   {per_s}")
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
        r = label_at_horizon(h, min_definite=LABEL_MIN_DEFINITE,
                             min_clusters=settings.min_independent_clusters,
                             generic_discount=settings.heuristic_family_discount)
        rows.append({"sha256": sha, "label": str(r.label), "grade": int(r.grade), "reason": r.reason, **r.evidence})
    labels = pd.DataFrame(rows).merge(
        run.cohort[["sha256", "label_gap", "stratum", "pi", "provenance"]], on="sha256", how="left")
    labels["source"] = "label_scan"
    labels["horizon_days"] = pd.to_timedelta(labels["label_gap"]).dt.total_seconds() / 86400.0
    labels["trainable"] = labels["label"].isin([str(x) for x in POSITIVE | NEGATIVE])
    assert_pilot_labels(labels["label"])
    if len(labels) != len(run.cohort):   # row-count assertion at the boundary
        raise SystemExit(f"{len(labels)} labels for {len(run.cohort)} cohort rows")

    w = 1.0 / labels["pi"]
    pos = labels["label"] == str(Label.MALICIOUS)
    train = labels[labels["trainable"]]
    report = "\n".join([
        f"labels -- run {run.run_id}, {len(labels)} artifacts, rule decisions/0011 (provisional)",
        f"floor {LABEL_MIN_DEFINITE} definite; bar {settings.min_independent_clusters} engines-as-clusters; "
        f"generic discount {settings.heuristic_family_discount}",
        "", rates(labels), "",
        "reasons: " + ", ".join(f"{k}={v}" for k, v in labels["reason"].value_counts().items()),
        f"trainable: {len(train)} of {len(labels)}  (malicious {int(pos.sum())}, benign "
        f"{int((labels['label'] == str(Label.BENIGN)).sum())})",
        f"prevalence among trainable: raw {pos[labels['trainable']].mean():.3f}   "
        f"x 1/pi {(w[labels['trainable']] * pos[labels['trainable']]).sum() / w[labels['trainable']].sum():.3f}",
        f"rate-only share ({', '.join(str(x) for x in RATE_REPORTED)}): raw {(~labels['trainable']).mean():.3f}   "
        f"x 1/pi {(w * ~labels['trainable']).sum() / w.sum():.3f}",
        f"realized horizon (days): p50 {labels['horizon_days'].median():.0f}  p90 {labels['horizon_days'].quantile(0.9):.0f}  "
        f"max {labels['horizon_days'].max():.0f}",
    ]) + "\n"
    (run.dir / "labels.report.txt").write_text(report)
    print(report)
    write_snapshot(labels, out, stage="03_label", run_id=run.run_id, rule="decisions/0011 provisional",
                   min_definite=LABEL_MIN_DEFINITE, min_clusters=settings.min_independent_clusters,
                   generic_discount=settings.heuristic_family_discount,
                   counts=labels["label"].value_counts().to_dict(),
                   base_content_sha256=run.base_manifest.get("content_sha256"))
    log.info("labels written", extra={"path": str(out), "rows": len(labels)})


if __name__ == "__main__":
    main()
