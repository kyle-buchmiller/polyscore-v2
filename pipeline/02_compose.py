#!/usr/bin/env python3
"""Stage 02 — the composition table. No modelling. Read it before continuing.

For the base (tier one) and, optionally, one run's cohort (tier two), prints:
  * shape -- rows, distinct sha256, the feed / customer split
  * the band histogram against the SS9 targets, and the LARGEST COHORT every band can fill
  * label-gap p50 / p90 / max per band -- what horizon_max_days is set from
  * answering-engine coverage per band -- what the floor must be chosen against
  * the T -> label change decomposition over the assertions: flips vs turnover
  * a family-string proxy for distinct clusters -- the real sample size, until TLSH exists
  * with --run: realized shares vs targets, pi per band, under-fill, the three draw checks,
    and one count shown raw / reweighted by 1/pi / in the base, so the denominators are seen
    to work before any label depends on them

A band that under-fills is a shortfall, reported; it is never back-filled from a neighbour.

Reads : data/base/<window>.parquet + .assertions.parquet  [+ data/runs/<run_id>/cohort.parquet]
Writes: data/reports/composition_<window>[_<run_id>].txt

Contract: specs/04-pipeline.md (02 · compose). Denominators: specs/03-labels.md.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import pandas as pd

from polyscore_v2.config import MIN_ANSWERING_ENGINES, STRATUM_TARGETS, settings
from polyscore_v2.draw import DRAWN_STRATA, assign_stratum
from polyscore_v2.labels import decompose_change
from polyscore_v2.logging_setup import configure

log = configure()

ORDER = list(DRAWN_STRATA) + ["below_floor"]
PLACEHOLDER_FLOOR = 5  # the survey's placeholder; reported, not applied (specs/99)
ILLUSTRATIVE_CUT = 0.5  # m at the label scan, for the reweighting demonstration only


def _gap_days(s: pd.Series) -> pd.Series:
    return pd.to_timedelta(s).dt.total_seconds() / 86400.0


def _verdict_maps(assertions: pd.DataFrame, role: str) -> dict[str, dict[str, bool | None]]:
    """sha256 -> {author -> True/False/None}. Absence from the dict is the fourth state."""
    sub = assertions[assertions["scan_role"] == role]
    out: dict[str, dict[str, bool | None]] = {}
    for sha, author, verdict in zip(sub["sha256"], sub["author"], sub["verdict"]):
        out.setdefault(sha, {})[author] = None if pd.isna(verdict) else bool(verdict)
    return out


def _counts(vm: dict[str, bool | None]) -> tuple[int, int]:
    definite = [v for v in vm.values() if v is not None]
    return sum(definite), len(definite)


def _band_of(n_mal: list[int], n_def: list[int], index) -> pd.Series:
    return assign_stratum(pd.Series(n_mal, index=index), pd.Series(n_def, index=index))


class Report:
    def __init__(self) -> None:
        self.lines: list[str] = []

    def h(self, title: str) -> None:
        self.lines += ["", f"== {title}", ""]

    def p(self, text: str = "") -> None:
        self.lines.append(text)

    def table(self, df: pd.DataFrame) -> None:
        self.lines.append(df.to_string())

    def text(self) -> str:
        return "\n".join(self.lines) + "\n"


def band_section(r: Report, df: pd.DataFrame, what: str) -> None:
    counts = df["stratum"].value_counts()
    rows = []
    for s in ORDER:
        n = int(counts.get(s, 0))
        share = STRATUM_TARGETS.get(s, 0.0)
        rows.append({"stratum": s, "n": n, "share_%": round(100 * n / max(len(df), 1), 1),
                     "target_%": round(100 * share, 1),
                     "fills_cohort_up_to": int(n / share) if share else None})
    t = pd.DataFrame(rows).set_index("stratum")
    r.h(f"{what}: bands at T (edges from config; below_floor is n_definite == 0 unless a floor is set)")
    r.table(t)
    fill = t.loc[list(DRAWN_STRATA), "fills_cohort_up_to"].min()
    r.p(f"\nlargest cohort every drawn band can fill at the SS9 shares: {int(fill)}  "
        f"(the smallest band bounds it; above this, under-fill is reported, never back-filled)")


def gap_and_coverage(r: Report, df: pd.DataFrame, what: str) -> None:
    g = df.assign(gap_days=_gap_days(df["label_gap"]))
    agg = g.groupby("stratum").agg(
        n=("sha256", "size"),
        gap_p50=("gap_days", lambda x: x.quantile(0.5)),
        gap_p90=("gap_days", lambda x: x.quantile(0.9)),
        gap_max=("gap_days", "max"),
        definite_min=("n_definite", "min"),
        definite_p10=("n_definite", lambda x: x.quantile(0.1)),
        definite_med=("n_definite", "median"),
        responded_med=("n_responded", "median"),
    ).reindex([s for s in ORDER if s in set(g["stratum"])]).round(1)
    r.h(f"{what}: label gap (days) and answering-engine coverage, per band")
    r.table(agg)
    below = int((df["n_definite"] < PLACEHOLDER_FLOOR).sum())
    r.p(f"\nrows with n_definite < {PLACEHOLDER_FLOOR} (the survey's placeholder floor; "
        f"config floor is {MIN_ANSWERING_ENGINES}): {below} of {len(df)}")
    r.p("horizon_max_days should be read off gap_p90 here, per band -- not guessed.")


def change_section(r: Report, df: pd.DataFrame, assertions: pd.DataFrame, what: str) -> None:
    at_t, at_l = _verdict_maps(assertions, "feature"), _verdict_maps(assertions, "label")
    shas = [s for s in df["sha256"] if s in at_t and s in at_l]
    if not shas:
        r.h(f"{what}: change decomposition"); r.p("no artifact has assertions for both scans"); return
    tot = {"flips": 0, "retractions": 0, "joined": 0, "left": 0, "stable": 0}
    any_flip = 0
    mal_all_t, def_all_t, mal_all_l, def_all_l = [], [], [], []
    mal_b_t, def_b_t, mal_b_l, def_b_l = [], [], [], []
    for s in shas:
        d = decompose_change(at_t[s], at_l[s])
        for k in tot:
            tot[k] += getattr(d, k)
        any_flip += d.flips > 0
        both = set(at_t[s]) & set(at_l[s])
        for src, mal, dfn in ((at_t[s], mal_all_t, def_all_t), (at_l[s], mal_all_l, def_all_l)):
            m, n = _counts(src); mal.append(m); dfn.append(n)
        for src, mal, dfn in ((at_t[s], mal_b_t, def_b_t), (at_l[s], mal_b_l, def_b_l)):
            m, n = _counts({a: v for a, v in src.items() if a in both}); mal.append(m); dfn.append(n)
    idx = pd.Index(shas)
    moved_all = int((_band_of(mal_all_t, def_all_t, idx) != _band_of(mal_all_l, def_all_l, idx)).sum())
    moved_both = int((_band_of(mal_b_t, def_b_t, idx) != _band_of(mal_b_l, def_b_l, idx)).sum())
    r.h(f"{what}: T -> label change decomposition over {len(shas)} artifacts (specs/03-labels.md)")
    r.p(f"engine-level  flips={tot['flips']} (retractions={tot['retractions']})  "
        f"joined={tot['joined']}  left={tot['left']}  stable={tot['stable']}")
    r.p(f"artifact-level  with >=1 flip: {any_flip}   "
        f"band moved, all engines: {moved_all}   band moved, engines present at both: {moved_both}")
    r.p("the gap between the last two numbers is turnover, not revision -- churn and retraction "
        "rates are computed over engines present at both moments only")


def family_section(r: Report, df: pd.DataFrame, assertions: pd.DataFrame, what: str) -> None:
    lab = assertions[(assertions["scan_role"] == "label") & (assertions["verdict"] == True)]  # noqa: E712
    lab = lab[lab["sha256"].isin(df["sha256"])]
    fam = lab["malware_family"].fillna("").str.strip().str.lower()
    lab = lab.assign(fam=fam)[fam != ""]
    modal = lab.groupby("sha256")["fam"].agg(lambda x: x.value_counts().index[0])
    r.h(f"{what}: distinct hashes vs distinct family strings (a PROXY for clusters; TLSH is stage 04/05)")
    r.p(f"artifacts: {df['sha256'].nunique()}   with a malicious family string at the label scan: "
        f"{len(modal)}   distinct modal family strings: {modal.nunique()}")
    if len(modal):
        r.p(f"family strings per artifact-with-family: {modal.nunique() / len(modal):.2f}  "
            "-- the lower this is, the smaller the real sample")


def run_section(r: Report, cohort: pd.DataFrame, manifest: dict, base: pd.DataFrame,
                assertions: pd.DataFrame) -> None:
    per = (cohort.groupby("stratum").agg(n_draw=("sha256", "size"), n_available=("n_available", "first"),
                                          pi=("pi", "first"))
           .reindex([s for s in DRAWN_STRATA if s in set(cohort["stratum"])]))
    per["realized_%"] = (100 * per["n_draw"] / len(cohort)).round(1)
    per["target_%"] = [round(100 * STRATUM_TARGETS[s], 1) for s in per.index]
    per["underfilled"] = [s in set(manifest.get("underfilled", [])) for s in per.index]
    r.h(f"run {manifest.get('run_id')}: realized shares against the SS9 targets "
        f"(seed {manifest.get('random_seed')}, requested {manifest.get('cohort_size_requested')})")
    r.table(per)
    problems = []
    if (cohort["pi"] <= 0).any() or (cohort["pi"] > 1).any():
        problems.append("pi outside (0, 1]")
    if len(cohort) != int(cohort.drop_duplicates("stratum")["n_draw"].sum()):
        problems.append("row count != sum of n_draw")
    for s, row in per.iterrows():
        if row["n_draw"] != row["n_available"] * row["pi"] and abs(row["n_draw"] / row["n_available"] - row["pi"]) > 1e-9:
            problems.append(f"{s}: pi != n_draw / n_available")
    r.p("\nthree draw checks: " + ("OK" if not problems else "FAILED -- " + "; ".join(problems)))
    r.p("provenance in cohort: " + ", ".join(f"{k}={v}" for k, v in cohort["provenance"].value_counts().items()))

    # One count, three ways. The label-scan m >= cut is ILLUSTRATIVE -- not a label.
    at_l = _verdict_maps(assertions, "label")
    def m_label(sha: str) -> float:
        m, n = _counts(at_l.get(sha, {}))
        return m / n if n else float("nan")
    c = cohort.assign(m_l=cohort["sha256"].map(m_label)).dropna(subset=["m_l"])
    b = base.assign(m_l=base["sha256"].map(m_label)).dropna(subset=["m_l"])
    hit_c, hit_b = (c["m_l"] >= ILLUSTRATIVE_CUT), (b["m_l"] >= ILLUSTRATIVE_CUT)
    w = 1.0 / c["pi"]
    r.h(f"run {manifest.get('run_id')}: one count three ways -- share with m(label) >= {ILLUSTRATIVE_CUT} (illustrative)")
    r.p(f"cohort raw        : {hit_c.mean():.3f}   (what training sees)")
    r.p(f"cohort x 1/pi     : {(w * hit_c).sum() / w.sum():.3f}   (what the base is like -- within the labellable population)")
    r.p(f"base, directly    : {hit_b.mean():.3f}   (the number the reweighting must recover)")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", type=Path, default=settings.base_snapshot,
                    help="base parquet (default: POLYSCORE_BASE_SNAPSHOT, else the newest in data/base)")
    ap.add_argument("--run", default=None, help="run_id under data/runs to report on as well")
    a = ap.parse_args()

    base_path = a.base
    if base_path is None:
        cands = sorted(settings.path("base").glob("*.parquet"))
        cands = [c for c in cands if not c.name.endswith(".assertions.parquet")]
        if not cands:
            sys.exit("no base under data/base; run 01_extract.py first")
        base_path = cands[-1]
    base = pd.read_parquet(base_path)
    assertions = pd.read_parquet(base_path.with_suffix(".assertions.parquet"))
    window = base_path.stem

    r = Report()
    r.p(f"composition -- base {base_path.name}  ({len(base)} rows, {base['sha256'].nunique()} distinct sha256, "
        f"{len(assertions)} assertion rows)")
    r.p("provenance: " + ", ".join(f"{k}={v}" for k, v in base["provenance"].value_counts().items()))
    b = base.assign(stratum=assign_stratum(base["n_malicious"], base["n_definite"]))
    band_section(r, b, "base")
    gap_and_coverage(r, b, "base")
    change_section(r, b, assertions, "base")
    family_section(r, b, assertions, "base")

    name = window
    if a.run:
        run_dir = settings.path("runs", a.run)
        cohort = pd.read_parquet(run_dir / "cohort.parquet")
        manifest = json.loads((run_dir / "cohort.manifest.json").read_text())
        run_section(r, cohort, manifest, base, assertions)
        gap_and_coverage(r, cohort, f"run {a.run}")
        change_section(r, cohort, assertions, f"run {a.run}")
        name = f"{window}_{a.run}"

    out = settings.path("reports", f"composition_{name}.txt")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(r.text())
    print(r.text())
    log.info("composition written", extra={"path": str(out), "rows": len(base), "run": a.run})


if __name__ == "__main__":
    main()
