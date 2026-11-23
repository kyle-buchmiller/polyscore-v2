"""The run draw: a stratified cohort from the base snapshot, with pi recorded.

Tier two of the two-tier extraction (estimand SS11, decisions/0010). Pure pandas, no
database -- that is the property everything else rests on. A run that touched the
database could not be reproduced tomorrow, could not run concurrently with its siblings
without contending on the replica, and could not scale by changing one number.

THE INVARIANT: pi = n_draw / n_available per stratum, computed over the BASE's band
populations, recorded on every row. pi_base is 1 by construction (the base is a full
pull), so this is pi_run outright. It is the one column no later step can reconstruct:
without it the cohort can be ranked and never reweighted, which means never calibrated.
See specs/01-estimand.md SS9.
"""

from __future__ import annotations

import hashlib
import math
from collections.abc import Mapping
from dataclasses import dataclass

import numpy as np
import pandas as pd

from .config import (
    CONSENSUS_MALICIOUS, CONTESTED_LOWER, CONTESTED_UPPER, MIN_ANSWERING_ENGINES, STRATUM_TARGETS)

#: Strata the draw takes from. injected_known_good is in STRATUM_TARGETS but is sourced
#: externally and never drawn from the base; below_floor is reported, never drawn.
DRAWN_STRATA: tuple[str, ...] = tuple(
    s for s in STRATUM_TARGETS if s != "injected_known_good"
)


def assign_stratum(
    n_malicious: pd.Series,
    n_definite: pd.Series,
    *,
    lower: float = CONTESTED_LOWER,
    upper: float = CONTESTED_UPPER,
    consensus: float = CONSENSUS_MALICIOUS,
    min_definite: int | None = MIN_ANSWERING_ENGINES,
) -> pd.Series:
    """Band each artifact on m = n_malicious / n_definite, at draw time.

    Computed here rather than read from the base so the band edges can be revised after
    stage 02 reports on them without a re-pull. The run manifest records which edges
    were used.

    Consensus malicious starts at `consensus`, not at unanimity: a benign verdict on this
    roster is mostly the absence of a signature, so m never reaches 1 at full coverage
    (decisions/0012).

    m is undefined when nothing answered definitely, and meaningless when very little
    did -- one verdict moves m by 0.5 at two engines. Both land in `below_floor`, which
    is its own stratum: reported, never folded into a band by a noisy ratio.
    """
    n_def = n_definite.astype("float64")
    m = n_malicious.astype("float64") / n_def.where(n_def > 0)
    floor = min_definite if min_definite is not None else 1
    out = pd.Series("below_floor", index=n_malicious.index, dtype="object")
    ok = n_def >= floor
    out[ok & (m == 0)] = "consensus_clean"
    out[ok & (m > 0) & (m <= lower)] = "leaning_clean"
    out[ok & (m > lower) & (m < upper)] = "contested"
    out[ok & (m >= upper) & (m < consensus)] = "leaning_malicious"
    out[ok & (m >= consensus)] = "consensus_malicious"
    return out


def _permutation_key(sha256: pd.Series, seed: int) -> pd.Series:
    """A deterministic pseudo-random order keyed by (sha256, seed).

    md5(sha256 || seed), the same construction the first base pull used in SQL,
    so a draw is reproducible from the seed alone and never depends on process state
    the way a seeded RNG consumed in a different order would.
    """
    return sha256.map(lambda s: hashlib.md5(f"{s}{seed}".encode()).hexdigest())


@dataclass(frozen=True)
class StratumReport:
    stratum: str
    n_available: int
    target_share: float
    n_target: int
    n_draw: int
    pi: float
    underfilled: bool


def stratified_draw(
    base: pd.DataFrame,
    *,
    cohort_size: int,
    seed: int,
    targets: dict[str, float] = STRATUM_TARGETS,
    lower: float = CONTESTED_LOWER,
    upper: float = CONTESTED_UPPER,
    consensus: float = CONSENSUS_MALICIOUS,
    min_definite: int | None = MIN_ANSWERING_ENGINES,
) -> tuple[pd.DataFrame, list[StratumReport]]:
    """Draw `cohort_size` artifacts from the base, stratified, recording pi per row.

    Under-fill is REPORTED, never back-filled from a neighbouring band -- that would
    silently change the draw and make pi a lie for both bands. A band taken whole has
    pi = 1.0, which is legitimate and carries no sampling variance.
    """
    if "stratum" in base.columns:
        raise ValueError("the base must be edge-agnostic; stratum is computed here, not stored")
    df = base.copy()
    df["stratum"] = assign_stratum(
        df["n_malicious"], df["n_definite"],
        lower=lower, upper=upper, consensus=consensus, min_definite=min_definite,
    )
    df["_key"] = _permutation_key(df["sha256"], seed)

    available = df["stratum"].value_counts()
    reports: list[StratumReport] = []
    drawn: list[pd.DataFrame] = []
    for stratum in DRAWN_STRATA:
        share = targets[stratum]
        n_avail = int(available.get(stratum, 0))
        n_target = math.ceil(cohort_size * share)
        n_draw = min(n_avail, n_target)
        pi = (n_draw / n_avail) if n_avail else float("nan")
        reports.append(StratumReport(stratum, n_avail, share, n_target, n_draw, pi, n_draw < n_target))
        if n_draw == 0:
            continue
        block = df[df["stratum"] == stratum].sort_values(["_key", "sha256"]).head(n_draw).copy()
        block["pi"] = pi
        block["n_available"] = n_avail
        block["n_draw"] = n_draw
        drawn.append(block)

    # below_floor is never drawn, but its size is part of the report
    n_floor = int(available.get("below_floor", 0))
    reports.append(StratumReport("below_floor", n_floor, 0.0, 0, 0, float("nan"), False))

    if not drawn:
        raise ValueError("nothing drawable: every stratum is empty or below the floor")
    cohort = pd.concat(drawn, ignore_index=True).drop(columns="_key")
    cohort = cohort.sort_values(["stratum", "sha256"]).reset_index(drop=True)
    cohort["pi"] = cohort["pi"].astype("float64")
    return cohort, reports


@dataclass(frozen=True)
class ScreenedStratumReport:
    """One band of a screened draw. `n_available` is the band's in-frame population: counted
    when the band was read to its end, estimated from the share examined otherwise."""

    stratum: str
    n_band: int
    n_examined: int
    n_out: int
    n_available: int
    target_share: float
    n_target: int
    n_draw: int
    pi: float
    underfilled: bool


def screened_draw(
    base: pd.DataFrame,
    examined: Mapping[str, str | None],
    *,
    cohort_size: int,
    seed: int,
    targets: dict[str, float] = STRATUM_TARGETS,
    lower: float = CONTESTED_LOWER,
    upper: float = CONTESTED_UPPER,
    consensus: float = CONSENSUS_MALICIOUS,
    min_definite: int | None = MIN_ANSWERING_ENGINES,
) -> tuple[pd.DataFrame, list[ScreenedStratumReport], list[str]]:
    """Draw like `stratified_draw` when a file must be examined before it can be shown to stay.

    `examined` maps a file to why it is out of frame, or to None when it stays; a file it does
    not hold has not been examined. Each band's fixed order is read from the top: a file that
    is out is passed over and a file that stays is drawn, until the target is met or the band
    ends. The third value lists the unexamined files the walk needs before it can finish, in
    order; the draw is complete when that list is empty.

    pi is the share of the band the walk read, n_examined / n_band: every file in that stretch
    was examined, so each drawn file stands for the same number of files of its band. It is
    recorded as n_draw / n_available so the invariant above holds for these rows too.

    A `phase` column in the base, when present, is read before the fixed order: every file of
    a lower phase comes first. It lets files added to the base later top a band up without
    moving a file already drawn. The phase must not depend on what a file is, or the order is
    no longer a random one.
    """
    if "stratum" in base.columns:
        raise ValueError("the base must be edge-agnostic; stratum is computed here, not stored")
    df = base.copy()
    df["stratum"] = assign_stratum(
        df["n_malicious"], df["n_definite"],
        lower=lower, upper=upper, consensus=consensus, min_definite=min_definite,
    )
    df["_key"] = _permutation_key(df["sha256"], seed)
    order = [*(["phase"] if "phase" in df.columns else []), "_key", "sha256"]

    reports: list[ScreenedStratumReport] = []
    drawn: list[pd.DataFrame] = []
    needed: list[str] = []
    for stratum in DRAWN_STRATA:
        share = targets[stratum]
        n_target = math.ceil(cohort_size * share)
        block = df[df["stratum"] == stratum].sort_values(order)
        hashes = block["sha256"].tolist()
        kept: list[int] = []
        n_out = n_examined = 0
        blocked: int | None = None
        for i, sha in enumerate(hashes):
            if len(kept) == n_target:
                break
            if sha not in examined:
                blocked = i
                break
            n_examined = i + 1
            if examined[sha] is None:
                kept.append(i)
            else:
                n_out += 1
        if blocked is not None:
            # What the walk reads next if every unexamined file stays: the least it can need.
            would_keep = len(kept)
            for sha in hashes[blocked:]:
                if would_keep == n_target:
                    break
                if sha not in examined:
                    needed.append(sha)
                    would_keep += 1
                elif examined[sha] is None:
                    would_keep += 1
        n_draw = len(kept)
        n_available = round(n_draw * len(hashes) / n_examined) if n_examined else 0
        pi = (n_draw / n_available) if n_available else float("nan")
        reports.append(
            ScreenedStratumReport(
                stratum, len(hashes), n_examined, n_out, n_available, share, n_target, n_draw, pi,
                n_draw < n_target,
            )
        )
        if n_draw == 0:
            continue
        rows = block.iloc[kept].copy()
        rows["pi"] = pi
        rows["n_available"] = n_available
        rows["n_draw"] = n_draw
        drawn.append(rows)

    n_floor = int((df["stratum"] == "below_floor").sum())
    reports.append(
        ScreenedStratumReport("below_floor", n_floor, 0, 0, n_floor, 0.0, 0, 0, float("nan"), False)
    )
    if not drawn:
        return df.iloc[0:0].drop(columns="_key"), reports, needed
    cohort = pd.concat(drawn, ignore_index=True).drop(columns="_key")
    cohort = cohort.sort_values(["stratum", "sha256"]).reset_index(drop=True)
    cohort["pi"] = cohort["pi"].astype("float64")
    return cohort, reports, needed


def check_draw(cohort: pd.DataFrame, reports: list[StratumReport] | list[ScreenedStratumReport]) -> list[str]:
    """The three checks every draw must pass; returns the failures, empty when sound."""
    problems: list[str] = []
    expected = sum(r.n_draw for r in reports)
    if len(cohort) != expected:
        problems.append(f"row count {len(cohort)} != sum of n_draw {expected}: a join fanned out")
    if (cohort["pi"] > 1.0).any() or (cohort["pi"] <= 0).any():
        problems.append("pi outside (0, 1]")
    if cohort["sha256"].duplicated().any():
        problems.append("duplicate sha256 in cohort: per-artifact counting violated")
    return problems
