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
from dataclasses import dataclass

import numpy as np
import pandas as pd

from .config import CONTESTED_LOWER, CONTESTED_UPPER, MIN_ANSWERING_ENGINES, STRATUM_TARGETS

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
    min_definite: int | None = MIN_ANSWERING_ENGINES,
) -> pd.Series:
    """Band each artifact on m = n_malicious / n_definite, at draw time.

    Computed here rather than read from the base so the band edges can be revised after
    stage 02 reports on them without a re-pull. The run manifest records which edges
    were used.

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
    out[ok & (m >= upper) & (m < 1)] = "leaning_malicious"
    out[ok & (m == 1)] = "consensus_malicious"
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
        df["n_malicious"], df["n_definite"], lower=lower, upper=upper, min_definite=min_definite
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


def check_draw(cohort: pd.DataFrame, reports: list[StratumReport]) -> list[str]:
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
