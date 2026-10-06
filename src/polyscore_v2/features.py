"""Feature construction, and the as-of rule that keeps it honest.

THE INVARIANT: every feature must be true at or before the scoring moment. The label
comes from the future by construction (horizon T+30); if a feature does too, the model
learns a clue that exists only because the answer already happened. It will score
brilliantly in testing and fail in production, and no metric will say so.

This is enforced here, mechanically, rather than by discipline. See specs/02-data.md.
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass

import pandas as pd

#: Fields that are regenerated and overwritten in place, folding in information that
#: arrived after the scoring moment. Safe for stratification and survey; never features.
FORBIDDEN_AS_FEATURES = frozenset(
    {
        "polyunite",           # regenerated, absorbs sandbox families and tags weeks later
        "detections",          # rolled-up counts, recomputed
        "tags",
        "families",
        "polyscore",           # the incumbent's output at any scan after T
        "incumbent_polyscore",  # the incumbent's output AT T -- baseline 4, carried for stage 06, never learned from
    }
)


#: Columns stage 01 writes to describe *how the row was drawn* (estimand §9). They are
#: not late — they are simply not properties of the file. As features they are perfect
#: provenance detectors: `provenance` separates the injected known-good arm from organic
#: traffic outright, and `stratum` is a coarsening of engine agreement, which the feature
#: matrix already holds. Bookkeeping throughout; reweighting reads them, models never do.
BOOKKEEPING_NOT_FEATURES = frozenset(
    {
        "stratum",             # which §9 band the row was drawn from
        "pi",                  # inclusion probability; 1/pi recovers natural prevalence
        "provenance",          # organic, or which injected known-good source
    }
)


class AsOfViolation(ValueError):
    """Raised when a field would leak information from after the scoring moment."""


@dataclass(frozen=True)
class Field:
    """A feature column and the instant its value became true."""

    name: str
    as_of: dt.datetime


def assert_as_of(fields: list[Field], scoring_moment: dt.datetime) -> None:
    """Refuse any field stamped later than the scoring moment, or on the deny-list.

    Called by 04_features.py before the matrix is written. tests/test_asof.py is the guard.
    """
    late = [f.name for f in fields if f.as_of > scoring_moment]
    if late:
        raise AsOfViolation(f"fields are stamped after the scoring moment {scoring_moment}: {sorted(late)}")
    banned = sorted({f.name for f in fields} & FORBIDDEN_AS_FEATURES)
    if banned:
        raise AsOfViolation(
            f"fields are regenerated in place and cannot be features: {banned} "
            f"(see specs/02-data.md; they are fine for stratification)"
        )
    bookkeeping = sorted({f.name for f in fields} & BOOKKEEPING_NOT_FEATURES)
    if bookkeeping:
        raise AsOfViolation(
            f"sampling bookkeeping cannot be features: {bookkeeping} "
            f"(estimand §9; reweighting reads these, the model must not)"
        )


def _verdict_frame(assertions: pd.DataFrame) -> pd.DataFrame:
    a = assertions.copy()
    a["malicious"] = (a["verdict"] == True).fillna(False).astype("int8")  # noqa: E712 -- nullable boolean
    a["benign"] = (a["verdict"] == False).fillna(False).astype("int8")    # noqa: E712
    a["definite"] = a["verdict"].notna().astype("int8")
    return a


def encode_engine_verdicts(assertions: pd.DataFrame, artifacts: pd.Index | None = None) -> pd.DataFrame:
    """Two columns per engine, keyed on the immutable address.

        engine_<addr>_responded   1 if the engine answered at all
        engine_<addr>_malicious   1 if it said malicious

    So clean is (1, 0), silent is (0, 0), malicious is (1, 1). The old model collapsed
    all three to 0.0, which is the structural cause of the 0.3346 constant. An explicit
    "unknown" (verdict NULL) is (1, 0) here and counted in the `n_unknown` aggregate.

    NOTE: key on `author` (the address), never the display name. The registry holds 296
    addresses under 258 names -- two engines sharing a name collapse to one, and a
    vendor's separate registrations split into unrelated columns.
    """
    a = _verdict_frame(assertions)
    responded = (a.pivot_table(index="sha256", columns="author", values="definite", aggfunc="size",
                               fill_value=0) > 0).astype("int8")
    malicious = a.pivot_table(index="sha256", columns="author", values="malicious", aggfunc="max",
                              fill_value=0).astype("int8")
    authors = sorted(set(responded.columns) | set(malicious.columns))
    responded = responded.reindex(columns=authors, fill_value=0)
    malicious = malicious.reindex(columns=authors, fill_value=0)
    responded.columns = [f"engine_{c}_responded" for c in authors]
    malicious.columns = [f"engine_{c}_malicious" for c in authors]
    out = pd.concat([responded, malicious], axis=1)
    if artifacts is not None:
        out = out.reindex(artifacts, fill_value=0).astype("int8")
    return out[sorted(out.columns)]


def encode_engine_verdicts_old(assertions: pd.DataFrame, artifacts: pd.Index | None = None) -> pd.DataFrame:
    """The 2023 encoding: one column per engine, 1 if malicious, else 0 -- clean, unknown
    and silent all collapse to 0. Built only so stage 07 can measure what that costs."""
    a = _verdict_frame(assertions)
    out = a.pivot_table(index="sha256", columns="author", values="malicious", aggfunc="max",
                        fill_value=0).astype("int8")
    out.columns = [f"engine_{c}" for c in out.columns]
    if artifacts is not None:
        out = out.reindex(artifacts, fill_value=0).astype("int8")
    return out[sorted(out.columns)]


def aggregates(assertions: pd.DataFrame, artifacts: pd.Index | None = None) -> pd.DataFrame:
    """Per-artifact counts over the T scan. `m` is NaN when nothing answered definitely;
    `m_defined` says so, so a linear model can impute without pretending."""
    a = _verdict_frame(assertions)
    g = a.groupby("sha256")
    out = pd.DataFrame({
        "n_responded": g.size(),
        "n_definite": g["definite"].sum(),
        "n_malicious": g["malicious"].sum(),
        "n_benign": g["benign"].sum(),
    })
    out["n_unknown"] = out["n_responded"] - out["n_definite"]
    out["m"] = out["n_malicious"] / out["n_definite"].where(out["n_definite"] > 0)
    out["m_defined"] = out["n_definite"].gt(0).astype("int8")
    out["malicious_share_responded"] = out["n_malicious"] / out["n_responded"].where(out["n_responded"] > 0)
    if "bid" in a.columns:
        out["bid_mean_malicious"] = a[a["malicious"] == 1].groupby("sha256")["bid"].mean()
        out["bid_mean_benign"] = a[a["benign"] == 1].groupby("sha256")["bid"].mean()
    if artifacts is not None:
        out = out.reindex(artifacts)
        for c in ("n_responded", "n_definite", "n_malicious", "n_benign", "n_unknown", "m_defined"):
            out[c] = out[c].fillna(0).astype("int64")
    return out


def family_scalars(assertions: pd.DataFrame, artifacts: pd.Index | None = None) -> pd.DataFrame:
    """Family-string scalars over the T scan's malicious verdicts (labels.family_class).
    `modal_family` is the string itself: carried as META for the split's grouping, never
    a feature."""
    from .labels import family_class  # local import: labels imports config, not features

    a = _verdict_frame(assertions)
    mal = a[a["malicious"] == 1].copy()
    mal["fam"] = mal["malware_family"].fillna("").astype(str).str.strip().str.lower()
    mal["cls"] = mal["fam"].map(family_class)
    g = mal.groupby("sha256")
    out = pd.DataFrame({
        "n_with_family": g["fam"].apply(lambda x: int((x != "").sum())),
        "n_distinct_families": g["fam"].apply(lambda x: int(x[x != ""].nunique())),
        "n_specific": g["cls"].apply(lambda x: int((x == "specific").sum())),
        "n_generic": g["cls"].apply(lambda x: int(x.isin(["generic", "none"]).sum())),
        "n_pup": g["cls"].apply(lambda x: int((x == "pup").sum())),
        "n_dual_use": g["cls"].apply(lambda x: int((x == "dual_use").sum())),
        "modal_family_share": g["fam"].apply(lambda x: (x[x != ""].value_counts().iloc[0] / len(x)) if (x != "").any() else 0.0),
        "modal_family": g["fam"].apply(lambda x: x[x != ""].value_counts().index[0] if (x != "").any() else ""),
    })
    if artifacts is not None:
        out = out.reindex(artifacts)
        for c in ("n_with_family", "n_distinct_families", "n_specific", "n_generic", "n_pup", "n_dual_use"):
            out[c] = out[c].fillna(0).astype("int64")
        out["modal_family_share"] = out["modal_family_share"].fillna(0.0)
        out["modal_family"] = out["modal_family"].fillna("")
    return out


META_COLUMNS = ["sha256", "instance_number", "scoring_moment", "label_gap", "modal_family",
                "incumbent_polyscore", "n_available", "n_draw"]
FAMILY_FEATURES = ["n_with_family", "n_distinct_families", "n_specific", "n_generic", "n_pup",
                   "n_dual_use", "modal_family_share"]


def build_matrix(
    cohort: pd.DataFrame, assertions: pd.DataFrame, *, static_block: pd.DataFrame | None = None
) -> tuple[pd.DataFrame, dict[str, list[str]]]:
    """Assemble the feature matrix for one cohort, enforcing the as-of rule.

    Everything learnable comes from the T scan (`scan_role == 'feature'`), so its as-of is
    the scoring moment by construction; the deny-lists are what `assert_as_of` guards here.
    A static PE block, if given, must carry `pe_as_of` (the artifact's first sighting --
    the facts are time-invariant, the record is not) and is checked row by row.

    Returns the matrix and the column groups downstream stages select from:
    `meta`, `bookkeeping`, `features_new`, `features_old`.
    """
    artifacts = pd.Index(cohort["sha256"])
    t = assertions[(assertions["scan_role"] == "feature") & assertions["sha256"].isin(artifacts)]
    new = encode_engine_verdicts(t, artifacts)
    old = encode_engine_verdicts_old(t, artifacts)
    agg = aggregates(t, artifacts)
    fam = family_scalars(t, artifacts)

    # Row-count assertion at the boundary: the base's counts at T were computed in SQL
    # over the same assertions; a disagreement means the pulls are out of step.
    for c in ("n_definite", "n_malicious", "n_responded"):
        if c in cohort.columns:
            got = agg[c].reindex(artifacts).to_numpy()
            exp = cohort[c].to_numpy()
            if (got != exp).any():
                raise ValueError(f"{c} from the assertions disagrees with the base for "
                                 f"{int((got != exp).sum())} artifacts: assertions and base are out of step")

    feature_new = list(new.columns) + [c for c in agg.columns] + FAMILY_FEATURES
    feature_old = list(old.columns)
    static_cols: list[str] = []
    parts = [cohort.set_index("sha256"), new, old, agg, fam]
    if static_block is not None:
        sb = static_block.set_index("sha256").reindex(artifacts)
        if "pe_as_of" not in sb.columns:
            raise AsOfViolation("static block lacks pe_as_of; every field needs the instant it became true")
        late = sb.index[(sb["pe_as_of"] > cohort.set_index("sha256")["scoring_moment"]).fillna(False)]
        if len(late):
            raise AsOfViolation(f"static block is stamped after the scoring moment for {len(late)} artifacts")
        static_cols = [c for c in sb.columns if c != "pe_as_of"]
        parts.append(sb[static_cols])
        feature_new += static_cols
    matrix = pd.concat(parts, axis=1).reset_index()

    bookkeeping = sorted(BOOKKEEPING_NOT_FEATURES & set(matrix.columns))
    meta = [c for c in META_COLUMNS if c in matrix.columns]
    moment = pd.to_datetime(matrix["scoring_moment"]).min().to_pydatetime()
    assert_as_of([Field(c, moment) for c in feature_new + feature_old], moment)
    groups = {"meta": meta, "bookkeeping": bookkeeping, "features_new": feature_new, "features_old": feature_old}
    return matrix, groups
