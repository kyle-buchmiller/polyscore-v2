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


def encode_engine_verdicts(assertions: pd.DataFrame) -> pd.DataFrame:
    """Two columns per engine, keyed on the immutable address.

        engine_<addr>_responded   1 if the engine answered at all
        engine_<addr>_malicious   1 if it said malicious

    So clean is (1, 0), silent is (0, 0), malicious is (1, 1). The old model collapsed
    all three to 0.0, which is the structural cause of the 0.3346 constant.

    NOTE: key on `author` (the address), never the display name. The registry holds 296
    addresses under 258 names -- two engines sharing a name collapse to one, and a
    vendor's separate registrations split into unrelated columns.
    """
    raise NotImplementedError("stage 04 — see specs/02-data.md for the column contract")


def build_matrix(snapshot: pd.DataFrame, scoring_moment: dt.datetime) -> pd.DataFrame:
    """Assemble the ~120-column feature matrix, enforcing the as-of rule."""
    raise NotImplementedError("stage 04 — see specs/02-data.md")
