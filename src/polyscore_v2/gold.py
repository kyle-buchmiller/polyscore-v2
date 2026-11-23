"""The gold slice's draw: files of one band at T, at random, in two groups by the cheap label.

A slice can continue an earlier one: the earlier files that are still eligible stay, and each
group is filled back up at random. see specs/04-pipeline.md § Stage contracts
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

import numpy as np
import pandas as pd

from polyscore_v2.labels import Label

#: group -> (the cheap label, its reasons) that make a file eligible
GROUPS = {
    "accrued": (Label.MALICIOUS, ("grew", "consensus")),
    "stayed": (Label.BENIGN, ("stayed_contested",)),
}


@dataclass(frozen=True)
class Earlier:
    """An earlier gold draw that a new one continues: its files, and every file of its pools."""

    run_id: str
    drawn: frozenset[str]
    #: sha256 -> the group whose pool held the file when the earlier slice was drawn
    pool: Mapping[str, str]


def pools(labelled: pd.DataFrame, band: str) -> dict[str, pd.DataFrame]:
    """Each group's eligible files of the band, in sha256 order."""
    in_band = labelled[labelled["band_t"] == band]
    out = {}
    for group, (label, reasons) in GROUPS.items():
        eligible = (in_band["label"] == str(label)) & in_band["reason"].isin(reasons)
        out[group] = in_band[eligible].sort_values("sha256")
    return out


def draw(
    by_group: Mapping[str, pd.DataFrame],
    per_group: int,
    rng: np.random.Generator,
    earlier: Earlier | None = None,
) -> tuple[pd.DataFrame, dict[str, dict]]:
    """`per_group` files of each pool, with `group`, `n_eligible`, `pi_gold` and `carried_from`.

    With `earlier`, its files still in a pool are kept and the group is filled from the rest
    of the pool. Returns the slice and a report per group. Raises ValueError when a pool cannot
    fill its group, or holds more earlier files than the group takes.
    """
    parts, report = [], {}
    for group, pool in by_group.items():
        n = len(pool)
        kept = np.zeros(n, dtype=bool) if earlier is None else pool["sha256"].isin(earlier.drawn).to_numpy()
        need = per_group - int(kept.sum())
        rest = np.flatnonzero(~kept)
        if need < 0:
            raise ValueError(f"group {group!r} holds {int(kept.sum())} earlier files, {per_group} asked")
        if len(rest) < need:
            raise ValueError(f"{n} eligible files in group {group!r}, {per_group} asked")
        new = rest[np.sort(rng.choice(len(rest), size=need, replace=False))]
        p_new = need / len(rest) if len(rest) else 0.0
        p_kept = pd.Series(0.0, index=pool.index)
        cells: dict[str, dict] = {}
        if earlier is not None:
            was = pool["sha256"].map(earlier.pool)
            if was[kept].isna().any():
                raise ValueError(f"group {group!r}: an earlier file is not in the earlier pools")
            # An earlier file is a random one of its cell: the files here that shared its earlier pool.
            carried = pd.Series(kept, index=pool.index)
            p_kept = (carried.groupby(was).transform("sum") / was.groupby(was).transform("size")).fillna(0.0)
            cells = {
                str(cell): {"in_pool": int(len(rows)), "carried": int(carried[rows.index].sum())}
                for cell, rows in was.dropna().groupby(was.dropna())
            }
        chosen = np.sort(np.concatenate([np.flatnonzero(kept), new]))
        take = pool.iloc[chosen].copy()
        take["group"], take["n_eligible"] = group, n
        # Kept in the earlier phase, or passed over there and drawn in this one.
        take["pi_gold"] = (p_kept + (1.0 - p_kept) * p_new).iloc[chosen].to_numpy()
        take["carried_from"] = np.where(kept[chosen], earlier.run_id if earlier else "", "")
        parts.append(take)
        report[group] = {"eligible": n, "drawn": per_group, "carried": int(kept.sum()), "new": need,
                         "pi_new": p_new, "earlier_pools": cells}
    return pd.concat(parts, ignore_index=True), report
