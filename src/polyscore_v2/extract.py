"""Frame construction for 01_extract.py -- the parts worth a test.

THE INVARIANT: an instance number is a 17-digit integer and must never pass through
float64. pandas picks float64 for an integer column with a NULL, and float64's 53-bit
mantissa rounds anything above ~9e15. Measured 2026-10-05: every label instance in the
first chunked stage base was rounded to a number that exists nowhere, and 26 of 32
artifacts labelled as "no assertions" for a scan the SQL had required assertions on.
"""

from __future__ import annotations

import pandas as pd

LABEL_COLS = ["sha256", "label_instance_number", "label_moment", "label_gap",
              "n_definite", "n_malicious", "n_responded"]
NULLABLE_INTS = ("label_instance_number", "n_definite", "n_malicious", "n_responded")


def label_frame(rows: list[tuple]) -> pd.DataFrame:
    """One label chunk's rows as a frame whose integer columns stay exact when NULL."""
    chunk = pd.DataFrame(rows, columns=LABEL_COLS)
    for c in NULLABLE_INTS:
        chunk[c] = chunk[c].astype("Int64")
    chunk["label_gap"] = chunk["label_gap"].astype(str).where(chunk["label_gap"].notna(), None)
    return chunk


def assert_exact_instance_numbers(df: pd.DataFrame, column: str) -> None:
    """Refuse a frame whose instance-number column could have been rounded."""
    if str(df[column].dtype) not in ("Int64", "int64"):
        raise ValueError(f"{column} is {df[column].dtype}: a 17-digit instance number does not survive float64")
