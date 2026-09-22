"""Read-only Postgres access for the extraction stage.

Postgres keeps one row per SCAN, with that scan's own assertions and analyzer output,
so "what did we know at scan N" is a keyed read. OpenSearch keeps one document per
file, overwritten, mixing epochs -- it is not usable for the feature matrix. See
specs/02-data.md.
"""

from __future__ import annotations

import pandas as pd
from sqlalchemy import create_engine

from .config import settings

#: mimetype is necessary but NOT sufficient -- WINDOWS_EXECUTABLE_MIMETYPES also admits
#: CAB, MSI, MS Access and VBE. The authoritative PE test is whether the pefile analyzer
#: succeeded: it writes {'error': 'unsupported file'} on rejection, so the presence of
#: imphash or sections is the positive test.
PE_MIMETYPES = (
    "application/x-dosexec",
    "application/vnd.microsoft.portable-executable",
    "application/x-msdownload",
)


def engine():
    if not settings.db_uri:
        raise RuntimeError("POLYSCORE_DB_URI is unset — copy .env.example to .env")
    return create_engine(settings.db_uri, pool_pre_ping=True)


def fetch_cohort() -> pd.DataFrame:
    """Pull the estimand SS1 population.

    Must include: a deterministic ORDER BY before any LIMIT (the old extraction had
    none, which is why the 2023 training set cannot be reconstructed); an upper bound
    tied to the scoring moment; feed rows excluded via scan_config; and a window ending
    at least horizon-plus-margin before today.
    """
    raise NotImplementedError("stage 01 — see specs/04-pipeline.md")
