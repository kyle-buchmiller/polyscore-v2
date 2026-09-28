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

#: mimetype is necessary but NOT sufficient -- WINDOWS_EXECUTABLE_MIMETYPES has nine
#: values and four are not PE (CAB, MSI in three spellings, MS Access, VBE), and
#: x-dosexec covers plain MZ/DOS binaries too. These three are the PE-bearing subset,
#: used as a cheap pre-filter only.
PE_MIMETYPES = (
    "application/x-dosexec",
    "application/vnd.microsoft.portable-executable",
    "application/x-msdownload",
)

#: The authoritative PE test is whether the pefile analyzer succeeded, and it must be
#: asked of OpenSearch rather than Postgres. Three reasons, in descending order of how
#: badly each one bites:
#:
#: 1. OUT-OF-LINE STORAGE. artifactmetadata.tool_metadata is a hybrid property with a
#:    size switch: documents at or above AI_METADATA_OUT_OF_LINE_SIZE go to psstorage
#:    and leave the column NULL. us-prod sets that threshold to 2000. A real parsed-PE
#:    document is far larger; the 32-byte rejection doc {"error": "unsupported file"} is
#:    always inline. So `tool_metadata ? 'imphash'` returns a set SKEWED TOWARD
#:    REJECTIONS -- the exact opposite of the intended filter.
#: 2. `sections` is not a valid positive: it is initialised to [] and filled inside a
#:    broad try/except, so a genuinely parsed PE can carry sections: [].
#: 3. get_imphash() returns "" for a PE with no import table, so any test must be key
#:    PRESENCE, never truthiness.
#:
#: In OpenSearch a rejected pefile document is stripped to {} and removed, so
#: `exists: pefile.imphash` is exact. Taking it from ES is safe here and only here,
#: because the test is TIME-INVARIANT -- a file's bytes do not change, so whether the
#: parser handled them cannot drift. Nothing time-varying may come from ES.
PE_CONFIRM_FIELD = "pefile.imphash"


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
