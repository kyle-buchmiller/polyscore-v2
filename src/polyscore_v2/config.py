"""Runtime configuration — environment variables only (workspace standard).

The frozen decisions in ``specs/01-estimand.md`` appear here as defaults so a stage
cannot silently disagree with the spec. Changing one of these is an estimand change:
bump ESTIMAND_VERSION and record it in ``decisions/``.
"""

from __future__ import annotations

import datetime as dt
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

#: Bumped whenever specs/01-estimand.md sections 1-8 change. Stamped onto every
#: artefact a stage writes, so a result can always be traced to the rules it was
#: produced under.
ESTIMAND_VERSION = 1


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="POLYSCORE_", env_file=".env", extra="ignore")

    # --- data sources -------------------------------------------------------
    db_uri: str = ""
    firehose_dir: Path | None = None
    data_dir: Path = Path("./data")

    # --- estimand SS1: reference population ---------------------------------
    window_start: dt.date = dt.date(2026, 9, 8)  # post-indexing-fix, see specs/02-data.md
    window_end: dt.date | None = None
    exclude_feed_rows: bool = True  # scan_config = 'feed'
    community: str = "public"

    # --- estimand SS4: horizon ----------------------------------------------
    horizon_days: int = 30
    churn_recheck_days: int = 180

    # --- estimand SS5: split ------------------------------------------------
    train_frac: float = 0.60
    validate_frac: float = 0.15
    # test is the remainder, and is opened once -- see specs/05-evaluation.md

    # --- labelling (specs/03-labels.md) -------------------------------------
    min_independent_clusters: int = 3
    heuristic_family_discount: float = 0.5

    # --- reproducibility ----------------------------------------------------
    random_seed: int = 20260922

    # --- logging ------------------------------------------------------------
    log_level: str = Field(default="INFO", alias="LOG_LEVEL")
    log_format: str = Field(default="json", alias="LOG_FORMAT")

    def path(self, *parts: str) -> Path:
        """Return a path under data_dir, creating parent directories."""
        p = self.data_dir.joinpath(*parts)
        p.parent.mkdir(parents=True, exist_ok=True)
        return p


settings = Settings()
