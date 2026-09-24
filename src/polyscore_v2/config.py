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

#: Bumped whenever specs/01-estimand.md sections 1-9 change. Stamped onto every
#: artefact a stage writes, so a result can always be traced to the rules it was
#: produced under.
#:
#: 1 -> 2 (2026-09-24): added SS9 sampling design and the per-artifact counting rule
#: in SS1. See decisions/0006. No results were produced under version 1.
ESTIMAND_VERSION = 2

#: --- estimand SS9: sampling design -------------------------------------------
#: Target share of the draw per stratum, keyed by the name stage 01 writes into the
#: ``stratum`` column. Bands are cut on m = malicious assertions / engines that
#: answered, evaluated at the scoring moment. These are targets for the *draw*, not
#: claims about the world: stage 02 reports realized shares against them, and a band
#: that under-fills is a reported shortfall, never back-filled from a neighbour.
STRATUM_TARGETS: dict[str, float] = {
    "contested": 0.45,            # CONTESTED_LOWER < m < CONTESTED_UPPER -- over-represented on purpose
    "leaning_malicious": 0.15,    # CONTESTED_UPPER <= m < 1.0
    "leaning_clean": 0.15,        # 0 < m <= CONTESTED_LOWER
    "consensus_malicious": 0.10,  # m == 1.0
    "consensus_clean": 0.10,      # m == 0
    "injected_known_good": 0.05,  # not drawn -- externally sourced, excluded from prevalence
}

#: Band edges on m. Both were chosen before anyone looked at how the bands populate;
#: revisit once against stage 02's report (specs/99-open-questions.md).
CONTESTED_LOWER = 0.2
CONTESTED_UPPER = 0.8

#: Below this many *answering* engines m is noise -- one verdict moves it by 0.5 at
#: two engines. Such artifacts form their own stratum rather than joining a band.
#: None means "not yet set": stage 02 produces the answer-count distribution this
#: needs, and a guessed floor silently reshapes the draw. Distinct from the coverage
#: tier in specs/06-signals.md, which counts signal families, not engine responses.
MIN_ANSWERING_ENGINES: int | None = None

#: Stage 06 rejects the draw above this. A classifier that can predict ``provenance``
#: from the feature set is identifying the upload batch rather than the file.
PROVENANCE_PROBE_MAX_AUC = 0.6

#: Columns never mixed into a prevalence estimate: the injection arm has no inclusion
#: probability by construction, so 1/pi is undefined for it.
INJECTED_PROVENANCE = "injected_known_good"

if abs(sum(STRATUM_TARGETS.values()) - 1.0) > 1e-9:  # pragma: no cover - import-time guard
    raise ValueError(
        f"STRATUM_TARGETS must sum to 1.0, got {sum(STRATUM_TARGETS.values())} "
        f"(estimand SS9; a draw over shares that do not sum to 1 is not a draw)"
    )


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
