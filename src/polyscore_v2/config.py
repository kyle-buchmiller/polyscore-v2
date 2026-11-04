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

#: Bumped whenever specs/01-estimand.md sections 1-11 change; stamped onto every artefact
#: a stage writes, so a result can always be traced to the rules it was produced under.
#: The change log is the version table at the foot of specs/01-estimand.md
ESTIMAND_VERSION = 6

#: --- estimand SS9: sampling design -------------------------------------------
#: Target share of the draw per stratum, keyed by the name stage 01 writes into the
#: ``stratum`` column. Bands are cut on m = malicious assertions / engines that
#: answered, evaluated at the scoring moment. These are targets for the *draw*, not
#: claims about the world: stage 02 reports realized shares against them, and a band
#: that under-fills is a reported shortfall, never back-filled from a neighbour.
STRATUM_TARGETS: dict[str, float] = {
    "contested": 0.45,            # CONTESTED_LOWER < m < CONTESTED_UPPER -- over-represented on purpose
    "leaning_malicious": 0.15,    # CONTESTED_UPPER <= m < CONSENSUS_MALICIOUS
    "leaning_clean": 0.15,        # 0 < m <= CONTESTED_LOWER
    "consensus_malicious": 0.10,  # m >= CONSENSUS_MALICIOUS
    "consensus_clean": 0.10,      # m == 0
    "injected_known_good": 0.05,  # not drawn -- externally sourced, excluded from prevalence
}

#: Band edges on m. Unanimity is unreachable on this roster: a benign verdict is mostly
#: the absence of a signature, so m tops out near 0.85 at full coverage and consensus
#: starts at half. Set by judgement, not measurement: see decisions/0012-band-edges-halved.md
CONTESTED_LOWER = 0.1
CONTESTED_UPPER = 0.4
CONSENSUS_MALICIOUS = 0.5

#: Below this many *answering* engines m is noise (one verdict moves it by 0.5 at two);
#: provisional at two thirds of the median coverage of 15, until the prod survey reports
#: the answer-count distribution. see specs/01-estimand.md § 9 · Sampling design
MIN_ANSWERING_ENGINES: int | None = 10

#: Stage 06 rejects the draw above this. A classifier that can predict ``provenance``
#: from the feature set is identifying the upload batch rather than the file.
PROVENANCE_PROBE_MAX_AUC = 0.6
#: PROVISIONAL (decisions/0011, Proposed): the fewest definite verdicts at the label scan
#: for a grade-1 label to be issued at all. Below it the row is `undecidable/below_floor`.
LABEL_MIN_DEFINITE = 5

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
    # The frame the probability is ABOUT, and the frame the calibrator is fitted on.
    # NOT the frame the model trains on -- that is SS10 and it is broader. See 0008.
    window_start: dt.date = dt.date(2026, 9, 8)  # post-indexing-fix, see specs/02-data.md
    window_end: dt.date | None = None
    community: str = "public"

    #: Feeds are excluded from the REFERENCE population only. Setting this False would
    #: put feed rows in the calibration denominator, which is how the base rate starts
    #: tracking how many feed contracts are switched on rather than anything about a
    #: file. Stage 08 honours it; stage 01 must not.
    reference_excludes_feeds: bool = True  # scan_config = 'feed'

    # --- estimand SS10: training population ---------------------------------
    #: The model may learn from the whole store, feeds included. True here means stage
    #: 01 draws across provenances and stage 06's probe is what keeps it honest;
    #: flipping it False narrows training back to SS1 and forfeits the contested band,
    #: which the customer-submitted frame is too thin to fill.
    train_on_feeds: bool = True

    # --- estimand SS4: horizon ----------------------------------------------
    horizon_days: int = 30
    churn_recheck_days: int = 180
    #: Upper bound on the TRAINING arm's natural label gap. T+30 is a target, not a
    #: floor: a label at T+400 carries an order of magnitude more accrual than one at
    #: T+31. Set from the gap distribution stage 02 reports; 90 is the placeholder.
    #: The VALIDATION arm is forced to ~30 and does not use this. See decisions/0010.
    horizon_max_days: int = 90

    # --- estimand SS11: scale and reproducibility ---------------------------
    #: THE scaling knob. 10k for the pilot; 1M+ is the same pipeline with this changed.
    #: A run draw takes this many artifacts from the base snapshot, stratified per SS9.
    cohort_size: int = 10_000
    #: Which base snapshot a run draws from. A run never touches the database -- that
    #: is what makes it quick, concurrent, and reproducible. Set to the base's path.
    base_snapshot: Path | None = None
    #: A base pulled by older extraction SQL is refused by 01b_draw unless this is
    #: set. The 25-row stage rehearsal base ran through five stability runs and stage 02
    #: after decision 0010 had changed the population under it, and nothing said so.
    allow_stale_base: bool = False
    #: Isolates every artifact a run writes under data/runs/<run_id>/. Two runs with
    #: the same base and seed must produce byte-identical files; this is how that is
    #: checked rather than assumed.
    run_id: str = "default"
    #: How many seeds the process-stability measurement runs. Their disagreement on the
    #: shared validation set is the noise floor a reported improvement must clear (SS8).
    stability_runs: int = 5
    #: Size of the forced-rescan VALIDATION arm. Small on purpose: it answers one
    #: question -- does a model trained on selected natural rescans hold on unselected
    #: forced ones -- and waits 30 days once.
    validation_size: int = 2_000
    #: The control sample 01a sets aside for the rescan probe (estimand SS4): a seeded draw
    #: of frame artifacts with NO natural later scan, T assertions only, never trained on.
    control_size: int = 10_000

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
