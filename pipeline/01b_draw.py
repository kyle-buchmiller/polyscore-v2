#!/usr/bin/env python3
"""Stage 01b — the run draw: a stratified cohort from the base snapshot, locally.

THIS STAGE NEVER TOUCHES THE DATABASE. It reads the base Parquet that 01a produced and
draws `settings.cohort_size` artifacts stratified per estimand SS9, seeded by
`settings.random_seed`, recording pi per row. That is what makes:

    scaling        a change to POLYSCORE_COHORT_SIZE and nothing else
    retraining     seconds, not a replica query
    concurrency    free -- N runs read one immutable file
    reproducibility a true sentence: same base + same seed => byte-identical cohort

Reads : settings.base_snapshot  (data/base/<window>.parquet + manifest)
Writes: data/runs/<run_id>/cohort.parquet + manifest.json

The stratum is computed HERE from n_malicious / n_definite with the edges in config,
not read from the base. The base is edge-agnostic so that revising the bands after
stage 02 reports on them does not require a re-pull; the manifest records which edges
this run used.

pi per row is n_draw / n_available for the row's stratum, over the BASE's band
populations. pi_base is 1 by construction (the base is a full pull), so pi_run equals
this value. It is the irreplaceable column -- see estimand SS9.

The manifest carries: base content hash, seed, cohort size, estimand version, band
edges, horizon_max_days, per-stratum n_available / n_draw, and whether any stratum
under-filled. Under-fill is REPORTED, never back-filled from a neighbouring band.

Contract: specs/04-pipeline.md stage 01b, decisions/0010.
"""

from __future__ import annotations

from polyscore_v2.config import settings
from polyscore_v2.logging_setup import configure

log = configure()


def main() -> None:
    raise NotImplementedError("stage 01b — see specs/04-pipeline.md and decisions/0010")


if __name__ == "__main__":
    main()
