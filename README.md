# polyscore-v2

A rebuild of PolySwarm's PolyScore as a **calibrated probability**: of all files we
score near 0.40, drawn from a named reference population, about 40% are
independently adjudicated malicious within 30 days of first sighting.

That sentence is the whole point. Every design choice in this repo exists to make
it *true* and *checkable*. The current production model cannot support it — its
labels are derived from its own inputs, so nothing it reports can be interpreted.

## Status

Pilot. The first milestone is a 10,000-file Windows-PE run whose purpose is to
walk the process end to end and measure where the real constraints are. **It is
not expected to produce a deployable model**, and that is not failure: a pilot
that ends with "the labels are the bottleneck, here is the number that proves it"
has succeeded completely.

## Start here

1. [`AGENTS.md`](./AGENTS.md) — conventions, layout, how to work in this repo.
2. [`specs/00-overview.md`](./specs/00-overview.md) — what this is and how the pieces fit.
3. [`specs/01-estimand.md`](./specs/01-estimand.md) — **the frozen decisions.** Read before writing code.
4. [`decisions/`](./decisions/) — why things are the way they are.

Two diagrams render the pipeline and the serving path: [**Build and Serve**](https://claude.ai/artifact/EHDK37N6ZgJ8EjpHaa5wKZ).
The specs are authoritative; the diagrams follow them.

## Layout

```
specs/       design contracts — authoritative on intent
             (07-requests.md: what we need from other teams)
             (08-future-work.md: what success unlocks later)
decisions/   dated decision records — authoritative on why
pipeline/    the nine numbered stages, run in order
src/         shared code the stages import
tests/       guards against the failure modes in specs/05
data/        snapshots and outputs (gitignored)
```

## Setup

This repo follows the workspace `python` environment convention: a `.venv` at the
repo root created with `uv`, activated by direnv.

```bash
sam setup polyscore-v2          # writes .envrc, creates .venv
uv pip install -e '.[dev]'      # dependencies, editable install
cp .env.example .env            # then fill in the connection strings
```

`pyproject.toml` is the authoritative dependency list. To refresh the pinned
lock:

```bash
make lock                       # uv pip compile pyproject.toml -o requirements.txt
```

## Running the pipeline

Each stage reads the previous stage's output and writes its own, so any stage can
be re-run without redoing the ones before it.

```bash
make extract     # 01 — pull the cohort, freeze a snapshot
make compose     # 02 — print the composition table, then READ IT
make label       # 03 — attach the answer column (needs the horizon to have elapsed)
make features    # 04 — build the feature matrix, as-of enforced
make split       # 05 — temporal + family-grouped split
make baselines   # 06 — the four baselines, BEFORE any model
make train       # 07 — three comparisons
make calibrate   # 08 — fit the calibrator and combiner (fits; changes the model)
make evaluate    # 09 — open the test set, once (measures; fits nothing)
```

Stage 06 is the most informative half hour in the project. If the
malicious-engine-count baseline comes back above ~0.97 AUC, the labels are a
restatement of the features and nothing downstream can measure anything — stop
there and fix the labels.
