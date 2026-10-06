# polyscore-v2

A rebuild of PolySwarm's PolyScore as a **calibrated probability**: of all files we
score near 0.40, drawn from a named reference population, about 40% are
independently adjudicated malicious within 30 days of first sighting.

That sentence is the whole point. Every design choice in this repo exists to make
it *true* and *checkable*. The current production model cannot support it — its
labels are derived from its own inputs, so nothing it reports can be interpreted.

## What the number is made of

PolyScore ships as **one number**, because some customer integrations can only read
one field and act on it. That constraint is real, so the design takes it seriously
rather than arguing with it.

But that one number is a **composite**, blended from two different kinds of evidence:

| Input | What it is | Order |
|---|---|---|
| **Base probability** | an ML model over engine verdicts — who said what, how independent they are, how specific the family names were | second-order: opinions *about* the file |
| **Signals** | facts read from the artifact itself — Authenticode chain state, section entropy, packing, sandbox behaviour | first-order: properties *of* the file |

The model alone can never express "this binary is signed with a stolen certificate,"
because it only ever sees what engines said. Signals are how such a fact reaches the
score at all — which is what leadership asked for when they asked that other factors
be able to push PolyScore up.

```
engine evidence ──► base model ──► raw score ──┐
                                               ├─► COMBINER ──► coverage gate ──► polyscore
signature signals ─────────────────────────────┤   (small,      (may refuse       + status
sandbox signals ───────────────────────────────┘    fitted)      to answer)       + components
```

### The invariant that keeps it a probability

**Composition is fitted, never asserted.** Every signal contributes `logit += w`, where
`w` was fitted against observed outcomes. Never `score × k` followed by a clamp.

This is not fussiness. Multiplying and clamping is exactly how the incumbent produces
its most embarrassing output: a category multiplier takes a container whose files are
*all clean* from 0.3346 to 1.338, clamps it to **1.0 — maximum risk**. Clamping is the
moment a probability stops being one. Adding fitted weights in log-odds cannot saturate
that way, because the arithmetic is closed over probabilities.

### Two properties that fall out of doing it this way

**It can refuse to answer.** The coverage gate is what finally retires the 0.3346
constant — the value the old model emits when it knows nothing, rendered to customers in
a coloured UI as though it were a finding. A composite with a gate can say
*insufficient evidence* instead of inventing a number.

**It is exactly explainable.** Because the combiner is small and linear in log-odds,
each input's contribution *is* `coefficient × value` — arithmetic, not a SHAP-style
approximation over a large ensemble. "Why is this 0.72?" has one exact answer, and that
exactness is the reason to keep the combiner small. Customers who want the headline
number get it; customers who want to drill in get a real decomposition.

### Where this honestly stands

No independently adjudicated labels exist yet, so the combiner's weights are currently
**expert-set rather than fitted**. That is a deliberate interim posture, not an
oversight ([`0005`](./decisions/0005-composite-polyscore-via-a-fitted-combiner.md)):
weights are written in log-odds so the eventual refit is a parameter change rather than
a rebuild, and any score produced this way must carry `calibration: provisional`.

The ranking number people ask for — "where does this sit in my queue?" — is a percentile
of the finished PolyScore over a named cohort. It is **downstream of everything above**
and is not built ([`08-future-work.md`](./specs/08-future-work.md) F1). A probability can
always be turned into a rank; a rank can never be turned back into a probability.

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
4. [`specs/06-signals.md`](./specs/06-signals.md) — the signal vocabulary and the combiner contract.
5. [`decisions/`](./decisions/) — why things are the way they are.

Two diagrams render the pipeline and the serving path: [**Build and Serve**](https://claude.ai/artifact/EHDK37N6ZgJ8EjpHaa5wKZ).
The specs are authoritative; the diagrams follow them.

## Layout

```
specs/       design contracts — authoritative on intent
             (07-requests.md: what we need from other teams)
             (08-future-work.md: what success unlocks later)
             (09-extraction-runbook.md: how to actually run stage 01)
             (10/11: Estimand B — the aged-artifact comparison arm, proposed)
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
be re-run without redoing the ones before it. Every stage is a `make` target, and
`make help` prints them with the run's current settings. The targets fall into two
groups: **extraction**, which needs the Postgres tunnel and `kubectl`, and **the
run**, which reads only local files.

```bash
# extraction (tunnel open, kubectl pointed at $KUBE_CONTEXT)
make pe-gate     # step 1 — the confirmed-PE hash list from OpenSearch, inside the CLI pod
make survey      # step 2 — the survey over a SAMPLE_PCT sample of artifacts; pulls nothing
make base        # step 3 — 01a: the base pull, feeds in, PE gate on — rare, heavy, resumable

# the run — local only, from an existing base
make compose     # step 4 — the composition table of the base (RUN=<id> adds a run's)
make draw        # step 5 — 01b: the stratified, seeded draw; pi recorded; never touches the database
make label       # step 6 — attach the answer column
make features    # step 7 — the feature matrix (and the control sample's)
make split       # step 8 — temporal + family-grouped split, plus the random variant
make baselines   # step 9 — the four baselines and the probes (BASELINES_FLAGS=--no-gate to report, not exit)
make train       # step 10 — the three comparisons, tuned on validate
make calibrate   # step 11 — the calibrator and combiner (CALIBRATE_FLAGS=--provisional until grade-3 labels)
make evaluate    # step 12 — open the test set, once; deliberately NOT part of `all`

make all         # draw … calibrate: one run end to end from an existing base
make rehearsal   # pe-gate survey base compose all: the stage run of 2026-10-05, start to finish
```

The run is named by four environment variables every stage from 01b on reads, and
the extraction by a handful of make variables; all have the stage rehearsal's values
as defaults and are overridden on the command line:

| Variable | Default | Names |
|---|---|---|
| `POLYSCORE_RUN_ID` | `stage-a` | the directory under `data/runs/` everything a run writes goes to |
| `POLYSCORE_COHORT_SIZE` | `10000` | **the** scaling knob — 10k or 1M, nothing else changes |
| `POLYSCORE_RANDOM_SEED` | `1` | same base + same seed ⇒ byte-identical run |
| `POLYSCORE_BASE_SNAPSHOT` | `data/base/<window>.parquet` | which base the run draws from |
| `WINDOW_START` / `WINDOW_END` | `2024-01-01` / `2026-09-01` | the extraction window |
| `HORIZON_MAX` | `1000` | the label-gap bound; read off the survey's `gap_p90` on prod |
| `SAMPLE_PCT` | `10` | the survey's artifact sample |
| `ENV`, `KUBE_CONTEXT` | `stage`, `us-stage-blue` | the PE gate file's name, and where `pe-gate` runs |
| `BASELINES_FLAGS`, `CALIBRATE_FLAGS`, `OVERWRITE` | `""`, `--provisional`, `""` | the flags the stages explain |

```bash
make all BASELINES_FLAGS=--no-gate POLYSCORE_RUN_ID=stage-b     # a second run from the same base
make evaluate POLYSCORE_RUN_ID=stage-b
```

Two things worth knowing. **Outputs are written once**: a target re-run over an
existing output refuses, and `OVERWRITE=--overwrite` is the deliberate exception.
And **it is the same output, not a similar one**: on 2026-10-06, `make all` +
`make evaluate` into `stage-b` reproduced the hand-run `stage-a` byte for byte — every
parquet identical by content hash, every report identical once run id and timestamp
are set aside. That is estimand §11's determinism check, and `make` is only another
way to type the commands. The hand-run form, with what each step does and how to tell
it worked, is step by step in
[`specs/09-extraction-runbook.md`](./specs/09-extraction-runbook.md) and in the pilot
write-up's *Sample stage rehearsal* section.

Stage 06 is the most informative half hour in the project. If the
malicious-engine-count baseline comes back above ~0.97 AUC, the labels are a
restatement of the features and nothing downstream can measure anything — stop
there and fix the labels.
