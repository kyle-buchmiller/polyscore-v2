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
