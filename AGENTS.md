# AGENTS.md — polyscore-v2

Orientation document for AI agents and humans new to the repo. Update it when major
workflow decisions land.

This file covers the layout, conventions, and the invariants that are easy to break.
**Detailed contracts and per-area design live under [`specs/`](./specs/)** — read the
relevant spec before changing the corresponding code, and update the spec in the same
PR. If a PR drifts from a spec, the spec is wrong until proven otherwise.

## Reading order for a new contributor

1. This file — layout, conventions, the invariants.
2. [`specs/00-overview.md`](./specs/00-overview.md) — what this repo is for and how the pieces fit.
3. [`specs/01-estimand.md`](./specs/01-estimand.md) — **the frozen decisions.** Nothing here is interpretable without them.
4. The spec for the area you are changing.
5. [`decisions/`](./decisions/) — dated records of why things are the way they are.

Two diagrams render the above and are useful for orientation:
[**Build and Serve**](https://claude.ai/artifact/EHDK37N6ZgJ8EjpHaa5wKZ) — the training pipeline with every technology slot named, and
the serving path from upload to a composed PolyScore. **The specs are authoritative; the
diagrams are a rendering.** When a stage or a signal changes, change the spec first and
treat the diagram as stale until it catches up.

If you own a platform repo and landed here because PolyScore asked you for something, [`specs/07-requests.md`](./specs/07-requests.md) is the page you want.

## Specs index

| Spec | Scope |
|---|---|
| [`specs/00-overview.md`](./specs/00-overview.md) | What this repo ships, where it sits, repo layout |
| [`specs/01-estimand.md`](./specs/01-estimand.md) | The ten frozen decisions: reference population, scoring moment, label, horizon, split, metric, baselines, decision rule, sampling design, training population |
| [`specs/02-data.md`](./specs/02-data.md) | What is collected, from which source, and the as-of rule |
| [`specs/03-labels.md`](./specs/03-labels.md) | Label taxonomy, grades, and how the pilot's labels are derived |
| [`specs/04-pipeline.md`](./specs/04-pipeline.md) | The nine stages, their contracts, and what each writes |
| [`specs/05-evaluation.md`](./specs/05-evaluation.md) | Metrics, baselines, the look-once rule, the standing controls |
| [`specs/06-signals.md`](./specs/06-signals.md) | Signal vocabulary, presence semantics, coverage tiers, and the combiner contract |
| [`specs/07-requests.md`](./specs/07-requests.md) | Capabilities other teams own that PolyScore needs — outward-facing |
| [`specs/08-future-work.md`](./specs/08-future-work.md) | Work unlocked *by* a successful retrain — the ranking number, per-type calibrators, scope expansion |
| [`specs/99-open-questions.md`](./specs/99-open-questions.md) | Known follow-ups and unresolved questions |

Specs follow a strict convention: each opens with **Scope** and **Invariants**, is
independently readable, and names the files and symbols it talks about.

## The four invariants

Everything else is a preference. These three are what the repo exists to protect, and
each corresponds to a specific way the 2023 model was destroyed.

**1 · The as-of rule.** Every feature must be true at or before the scoring moment.
The label comes from the future by construction; if a feature does too, the model
learns to cheat, scores brilliantly in testing, and fails in production. This is
enforced mechanically in `src/polyscore_v2/features.py`, not by discipline, and
`tests/test_asof.py` is the guard. Do not add a feature that bypasses it.

**2 · Labels never come from the features.** The 2023 model's answer column was a
threshold on the same engine verdicts that were its inputs, so a model that perfectly
reproduced the vote count would have scored flawlessly and known nothing. Label grades
are defined in `specs/03-labels.md`; grade 0 is banned outright and grade 1 may train
but never calibrate.

**3 · The test split is opened once.** After a look, any change makes it a tuning set.
Only `pipeline/09_evaluate.py` reads it. Access is logged; if the count exceeds two,
the count is printed next to the metric.

**4 · Composition is fitted, never asserted.** `polyscore` is the output of a small
combiner over the base score plus signals. Its coefficients are *fitted artefacts with a
version*, changed by refitting on data and reviewed like any model promotion. Editing a
coefficient in place to chase a complaint turns the score back into a hand-tuned
aggregate — which is where it started. See `specs/06-signals.md`.

## Layout

```
specs/                   design contracts — authoritative on intent
decisions/               dated decision records — authoritative on why
pipeline/01..08_*.py     the numbered stages, runnable, one job each
src/polyscore_v2/        shared code the stages import
tests/                   guards, not coverage theatre
data/                    snapshots and outputs (gitignored, reproducible)
```

Stages are **numbered scripts, not a package**, because they are run in order by a
human who is watching the output. Shared logic belongs in `src/polyscore_v2/` so the
stages stay thin; a stage that grows real logic should push it down into the package
and keep the orchestration.

### There is deliberately no `notebooks/`

The pipeline being replaced was a CLI plus notebooks plus a hand-run query, which is
why nobody can reproduce what the 2023 model was trained on. Exploration in a notebook
is fine; **a result that matters gets a stage or a test.** If a notebook directory
appears here, it should come with a spec saying what keeps it from becoming the source
of truth again.

## Conventions

**Configuration** is environment variables only, loaded through
`src/polyscore_v2/config.py`. Never hardcode a connection string, a path, or a date
window in a stage. See `.env.example`.

**Logging** is JSON by default, controlled by `LOG_LEVEL` and `LOG_FORMAT`, matching
the workspace standard.

**Randomness** is seeded from `POLYSCORE_RANDOM_SEED` and threaded explicitly. An
unseeded split is how you get a number you cannot reproduce or defend.

**Comments state facts in a line or two; design rationale lives in the spec** and is
referenced, not restated.

**Commits** are small, meaningful, and conventionally prefixed (`feat:`, `fix:`,
`docs:`, `spec:`, `chore:`). No AI attribution trailers.

## Gitflow

Simple, for now: feature branches off `main`, PR into `main`. The repo currently lives
at `kyle-buchmiller/polyscore-v2` and has no CI.

If and when this moves into the `polyswarm` org, three things follow and should be
done deliberately rather than discovered:

- adopt the shared GitLab CI template (`e2e/.gitlab-ci-default.yaml`) per the workspace
  project standards;
- add the repo to `sam.yaml` with `setup: python` so `sam sync` manages it;
- revisit which org standards apply — see below.

## Which org standards apply here

The workspace standards in `devenv/specs/05-project-standards.md` are written for
deployed services. This is an offline training pipeline, so most do not apply *yet*.
Stating which is which prevents both cargo-culting and silent drift.

| Standard | Applies? |
|---|---|
| Runtime config via env vars | **yes**, now |
| JSON logging, `LOG_LEVEL` / `LOG_FORMAT` | **yes**, now |
| Comments vs specs | **yes**, now |
| Shared CI template + e2e | on move to the org |
| Storage via `psstorage`, never direct S3 | when it reads artifacts from storage |
| Admin CLI, k8s CronJobs | when retraining becomes scheduled |
| Helm chart, components pattern | when a serving path exists |
| Celery / RabbitMQ, AKM, two-cluster, at-least-once | not applicable to an offline pipeline |
