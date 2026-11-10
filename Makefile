.PHONY: help setup lock lint test clean \
        slice force-draw force-submit force-collect pe-gate survey base extract compose compose-run draw label features split baselines train calibrate evaluate \
        all rehearsal

VENV ?= .venv
PY   ?= $(VENV)/bin/python

# ---- the run: environment variables every stage from 01b on reads (override on the command line) ----
export POLYSCORE_BASE_SNAPSHOT ?= data/base/$(WINDOW_START)_$(WINDOW_END).parquet
export POLYSCORE_RUN_ID        ?= stage-a
export POLYSCORE_COHORT_SIZE   ?= 10000
export POLYSCORE_RANDOM_SEED   ?= 1

# ---- extraction parameters: the stage rehearsal of 2026-10-05 as defaults ----
# (comments on their own lines: make keeps the spaces before an inline comment as part of the value)
# ENV names the PE gate file: stage | prod
ENV             ?= stage
KUBE_CONTEXT    ?= us-stage-blue
WINDOW_START    ?= 2024-01-01
WINDOW_END      ?= 2026-09-01
# HORIZON_MAX is read off the survey's gap_p90 on prod; 1000 kept all 32 on stage
HORIZON_MAX     ?= 1000
# the survey's artifact sample, in percent
SAMPLE_PCT      ?= 10
PE_CONFIRMED    ?= data/pe_confirmed/$(ENV)_$(WINDOW_START)_$(WINDOW_END).txt
EXTRACT_FLAGS   ?= --chunk-days 1 --timeout 1800s
# BASELINES_FLAGS=--no-gate on stage, where the feed-vs-customer gate fails by construction
BASELINES_FLAGS ?=
# CALIBRATE_FLAGS=--provisional until grade-3 labels exist
CALIBRATE_FLAGS ?= --provisional
# OVERWRITE=--overwrite to replace a stage's outputs; they are written once on purpose
OVERWRITE       ?=
# RUN=<id> makes `make compose` report that run beside the base
RUN             ?=
# the API slice (step 0): a lowercase hex sha256 prefix, pi = 16^-len; empty derives one from the seed
PREFIX          ?=
SLICE_FLAGS     ?=
# the forced-rescan run (step 0b): the slices to draw from, and the phase flags
SLICES          ?= data/api_slice/2026-09-08_2026-10-08_a1.parquet data/api_slice/2026-09-08_2026-10-08_a0.parquet
FORCE_FLAGS     ?=

help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
	  | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'
	@echo
	@echo "  run:  POLYSCORE_RUN_ID=$(POLYSCORE_RUN_ID)  POLYSCORE_COHORT_SIZE=$(POLYSCORE_COHORT_SIZE)  POLYSCORE_RANDOM_SEED=$(POLYSCORE_RANDOM_SEED)"
	@echo "  base: $(POLYSCORE_BASE_SNAPSHOT)   window $(WINDOW_START)..$(WINDOW_END)   gate $(PE_CONFIRMED)"

setup:  ## editable install with dev extras
	uv pip install -e '.[dev]'

lock:  ## regenerate the pinned lock from pyproject.toml
	uv pip compile pyproject.toml -o requirements.txt

lint:  ## ruff check + format check
	$(VENV)/bin/ruff check src pipeline tests
	$(VENV)/bin/ruff format --check src pipeline tests

test:  ## run the test suite
	$(PY) -m pytest -q tests

clean:  ## remove caches (never touches data/)
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
	rm -rf .pytest_cache .ruff_cache

# --- extraction: needs the Postgres tunnel open and kubectl pointed at $(KUBE_CONTEXT) -----------
slice:  ## step 0 (API): a sha256-prefix slice of the public metadata index and its survey; needs POLYSCORE_API_KEY
	$(PY) pipeline/00_api_slice.py --start $(WINDOW_START) --end $(WINDOW_END) $(if $(PREFIX),--prefix $(PREFIX),) \
	    --horizon-max-days $(HORIZON_MAX) $(SLICE_FLAGS) $(OVERWRITE)

force-draw:  ## step 0b.1: band the slices at T and draw the cohort to rescan (needs POLYSCORE_API_KEY from here on)
	$(PY) pipeline/00b_force_rescan.py $(OVERWRITE) draw $(foreach s,$(SLICES),--slice $(s)) --max-age-days $(HORIZON_MAX) $(FORCE_FLAGS)

force-submit:  ## step 0b.2: POST the rescans, resumably (FORCE_FLAGS=--limit 20 for a canary)
	$(PY) pipeline/00b_force_rescan.py submit $(FORCE_FLAGS)

force-collect:  ## step 0b.3: read the forced scans back; writes the base and the run cohort
	$(PY) pipeline/00b_force_rescan.py $(OVERWRITE) collect $(FORCE_FLAGS)

pe-gate:  ## step 1: the confirmed-PE hash list from OpenSearch, run inside the CLI pod
	mkdir -p data/pe_confirmed
	POD=$$(kubectl --context $(KUBE_CONTEXT) -n ai get pods -o name | grep artifact-index-cli-terminal); \
	kubectl --context $(KUBE_CONTEXT) -n ai exec -i "$$POD" -- python3 - \
	    --window-start $(WINDOW_START) --window-end $(WINDOW_END) --direct < pipeline/03_pe_confirm.py \
	    > $(PE_CONFIRMED)
	wc -l $(PE_CONFIRMED)

survey:  ## step 2: the survey over a SAMPLE_PCT sample of artifacts; pulls nothing
	$(PY) pipeline/01_extract.py --window-start $(WINDOW_START) --window-end $(WINDOW_END) \
	    --sample-pct $(SAMPLE_PCT) --survey --horizon-max-days $(HORIZON_MAX) $(EXTRACT_FLAGS)

base:  ## step 3 (01a): the base pull, feeds in, PE gate on -- rare, heavy, resumable
	$(PY) pipeline/01_extract.py --window-start $(WINDOW_START) --window-end $(WINDOW_END) \
	    --pe-confirmed $(PE_CONFIRMED) --horizon-max-days $(HORIZON_MAX) $(EXTRACT_FLAGS) $(OVERWRITE)

extract: base  ## alias of base

# --- the run: local only, from the base -----------------------------------------------------------
compose:  ## step 4: the composition table of the base (RUN=<id> adds that run's)
	$(PY) pipeline/02_compose.py $(if $(RUN),--run $(RUN),)

compose-run:  ## the composition table of $(POLYSCORE_RUN_ID)
	$(PY) pipeline/02_compose.py --run $(POLYSCORE_RUN_ID)

draw:  ## step 5 (01b): the run draw -- stratified, seeded, pi recorded; never touches the database
	$(PY) pipeline/01b_draw.py

label:  ## step 6: attach the answer column
	$(PY) pipeline/03_label.py $(OVERWRITE)

features:  ## step 7: build the feature matrix (and the control sample's)
	$(PY) pipeline/04_features.py $(OVERWRITE)

split:  ## step 8: temporal + family-grouped split, plus the random variant
	$(PY) pipeline/05_split.py $(OVERWRITE)

baselines:  ## step 9: the four baselines and the probes (BASELINES_FLAGS=--no-gate to report a failed gate instead of exiting 2)
	$(PY) pipeline/06_baselines.py $(BASELINES_FLAGS)

train:  ## step 10: the three comparisons, tuned on validate
	$(PY) pipeline/07_train.py $(OVERWRITE)

calibrate:  ## step 11: fit the calibrator and the combiner (CALIBRATE_FLAGS=--provisional until grade-3 labels)
	$(PY) pipeline/08_calibrate.py $(CALIBRATE_FLAGS)

evaluate:  ## step 12: open the test set, once -- deliberately not part of `all`
	$(PY) pipeline/09_evaluate.py

all: draw compose-run label features split baselines train calibrate  ## one run end to end from an existing base, stopping before evaluate
	@echo
	@echo "Deliberately stopping before evaluate: the test set is opened once, by hand, with 'make evaluate'."

rehearsal: pe-gate survey base compose all  ## the stage rehearsal of 2026-10-05, start to finish (tunnel open; then 'make evaluate')
