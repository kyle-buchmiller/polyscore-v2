.PHONY: help setup lock lint test clean \
        extract compose label features split baselines train calibrate evaluate all

PY := python

help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
	  | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

setup:  ## editable install with dev extras
	uv pip install -e '.[dev]'

lock:  ## regenerate the pinned lock from pyproject.toml
	uv pip compile pyproject.toml -o requirements.txt

lint:  ## ruff check + format check
	ruff check src pipeline tests
	ruff format --check src pipeline tests

test:  ## run the test suite
	pytest tests -v

clean:  ## remove caches (never touches data/)
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
	rm -rf .pytest_cache .ruff_cache

# --- pipeline stages, in order ----------------------------------------------
extract:    ## 01 pull the cohort and freeze a snapshot
	$(PY) pipeline/01_extract.py
compose:    ## 02 print the composition table
	$(PY) pipeline/02_compose.py
label:      ## 03 attach the answer column
	$(PY) pipeline/03_label.py
features:   ## 04 build the feature matrix
	$(PY) pipeline/04_features.py
split:      ## 05 temporal + grouped split
	$(PY) pipeline/05_split.py
baselines:  ## 06 the four baselines, before any model
	$(PY) pipeline/06_baselines.py
train:      ## 07 the three comparisons
	$(PY) pipeline/07_train.py
calibrate:  ## 08 fit the calibrator and the combiner
	$(PY) pipeline/08_calibrate.py
evaluate:   ## 09 open the test set, once
	$(PY) pipeline/09_evaluate.py

all: extract compose label features split baselines train calibrate  ## everything except evaluate
	@echo
	@echo "Deliberately stopping before 09_evaluate."
	@echo "The test set is opened once, by hand, after model + calibrator + combiner are frozen."
