"""One run's files, and the checks that keep a stage from reading the wrong ones.

A run lives under data/runs/<run_id>/ (estimand SS11): the cohort 01b drew, then what
each later stage adds beside it. Every stage reads through here so the cohort-to-base
linkage is verified once, the same way, and an output is never silently overwritten.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

import pandas as pd

from .config import settings
from .io import read_snapshot


@dataclass(frozen=True)
class Run:
    run_id: str
    dir: Path
    cohort: pd.DataFrame
    cohort_manifest: dict
    base: pd.DataFrame
    base_manifest: dict
    assertions: pd.DataFrame


def load_run(run_id: str | None = None) -> Run:
    """The cohort, the base it was drawn from, and that base's assertions -- verified.

    The cohort manifest records the base's content hash; the base's own manifest is
    verified by read_snapshot; the two are compared here. A cohort drawn from one base
    and labelled against another would be wrong in no way a later stage could see.
    """
    run_id = run_id or settings.run_id
    run_dir = settings.path("runs", run_id)
    cohort, cm = read_snapshot(run_dir / "cohort.parquet")
    # The manifest names the base by path; POLYSCORE_BASE_SNAPSHOT may point at it after a
    # move. The content hash below is what proves it is the same base, not the path.
    base_path = Path(settings.base_snapshot) if settings.base_snapshot else Path(cm["base_snapshot"])
    base, bm = read_snapshot(base_path)
    if bm.get("content_sha256") != cm.get("base_content_sha256"):
        raise SystemExit(f"run {run_id} was drawn from a base other than {base_path} "
                         f"(cohort manifest {str(cm.get('base_content_sha256'))[:12]}, "
                         f"base manifest {str(bm.get('content_sha256'))[:12]})")
    assertions = pd.read_parquet(base_path.with_suffix(".assertions.parquet"))
    return Run(run_id, run_dir, cohort, cm, base, bm, assertions)


def fresh(path: Path, overwrite: bool) -> Path:
    """Make `path` writable by write_snapshot: refuse if it exists, unless told to replace it."""
    manifest = path.with_suffix(".manifest.json")
    if path.exists() or manifest.exists():
        if not overwrite:
            raise SystemExit(f"{path} exists; outputs are written once -- pass --overwrite to replace it")
        path.unlink(missing_ok=True)
        manifest.unlink(missing_ok=True)
    return path


def read_manifest(path: Path) -> dict:
    return json.loads(path.with_suffix(".manifest.json").read_text())
