"""Snapshot reading and writing, and the manifest that makes a result traceable.

The snapshot -- not the query -- is the unit of reproducibility. Re-running a query
against a live database tomorrow returns different rows and silently invalidates every
downstream stage. See specs/04-pipeline.md.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
from pathlib import Path
from typing import Any

import pandas as pd

from .config import ESTIMAND_VERSION, settings


def _content_hash(df: pd.DataFrame) -> str:
    return hashlib.sha256(pd.util.hash_pandas_object(df, index=True).values.tobytes()).hexdigest()


def write_snapshot(df: pd.DataFrame, path: Path, *, stage: str, **meta: Any) -> Path:
    """Write a parquet plus its manifest. Refuses to overwrite: snapshots are immutable."""
    if path.exists():
        raise FileExistsError(f"{path} exists; snapshots are written once (delete it deliberately)")
    path.parent.mkdir(parents=True, exist_ok=True)
    df.to_parquet(path, index=False)
    manifest = {
        "stage": stage,
        "written_at": dt.datetime.now(dt.UTC).isoformat(),
        "estimand_version": ESTIMAND_VERSION,
        "rows": int(len(df)),
        "columns": list(df.columns),
        "content_sha256": _content_hash(df),
        "random_seed": settings.random_seed,
        **meta,
    }
    path.with_suffix(".manifest.json").write_text(json.dumps(manifest, indent=2, default=str))
    return path


def read_snapshot(path: Path) -> tuple[pd.DataFrame, dict[str, Any]]:
    """Read a parquet and its manifest, verifying the content hash still matches."""
    df = pd.read_parquet(path)
    manifest_path = path.with_suffix(".manifest.json")
    manifest = json.loads(manifest_path.read_text()) if manifest_path.exists() else {}
    if manifest.get("content_sha256") and manifest["content_sha256"] != _content_hash(df):
        raise ValueError(f"{path} has changed since its manifest was written")
    return df, manifest
