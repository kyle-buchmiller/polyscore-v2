"""The public-API source: a sha256-prefix slice of the metadata index, paged politely.

A hex prefix is a uniform sample the server applies for us (sha256 is uniform), so a
slice needs no enumeration and carries an exact inclusion probability. What a document
can and cannot say about a scan: see specs/12-api-slice-pilot.md.
"""

from __future__ import annotations

import json
import logging
import random
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Iterator, Sequence
from dataclasses import dataclass, field
from pathlib import Path

import pandas as pd

from .config import settings

log = logging.getLogger("polyscore_v2.api_source")

PE_GATE = "pefile.imphash:*"
_HEX = frozenset("0123456789abcdef")

#: The slice's projection. `artifact.*` always comes along (the server adds it); the two
#: scan sub-documents are the only per-scan facts the index holds.
SLICE_INCLUDE: tuple[str, ...] = (
    "scan.first_scan.created",
    "scan.first_scan.artifact_instance_id",
    "scan.first_scan.detections",
    "scan.first_scan.polyscore",
    "scan.first_scan.assertions",
    "scan.latest_scan.created",
    "scan.latest_scan.artifact_instance_id",
    "scan.latest_scan.detections",
    "scan.latest_scan.polyscore",
    "scan.latest_scan.assertions",
    "scan.mimetype",
)


class ApiError(RuntimeError):
    """A non-retryable answer, or retries exhausted. Never carries the key or a URL with it."""


def inclusion_probability(prefix: str) -> float:
    return 16.0 ** -len(prefix)


def slice_query(prefix: str, start: str, end: str, *, pe_gate: bool = True) -> str:
    """The Lucene query of one slice: first scan in [start, end), sha256 under `prefix`."""
    if not prefix or set(prefix) - _HEX:
        raise ValueError(f"prefix must be lowercase hex, got {prefix!r}")
    parts = [f"scan.first_scan.created:[{start} TO {end}}}", f"artifact.sha256:{prefix}*"]
    if pe_gate:
        parts.insert(0, PE_GATE)
    return " AND ".join(parts)


@dataclass
class ApiClient:
    base_url: str = settings.api_url
    api_key: str = field(default=settings.api_key, repr=False)
    community: str = "public"
    min_interval: float = 0.35
    retries: int = 5
    timeout: int = 120
    calls: int = 0
    _last: float = field(default=0.0, repr=False)

    def __post_init__(self) -> None:
        if not self.api_key:
            raise ApiError(
                "no API key: set POLYSCORE_API_KEY (or POLYSWARM_API_KEY) in the environment or .env"
            )

    def _pace(self) -> None:
        wait = self._last + self.min_interval - time.monotonic()
        if wait > 0:
            time.sleep(wait)
        self._last = time.monotonic()

    def get(self, path: str, params: Sequence[tuple[str, str]]) -> dict:
        """One GET with bounded retries on 429 and 5xx. A 404 is the API's empty result."""
        url = f"{self.base_url}{path}?{urllib.parse.urlencode(list(params))}"
        req = urllib.request.Request(
            url,
            headers={
                "Authorization": self.api_key,
                "Accept": "application/json",
                "User-Agent": "polyscore-v2-pilot/0.1",
            },
        )
        for attempt in range(self.retries + 1):
            self._pace()
            self.calls += 1
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as r:
                    return json.load(r)
            except urllib.error.HTTPError as e:
                body = e.read(300).decode(errors="replace").strip()
                if e.code == 404:
                    return {"result": [], "has_more": False}
                if e.code not in (429, 500, 502, 503, 504) or attempt == self.retries:
                    raise ApiError(f"{e.code} on {path}: {body}") from None
                why = str(e.code)
            except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as e:
                if attempt == self.retries:
                    raise ApiError(f"{type(e).__name__} on {path}: {e}") from None
                why = type(e).__name__
            backoff = min(60.0, 2.0**attempt) * (1 + random.random())
            log.warning(
                "retrying",
                extra={"path": path, "why": why, "attempt": attempt + 1, "sleep_s": round(backoff, 1)},
            )
            time.sleep(backoff)
        raise ApiError(f"retries exhausted on {path}")

    def post(self, path: str, data: dict[str, str]) -> dict:
        """One form POST. Retried only on 429 and 503, when the server did nothing; any other
        failure is returned as {"error": ...} because a rescan POST that timed out may have
        created the instance, and a blind retry would create a second one."""
        url = f"{self.base_url}{path}"
        body = urllib.parse.urlencode(data).encode()
        headers = {
            "Authorization": self.api_key,
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "polyscore-v2-pilot/0.1",
        }
        for attempt in range(self.retries + 1):
            self._pace()
            self.calls += 1
            req = urllib.request.Request(url, data=body, headers=headers, method="POST")
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as r:
                    return json.load(r)
            except urllib.error.HTTPError as e:
                text = e.read(300).decode(errors="replace").strip()
                if e.code in (429, 503) and attempt < self.retries:
                    backoff = min(60.0, 2.0**attempt) * (1 + random.random())
                    log.warning("retrying", extra={"path": path, "why": e.code, "sleep_s": round(backoff, 1)})
                    time.sleep(backoff)
                    continue
                return {"error": f"{e.code}: {text}", "http_status": e.code}
            except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as e:
                return {"error": f"{type(e).__name__}: {e}", "http_status": None}
        return {"error": "retries exhausted", "http_status": None}

    def metadata_pages(
        self,
        query: str,
        include: Sequence[str] = SLICE_INCLUDE,
        *,
        limit: int = 300,
        offset: str | None = None,
    ) -> Iterator[tuple[list[dict], str | None]]:
        """Pages of one metadata query, following the opaque cursor until the server stops.

        Yields (documents, next_offset); next_offset is None on the last page. Start from a
        saved cursor with `offset` to resume a walk.
        """
        seen: set[str] = set()
        while True:
            params = [("query", query), ("limit", str(limit)), ("community", self.community)]
            params += [("include", i) for i in include]
            if offset:
                params.append(("offset", offset))
            body = self.get("/search/metadata/query", params)
            nxt = body.get("offset") if body.get("has_more") else None
            if nxt and nxt in seen:
                log.warning("cursor did not advance; stopping", extra={"query": query})
                nxt = None
            yield (body.get("result") or []), nxt
            if not nxt:
                return
            seen.add(nxt)
            offset = nxt

    def scan_history(self, sha256: str) -> list[dict]:
        """Every scan of one file, oldest first (the minified render: no verdicts)."""
        out: list[dict] = []
        offset: str | None = None
        while True:
            params = [("hash", sha256), ("community", self.community), ("limit", "50")]
            if offset:
                params.append(("offset", offset))
            body = self.get("/search/instances", params)
            out += body.get("result") or []
            offset = body.get("offset") if body.get("has_more") else None
            if not offset:
                break
        return sorted(out, key=lambda r: r["created"])


def _scan_columns(prefix: str, scan: dict | None) -> dict:
    scan = scan or {}
    det = scan.get("detections") or {}
    asr = scan.get("assertions") or {}
    return {
        f"{prefix}_instance": scan.get("artifact_instance_id"),
        f"{prefix}_created": scan.get("created"),
        f"{prefix}_polyscore": scan.get("polyscore"),
        f"{prefix}_malicious": det.get("malicious"),
        f"{prefix}_benign": det.get("benign"),
        f"{prefix}_definite": det.get("total"),
        f"{prefix}_responded": len(asr),
        f"{prefix}_assertions": json.dumps(asr, sort_keys=True, separators=(",", ":")) if asr else None,
    }


def flatten(doc: dict) -> dict:
    """One index document -> one flat row: the artifact, its first scan and its latest scan."""
    art = doc.get("artifact") or {}
    scan = doc.get("scan") or {}
    mime = scan.get("mimetype")
    return {
        "sha256": art.get("sha256"),
        "artifact_created": art.get("created"),
        "size": art.get("size"),
        "mimetype": mime.get("mime") if isinstance(mime, dict) else mime,
        **_scan_columns("first", scan.get("first_scan")),
        **_scan_columns("latest", scan.get("latest_scan")),
    }


def _nullable_int(s: pd.Series) -> pd.Series:
    # Through Python ints, never float: an instance id has 17 digits and float64 would round it.
    return pd.Series(
        [int(v) if v is not None and v == v and v != "" else pd.NA for v in s], index=s.index, dtype="Int64"
    )


def to_frame(rows: list[dict]) -> pd.DataFrame:
    df = pd.DataFrame(rows)
    for c in ("artifact_created", "first_created", "latest_created"):
        df[c] = pd.to_datetime(df[c], utc=True, format="ISO8601")
    for c in (
        "size",
        "first_instance",
        "first_malicious",
        "first_benign",
        "first_definite",
        "first_responded",
        "latest_instance",
        "latest_malicious",
        "latest_benign",
        "latest_definite",
        "latest_responded",
    ):
        df[c] = _nullable_int(df[c])
    return df


def walk_slice(client: ApiClient, query: str, cache_dir: Path, *, limit: int = 300) -> tuple[list[dict], int]:
    """Every document of one query, one cached JSON file per page; a killed walk resumes
    from the last saved cursor, a complete cache costs no call at all."""
    pages = sorted(cache_dir.glob("page_*.json"))
    docs: list[dict] = []
    offset = None
    for p in pages:
        page = json.loads(p.read_text())
        docs += page["result"]
        offset = page["next"]
        if offset is None:
            log.info("slice complete in cache", extra={"pages": len(pages), "docs": len(docs)})
            return docs, len(pages)
    n = len(pages)
    if n:
        log.info("resuming", extra={"pages_cached": n, "docs": len(docs)})
    for result, nxt in client.metadata_pages(query, limit=limit, offset=offset):
        (cache_dir / f"page_{n:04d}.json").write_text(json.dumps({"result": result, "next": nxt}))
        docs += result
        n += 1
        if n % 10 == 0:
            log.info("walking", extra={"pages": n, "docs": len(docs)})
    return docs, n


def hash_batches(hashes: Sequence[str], size: int = 50) -> Iterator[str]:
    """Lucene disjunctions over sha256 batches: the way to read a known list of files
    from the index without walking a slice."""
    for i in range(0, len(hashes), size):
        yield "artifact.sha256:(" + " OR ".join(hashes[i : i + size]) + ")"
