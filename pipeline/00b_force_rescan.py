#!/usr/bin/env python3
"""Stage 00b — forced rescans: draw the cohort at T from API slices, rescan it, collect labels.

Natural rescans cannot label a 10k cohort from the public community (specs/12 § Measured),
so the pilot forces them (decisions/0014). Five phases, each resumable:

  static   a survey, not a step: what the index's layout fields say of each frame file. The
           draw does not read it; the index is wrong in both directions (specs/12).
  bytes    read the bytes of every file the draw needs, from the sample directories or the
           API, and record what they show: memory images are not training material
           (decisions/0017) and only a file's bytes say whether it is one (decisions/0018).
  draw     band every scanned-first file of the slices at T and read each band's fixed order
           from the top, passing over the memory images, until the band's target is met
           (pi_draw recorded beside the slices' pi_base). --continues RUN tops an earlier
           run up as a new one, and --top-up-slice adds a slice that is read only after
           the others, for the bands they could not fill.
  submit   POST one rescan per drawn file through /v3/consumer/submission/<community>/rescan
           in a seeded random order, so a partial run is a random subsample; one line per
           file in rescans.jsonl, so a killed run continues where it stopped.
  collect  fetch the full render of every forced instance and of its T instance (the index's
           document can be written before the reveal, with every verdict still hidden), keep
           the files whose forced window has closed, and write what the rest of the pipeline
           reads: a base + its assertions (01a's shape) and the run cohort (01b's shape), so
           02 -> 09 run unchanged.

Writes: data/forced/<run_id>/{static.jsonl, static.parquet, bytes.jsonl, screen.parquet,
        draw.parquet, rescans.jsonl, renders.jsonl, collect.report.txt}
        data/base/forced_<run_id>.parquet (+ .assertions.parquet, manifest)
        data/runs/<run_id>/cohort.parquet (+ manifest)
Contract: specs/12-api-slice-pilot.md § Forced rescans; specs/04-pipeline.md stage 00b.
"""

from __future__ import annotations

import argparse
import dataclasses
import datetime as dt
import hashlib
import json
import sys
import threading
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from polyscore_v2 import image_bytes  # noqa: E402
from polyscore_v2.api_source import ApiClient, hash_batches  # noqa: E402
from polyscore_v2.config import (  # noqa: E402
    CONSENSUS_MALICIOUS,
    CONTESTED_LOWER,
    CONTESTED_UPPER,
    MIN_ANSWERING_ENGINES,
    STRATUM_TARGETS,
    settings,
)
from polyscore_v2.draw import assign_stratum, check_draw, screened_draw  # noqa: E402
from polyscore_v2.io import read_snapshot, write_snapshot  # noqa: E402
from polyscore_v2.logging_setup import configure  # noqa: E402
from polyscore_v2.memory_image import (  # noqa: E402
    REASONS,
    STATIC_INCLUDE,
    absent,
    classify,
    to_frame,
    trim,
)
from polyscore_v2.runs import fresh  # noqa: E402

VERDICT = {"malicious": True, "benign": False}
#: The API renders no scan_config, so no row can be told apart as feed or customer (specs/12).
PROVENANCE_UNKNOWN = "unknown"
DEVIATIONS = [
    "T is the index's first instance (scanned-first files only)",
    "the label is a forced rescan at T + age, not a natural later scan",
    "assertions come from the full render: engine id, name, bid, mask, family; scanner_version when rendered",
    "provenance is unknown for every row: no calibration from this base",
    "bands at draw time used the index's detections.total; the base's n_definite is the render's"
    " count of non-null verdicts, which can differ by one or two",
    "files over the rescan route's size cap are out of frame: the public API refuses them under this key",
    "memory images are out of frame, told by each file's own bytes: an image captured before the"
    " loader ran and saved in file layout at its link-time base is not seen",
    "a file whose bytes could not be read is out of frame: it cannot be shown to stay",
    "a file on the reviewed list is out of frame: a person found it to be a memory image where no"
    " rule says so",
]
STOP_STATUSES = (401, 402, 403)


def _out(run_id: str, name: str) -> Path:
    return settings.path("forced", run_id, name)


def _now() -> pd.Timestamp:
    return pd.Timestamp(dt.datetime.now(dt.UTC))


# ----------------------------------------------------------------------------- the frame


@dataclasses.dataclass(frozen=True)
class Frame:
    """The files a draw may take before the memory-image rule, and what the slices say of them."""

    files: pd.DataFrame
    slice_hashes: list[str]
    top_up_hashes: list[str]
    window: tuple[str, str]
    pi_base: float
    slice_rows: int
    scanned_rows: int
    over_cap: int
    now: pd.Timestamp


def _frame(a: argparse.Namespace) -> Frame:
    # A top-up slice is a later phase of every band's walk. Which slice a file is in follows
    # from its hash alone, so reading the slices in turn is still a random order.
    slices = [read_snapshot(Path(p)) for p in [*a.slice, *a.top_up_slice]]
    for k, (d, _) in enumerate(slices):
        d["phase"] = max(0, k - len(a.slice) + 1)
    windows = {(m["window_start"], m["window_end"]) for _, m in slices}
    if len(windows) != 1:
        sys.exit(f"slices must share one window, got {sorted(windows)}")
    prefixes = [m["prefix"] for _, m in slices]
    for i, p in enumerate(prefixes):
        for q in prefixes[i + 1 :]:
            if p.startswith(q) or q.startswith(p):
                sys.exit(f"prefixes overlap, the union's pi would be wrong: {p!r} {q!r}")
    pi_base = float(sum(m["inclusion_probability"] for _, m in slices))
    df = pd.concat([d for d, _ in slices], ignore_index=True)
    if df["sha256"].duplicated().any():
        sys.exit("duplicate sha256 across slices")

    now = _now()
    age = (now - df["first_created"]).dt.total_seconds() / 86400.0
    scanned = df["first_definite"].fillna(0) > 0
    in_age = (age >= a.min_age_days) & (age < a.max_age_days)
    # The rescan route refuses a file over the key's size cap, so such a file is out of frame
    # rather than drawn and lost; an unknown size stays in.
    under_cap = ~(df["size"] > a.max_size_bytes)
    keep = scanned & in_age & under_cap
    files = pd.DataFrame(
        {
            "sha256": df.loc[keep, "sha256"],
            "instance_number": df.loc[keep, "first_instance"].astype("int64"),
            "scoring_moment": df.loc[keep, "first_created"],
            "n_definite": df.loc[keep, "first_definite"].fillna(0).astype("int64"),
            "n_malicious": df.loc[keep, "first_malicious"].fillna(0).astype("int64"),
            "n_responded": df.loc[keep, "first_responded"].fillna(0).astype("int64"),
            "incumbent_polyscore": df.loc[keep, "first_polyscore"].astype("float64"),
            "first_assertions": df.loc[keep, "first_assertions"],
            "age_days": age[keep].round(2),
            "natural_rescan": (df.loc[keep, "latest_instance"] != df.loc[keep, "first_instance"])
            .fillna(False)
            .astype(bool),
            "phase": df.loc[keep, "phase"].astype("int64"),
        }
    ).reset_index(drop=True)
    hashes = [m["content_sha256"] for _, m in slices]
    return Frame(
        files=files,
        slice_hashes=hashes[: len(a.slice)],
        top_up_hashes=hashes[len(a.slice) :],
        window=next(iter(windows)),
        pi_base=pi_base,
        slice_rows=int(len(df)),
        scanned_rows=int(scanned.sum()),
        over_cap=int((scanned & in_age & ~under_cap).sum()),
        now=now,
    )


# ----------------------------------------------------------------------------- static


def _read_static_cache(path: Path) -> dict[str, dict | None]:
    """sha256 -> the trimmed index document, None when the index had none; the last line wins."""
    docs: dict[str, dict | None] = {}
    if path.exists():
        with path.open() as fh:
            for line in fh:
                if line.strip():
                    rec = json.loads(line)
                    docs[rec["sha256"]] = rec["doc"]
    return docs


def cmd_static(a: argparse.Namespace, log) -> None:
    out = fresh(_out(a.run_id, "static.parquet"), a.overwrite)
    fr = _frame(a)
    hashes = list(fr.files["sha256"])
    cache = _out(a.run_id, "static.jsonl")
    docs = _read_static_cache(cache)
    todo = [h for h in hashes if h not in docs or (a.retry_absent and docs[h] is None)]
    log.info(
        "static", extra={"frame": len(hashes), "cached": len(hashes) - len(todo), "to_fetch": len(todo)}
    )
    calls = 0
    if todo:
        client = ApiClient(min_interval=1.0 / a.rate)
        with cache.open("a") as fh:
            for n, query in enumerate(hash_batches(todo, a.batch), 1):
                found: dict[str, dict] = {}
                for page, _ in client.metadata_pages(query, include=STATIC_INCLUDE, limit=a.batch):
                    for doc in page:
                        found[(doc.get("artifact") or {}).get("sha256")] = trim(doc)
                for h in todo[(n - 1) * a.batch : n * a.batch]:
                    docs[h] = found.get(h)
                    fh.write(json.dumps({"sha256": h, "doc": docs[h]}, separators=(",", ":")) + "\n")
                fh.flush()
                if n % 100 == 0:
                    done = min(n * a.batch, len(todo))
                    log.info("static", extra={"done": done, "of": len(todo), "api_calls": client.calls})
        calls = client.calls

    static = to_frame([classify(docs[h]) if docs[h] else absent(h) for h in hashes])
    layouts = {k: int(v) for k, v in static["layout"].value_counts().items()}
    reasons = {r: int((static["reason"] == r).sum()) for r in REASONS if (static["reason"] == r).any()}
    write_snapshot(
        static,
        out,
        stage="00b_static",
        run_id=a.run_id,
        source="public-api",
        slices=[str(p) for p in a.slice],
        slice_content_sha256=fr.slice_hashes,
        window_start=fr.window[0],
        window_end=fr.window[1],
        min_age_days=a.min_age_days,
        max_age_days=a.max_age_days,
        max_size_bytes=a.max_size_bytes,
        frame_rows=int(len(static)),
        include=list(STATIC_INCLUDE),
        layouts=layouts,
        memory_images=reasons,
        read_at=fr.now.isoformat(),
    )
    print(
        "\n".join(
            [
                f"forced static -- run {a.run_id}: {len(static)} frame files,"
                f" {len(todo)} read from the index in {calls} calls",
                "layout: " + ", ".join(f"{k}={v}" for k, v in layouts.items()),
                "memory images: "
                + (", ".join(f"{k}={v}" for k, v in reasons.items()) or "none")
                + f"; {int(static['reason'].isna().sum())} files stay in frame",
                f"written {out}",
            ]
        )
    )


# ----------------------------------------------------------------------------- bytes

REASON_MEMORY_IMAGE = "memory_image"
#: The mark of a file a person found to be a memory image where no rule says so.
REVIEWED = "reviewed"
#: A file whose bytes could not be had cannot be shown to stay, so it is out of frame too.
REASON_NO_BYTES = "no_bytes"
#: What reading a file can end in for good; any other status is tried again.
SETTLED = ("ok", "not_found", "withheld", "too_large")
#: Which reader wrote a cached line: facts read by another version of the rule are read again.
READER = hashlib.sha256(Path(image_bytes.__file__).read_bytes()).hexdigest()


def _read_bytes_cache(path: Path) -> dict[str, dict]:
    """sha256 -> what reading the file gave, by this reader. The last line of a file wins."""
    records: dict[str, dict] = {}
    if path.exists():
        with path.open() as fh:
            for line in fh:
                if line.strip():
                    rec = json.loads(line)
                    records[rec["sha256"]] = rec
    return {h: r for h, r in records.items() if r["status"] in SETTLED and r.get("reader") == READER}


def _read_reviewed(path: str | None) -> dict[str, str]:
    """sha256 -> note, from a tab-separated list with those two columns; empty without a list."""
    if not path:
        return {}
    listed = pd.read_csv(path, sep="\t", dtype=str).fillna("")
    return dict(zip(listed["sha256"], listed["note"], strict=True))


def _screen(records: dict[str, dict], reviewed: dict[str, str]) -> tuple[dict[str, str | None], pd.DataFrame]:
    """Every examined file -> why it is out of frame, None when it stays; and the verdict table.

    The verdicts are taken over all examined files at once, because some tells compare files.
    A file on the reviewed list is a memory image whatever its bytes showed the reader.
    """
    rows = image_bytes.verdicts((h, r["facts"]) for h, r in sorted(records.items()) if r["status"] == "ok")
    rows += [
        {"sha256": h, "verdict": REASON_NO_BYTES, "tells": r["status"], "as_built": ""}
        for h, r in sorted(records.items())
        if r["status"] != "ok"
    ]
    by_sha = {r["sha256"]: r for r in rows}
    for sha in sorted(reviewed):
        row = by_sha.get(sha)
        if row is None:
            row = by_sha[sha] = {"sha256": sha, "verdict": "", "tells": "", "as_built": ""}
            rows.append(row)
        if row["verdict"] != image_bytes.MEMORY_IMAGE:
            row.update(verdict=image_bytes.MEMORY_IMAGE, tells=REVIEWED)
    table = pd.DataFrame(rows, columns=["sha256", "verdict", "tells", "as_built"])
    out = {image_bytes.MEMORY_IMAGE: REASON_MEMORY_IMAGE, REASON_NO_BYTES: REASON_NO_BYTES}
    return {r["sha256"]: out.get(r["verdict"]) for r in rows}, table


def _examine(sha: str, dirs: list[Path], client: ApiClient | None, max_bytes: int) -> dict:
    """One file's bytes, from the sample directories or else the API, and what they show."""
    data = next(((d / sha).read_bytes() for d in dirs if (d / sha).is_file()), None)
    status = "ok"
    if data is not None:
        if hashlib.sha256(data).hexdigest() != sha:
            status = "wrong_content"
    elif client is None:
        status = "absent"
    else:
        status, data = client.download(sha, max_bytes=max_bytes)
        if status == "ok":
            # Kept so the rule can be read again without a download. A live sample: read-only, never run.
            part = dirs[0] / f".part-{sha}"
            part.write_bytes(data)
            part.chmod(0o400)
            part.replace(dirs[0] / sha)
    facts = image_bytes.read(data) if status == "ok" else None
    return {"sha256": sha, "status": status, "reader": READER, "facts": facts}


def cmd_bytes(a: argparse.Namespace, log) -> None:
    fr = _frame(a)
    dirs = [Path(d) for d in a.samples]
    for d in dirs:
        if not d.is_dir():
            sys.exit(f"{d} is not a directory")
    cache = _out(a.run_id, "bytes.jsonl")
    records = _read_bytes_cache(cache)
    reviewed = _read_reviewed(a.reviewed)
    already = len(records)
    in_frame = set(fr.files["sha256"])
    # Files already on disk give the cross-file tell more builds to compare, so they are read too.
    batch = sorted({p.name for d in dirs for p in d.iterdir() if p.name in in_frame} - set(records))
    if not a.read_local:
        batch = []
    local = threading.local()

    def one(sha: str) -> dict:
        if a.no_fetch:
            return _examine(sha, dirs, None, a.max_size_bytes)
        if not hasattr(local, "client"):
            local.client = ApiClient(min_interval=0.0)
        return _examine(sha, dirs, local.client, a.max_size_bytes)

    tried: set[str] = set()
    statuses: Counter[str] = Counter()
    rounds = 0
    needed: list[str] = []
    with cache.open("a") as fh, ThreadPoolExecutor(max_workers=a.workers) as pool:
        while True:
            if not batch:
                _, _, needed = screened_draw(
                    fr.files,
                    _screen(records, reviewed)[0],
                    cohort_size=a.cohort_size,
                    seed=settings.random_seed,
                    min_definite=MIN_ANSWERING_ENGINES,
                )
                batch = [h for h in needed if h not in tried]
                if not batch:
                    break
            rounds += 1
            log.info("bytes", extra={"round": rounds, "to_read": len(batch), "examined": len(records)})
            for n, rec in enumerate(pool.map(one, batch), 1):
                tried.add(rec["sha256"])
                statuses[rec["status"]] += 1
                fh.write(json.dumps(rec, separators=(",", ":")) + "\n")
                if rec["status"] in SETTLED:
                    records[rec["sha256"]] = rec
                if n % 1000 == 0:
                    fh.flush()
                    log.info("bytes", extra={"round": rounds, "done": n, "of": len(batch)})
            fh.flush()
            batch = []

    examined, table = _screen(records, reviewed)
    verdicts = {k: int(v) for k, v in table["verdict"].value_counts().items()}
    print(
        "\n".join(
            [
                f"forced bytes -- run {a.run_id}: {len(records)} frame files examined"
                f" ({already} before this run), {rounds} rounds",
                "read this run: " + (", ".join(f"{k}={v}" for k, v in sorted(statuses.items())) or "nothing"),
                "verdicts: " + ", ".join(f"{k}={v}" for k, v in sorted(verdicts.items())),
                f"written {cache}",
            ]
        )
    )
    if needed:
        sys.exit(f"{len(needed)} files the draw needs could not be read: see their status in {cache}")


# ----------------------------------------------------------------------------- draw


def _write_whole(path: Path, text: str) -> None:
    """All of the file or none of it: a log half-written would read as a finished one."""
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(text)
    tmp.replace(path)


def _check_continues(prev_id: str, fr: Frame, examined: dict, cohort: pd.DataFrame) -> dict:
    """Check this draw tops up an earlier run; exits when it does not.

    The draw is the head of a fixed order that reads the earlier run's slices first, so every
    file that run drew that is still in frame is drawn again in its band; a file that is not
    means the two draws differ.
    """
    prev, pm = read_snapshot(_out(prev_id, "draw.parquet"))
    # The earlier run's slices must be read first and in its order here; more may follow them.
    earlier = [sorted(pm["slice_content_sha256"]), *pm.get("top_up_slice_content_sha256", [])]
    ours = [sorted(fr.slice_hashes), *fr.top_up_hashes]
    if ours[: len(earlier)] != earlier or pm["random_seed"] != settings.random_seed:
        sys.exit(f"run {prev_id} was drawn from other slices or under another seed: it cannot be continued")
    why = {sha: examined.get(sha) for sha in fr.files["sha256"]}
    band_now = dict(zip(cohort["sha256"], cohort["stratum"], strict=True))
    dropped: dict[str, int] = {}
    broken = 0
    for sha, band in zip(prev["sha256"], prev["stratum"], strict=True):
        if band_now.get(sha) == band:
            continue
        if sha not in why:
            key = "left_the_frame"
        elif isinstance(why[sha], str):
            key = why[sha]
        else:
            broken += 1
            continue
        dropped[key] = dropped.get(key, 0) + 1
    if broken:
        sys.exit(
            f"{broken} files of run {prev_id} are still in frame and were not drawn again in their band:"
            " the band edges, the floor or the cohort size differ, and this draw does not continue it"
        )
    again = len(prev) - sum(dropped.values())
    return {
        "run_id": prev_id,
        "draw_content_sha256": pm["content_sha256"],
        "earlier_drawn": int(len(prev)),
        "drawn_again": int(again),
        "dropped": dropped,
        "new": int(len(cohort) - again),
    }


def _carry_over(prev_id: str, run_id: str, cohort: pd.DataFrame) -> dict:
    """Seed this run's rescan log and render cache with the earlier run's records of its files."""
    # The log's existence marks the seeding as done, so it is written last and never twice.
    logp = _out(run_id, "rescans.jsonl")
    if logp.exists():
        return {"log_records_carried": None, "renders_carried": None}
    drawn = set(cohort["sha256"])
    recs = [r for r in _read_log(_out(prev_id, "rescans.jsonl")).values() if r["sha256"] in drawn]
    t_instance = dict(zip(cohort["sha256"], cohort["instance_number"], strict=True))
    wanted = {int(r["rescan_instance"]) for r in recs if r.get("rescan_instance") is not None}
    wanted |= {int(t_instance[r["sha256"]]) for r in recs}
    renders: dict[int, str] = {}
    src = _out(prev_id, "renders.jsonl")
    if src.exists():
        with src.open() as fh:
            for line in fh:
                if line.strip():
                    iid = json.loads(line)["instance"]
                    if iid in wanted:
                        renders[iid] = line if line.endswith("\n") else line + "\n"
    _write_whole(_out(run_id, "renders.jsonl"), "".join(renders.values()))
    _write_whole(logp, "".join(json.dumps(r) + "\n" for r in recs))
    return {"log_records_carried": len(recs), "renders_carried": len(renders)}


def cmd_draw(a: argparse.Namespace, log) -> None:
    fr = _frame(a)
    records = _read_bytes_cache(_out(a.run_id, "bytes.jsonl"))
    if not records:
        sys.exit("no file of this frame has been examined: run the bytes phase first")
    reviewed = _read_reviewed(a.reviewed)
    examined, table = _screen(records, reviewed)
    now, pi_base, over_cap = fr.now, fr.pi_base, fr.over_cap

    cohort, reports, needed = screened_draw(
        fr.files,
        examined,
        cohort_size=a.cohort_size,
        seed=settings.random_seed,
        min_definite=MIN_ANSWERING_ENGINES,
    )
    if needed:
        sys.exit(f"the draw needs {len(needed)} files that have not been examined: run the bytes phase")
    problems = check_draw(cohort, reports)
    for r in reports:
        log.info("stratum", extra=dataclasses.asdict(r))
    if problems:
        for p in problems:
            log.error("draw check failed", extra={"problem": p})
        sys.exit(2)
    underfilled = [r.stratum for r in reports if r.underfilled]
    cohort = cohort.rename(columns={"pi": "pi_draw"})
    cohort["pi_base"] = pi_base
    cohort["pi"] = cohort["pi_draw"] * pi_base
    # Submission order: a seeded permutation, so a run cut short is still a random subsample
    # of every band. Salted differently from the draw's own key, which the drawn rows of a
    # thinly-sampled band all have at the low end: that key would send the band out first.
    order = cohort["sha256"].map(
        lambda s: hashlib.md5(f"submit:{s}:{settings.random_seed}".encode()).hexdigest()
    )
    cohort = cohort.assign(_o=order).sort_values("_o").drop(columns="_o").reset_index(drop=True)

    # What the screen found, over the frame files it examined; the table is the per-file record.
    in_frame = table[table["sha256"].isin(set(fr.files["sha256"]))].reset_index(drop=True)
    band_at_t = assign_stratum(fr.files["n_malicious"], fr.files["n_definite"])
    band_of = dict(zip(fr.files["sha256"], band_at_t, strict=True))
    in_frame["band_at_t"] = in_frame["sha256"].map(band_of)
    out_rows = in_frame[in_frame["sha256"].map(examined).notna()]
    verdicts = {k: int(v) for k, v in in_frame["verdict"].value_counts().items()}
    images = in_frame[in_frame["verdict"] == image_bytes.MEMORY_IMAGE]
    by_tell = Counter(t for tells in images["tells"] for t in tells.split(","))
    told = [*image_bytes.TELLS, REVIEWED]
    reviewed_sha256 = hashlib.sha256(Path(a.reviewed).read_bytes()).hexdigest() if a.reviewed else None
    out_by_band = {k: int(v) for k, v in out_rows["band_at_t"].value_counts().items()}
    screen_out = _out(a.run_id, "screen.parquet")
    in_frame.to_parquet(screen_out, index=False)

    continues = _check_continues(a.continues, fr, examined, cohort) if a.continues else None
    out = fresh(_out(a.run_id, "draw.parquet"), a.overwrite)
    if continues:
        continues |= _carry_over(a.continues, a.run_id, cohort)
    (w0, w1) = fr.window
    write_snapshot(
        cohort,
        out,
        stage="00b_draw",
        run_id=a.run_id,
        source="public-api",
        slices=[str(p) for p in a.slice],
        slice_content_sha256=fr.slice_hashes,
        top_up_slices=[str(p) for p in a.top_up_slice],
        top_up_slice_content_sha256=fr.top_up_hashes,
        window_start=w0,
        window_end=w1,
        pi_base=pi_base,
        min_age_days=a.min_age_days,
        max_age_days=a.max_age_days,
        max_size_bytes=a.max_size_bytes,
        over_cap_rows=over_cap,
        slice_rows=fr.slice_rows,
        frame_rows=int(len(fr.files)),
        examined_rows=int(len(in_frame)),
        examined_verdicts=verdicts,
        memory_images_by_tell={t: int(by_tell[t]) for t in told if by_tell[t]},
        reviewed_rows=len(reviewed),
        reviewed_content_sha256=reviewed_sha256,
        rules_version=image_bytes.RULES_VERSION,
        out_of_frame_by_band_at_t=out_by_band,
        screen_content_sha256=hashlib.sha256(
            in_frame.sort_values("sha256").to_csv(index=False).encode()
        ).hexdigest(),
        reader_sha256=READER,
        continues=continues,
        cohort_size_requested=a.cohort_size,
        band_edges={"lower": CONTESTED_LOWER, "upper": CONTESTED_UPPER, "consensus": CONSENSUS_MALICIOUS},
        min_definite=MIN_ANSWERING_ENGINES,
        targets=STRATUM_TARGETS,
        strata=[dataclasses.asdict(r) for r in reports],
        underfilled=underfilled,
        drawn_at=now.isoformat(),
        deviations=DEVIATIONS,
    )
    lines = [
        f"forced draw -- run {a.run_id}: {fr.slice_rows} slice rows, {fr.scanned_rows} scanned first,"
        f" {len(fr.files)} aged [{a.min_age_days}, {a.max_age_days}) days and under {a.max_size_bytes} bytes"
        f" ({over_cap} over the cap); pi_base = {pi_base:.6g}",
        f"examined from their bytes: {len(in_frame)} frame files: "
        + ", ".join(f"{k}={v}" for k, v in sorted(verdicts.items())),
        "  memory images by tell: "
        + (", ".join(f"{t}={by_tell[t]}" for t in told if by_tell[t]) or "none"),
        "  out of frame by band at T: " + (", ".join(f"{k}={v}" for k, v in out_by_band.items()) or "none"),
        f"{'stratum':20s} {'in band':>8s} {'examined':>8s} {'out':>6s} {'target':>7s} {'drawn':>6s}"
        f" {'pi_draw':>8s}",
    ]
    for r in reports:
        lines.append(
            f"{r.stratum:20s} {r.n_band:8d} {r.n_examined:8d} {r.n_out:6d} {r.n_target:7d} {r.n_draw:6d}"
            f" {r.pi:8.4f}" + ("  UNDER-FILLED" if r.underfilled else "")
        )
    if continues:
        gone = ", ".join(f"{k}={v}" for k, v in continues["dropped"].items()) or "none"
        lines.append(
            f"continues run {continues['run_id']}: {continues['drawn_again']} of its"
            f" {continues['earlier_drawn']} files drawn again, {continues['new']} new; dropped: {gone}"
        )
        if continues["log_records_carried"] is not None:
            lines.append(
                f"  carried over {continues['log_records_carried']} rescan records and"
                f" {continues['renders_carried']} renders"
            )
    lines.append(f"cohort: {len(cohort)} files in the draw; written {out} and {screen_out}")
    print("\n".join(lines))


# ----------------------------------------------------------------------------- submit


def _read_log(path: Path) -> dict[str, dict]:
    done: dict[str, dict] = {}
    if path.exists():
        for line in path.read_text().splitlines():
            if line.strip():
                rec = json.loads(line)
                done[rec["sha256"]] = rec  # the last record of a file wins
    return done


def cmd_submit(a: argparse.Namespace, log) -> None:
    cohort, _ = read_snapshot(_out(a.run_id, "draw.parquet"))
    logp = _out(a.run_id, "rescans.jsonl")
    done = _read_log(logp)
    todo = [
        r
        for r in cohort.itertuples(index=False)
        if r.sha256 not in done or (a.retry_errors and done[r.sha256].get("error"))
    ]
    if a.limit:
        todo = todo[: a.limit]
    log.info(
        "submit", extra={"cohort": len(cohort), "already": len(done), "todo": len(todo), "rate_per_s": a.rate}
    )
    if a.dry_run:
        for r in todo[:20]:
            print(r.sha256, r.stratum)
        print(f"dry run: {len(todo)} rescans would be submitted")
        return

    client = ApiClient(min_interval=1.0 / a.rate)
    ok = err = streak = 0
    t0 = time.monotonic()
    with logp.open("a") as fh:
        for i, r in enumerate(todo, 1):
            resp = client.post(
                f"/consumer/submission/{client.community}/rescan/sha256/{r.sha256}",
                {"community": client.community},
            )
            rec = {
                "sha256": r.sha256,
                "instance_number": int(r.instance_number),
                "stratum": r.stratum,
                "submitted_at": _now().isoformat(),
            }
            if "error" in resp:
                rec["error"] = resp["error"]
                rec["http_status"] = resp.get("http_status")
                err += 1
                streak += 1
            else:
                res = resp.get("result") or {}
                rec["rescan_instance"] = int(res["id"]) if res.get("id") is not None else None
                rec["rescan_created"] = res.get("created")
                ok += 1
                streak = 0
            fh.write(json.dumps(rec) + "\n")
            fh.flush()
            if i % 100 == 0 or i == len(todo):
                log.info("submitting", extra={"done": i, "of": len(todo), "ok": ok, "errors": err})
            if rec.get("http_status") in STOP_STATUSES or streak >= a.max_error_streak:
                log.error("stopping", extra={"last_error": rec.get("error"), "streak": streak})
                break
    print(
        json.dumps(
            {
                "run_id": a.run_id,
                "submitted_ok": ok,
                "errors": err,
                "seconds": round(time.monotonic() - t0, 1),
                "log": str(logp),
            }
        )
    )


# ----------------------------------------------------------------------------- collect


def _extract_render(res: dict) -> dict:
    """The facts the pipeline keeps from one full instance render; everything else is dropped."""
    rows = []
    for x in res.get("assertions") or []:
        meta = x.get("metadata") or {}
        scanner = meta.get("scanner") if isinstance(meta.get("scanner"), dict) else {}
        rows.append(
            {
                "author": str(x.get("author")),
                "author_name": x.get("author_name"),
                "verdict": x.get("verdict"),
                "bid": x.get("bid"),
                "mask": x.get("mask"),
                "malware_family": meta.get("malware_family"),
                "scanner_version": scanner.get("version"),
            }
        )
    return {
        "instance": int(res["id"]),
        "created": res.get("created"),
        "state": res.get("state"),
        "window_closed": bool(res.get("window_closed")),
        "failed": bool(res.get("failed")),
        "polyscore": res.get("polyscore"),
        "result": res.get("result"),
        "assertions": rows,
    }


def _fetch_renders(client: ApiClient, ids: list[int], cache: Path, log) -> dict[int, dict]:
    """Full renders by instance id, cached as JSONL; an unsettled or missing one is fetched again."""
    have: dict[int, dict] = {}
    if cache.exists():
        for line in cache.read_text().splitlines():
            if line.strip():
                rec = json.loads(line)
                have[rec["instance"]] = rec
    todo = [i for i in dict.fromkeys(ids) if i not in have or not have[i].get("window_closed")]
    log.info(
        "renders", extra={"wanted": len(set(ids)), "cached": len(set(ids)) - len(todo), "to_fetch": len(todo)}
    )
    with cache.open("a") as fh:
        for n, iid in enumerate(todo, 1):
            res = (client.get("/instance", [("id", str(iid)), ("community", client.community)]) or {}).get(
                "result"
            )
            rec = (
                _extract_render(res)
                if res and res.get("id")
                else {
                    "instance": iid,
                    "missing": True,
                    "window_closed": False,
                    "failed": False,
                    "assertions": [],
                }
            )
            have[iid] = rec
            fh.write(json.dumps(rec) + "\n")
            fh.flush()
            if n % 250 == 0:
                log.info("renders", extra={"done": n, "of": len(todo), "api_calls": client.calls})
    return have


def _status(row, renders: dict[int, dict]) -> str:
    if pd.isna(row.rescan_instance):
        return "not_submitted"
    lab = renders.get(int(row.rescan_instance), {})
    t = renders.get(int(row.instance_number), {})
    if lab.get("missing") or t.get("missing"):
        return "missing_render"
    if lab.get("failed"):
        return "failed"
    if not lab.get("window_closed"):
        return "pending"
    if not lab["assertions"] or not t.get("assertions"):
        return "no_assertions"
    return "labelled"


def _bid(value) -> int:
    """The render's bid is a decimal string of NCT-wei; 01a's column is int64, 0 when absent."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _assertion_rows(sha: str, role: str, rec: dict) -> list[dict]:
    return [
        {"sha256": sha, "scan_role": role, "instance_number": rec["instance"], **a, "bid": _bid(a.get("bid"))}
        for a in rec["assertions"]
    ]


def _counts(rec: dict) -> tuple[int, int, int]:
    verdicts = [a["verdict"] for a in rec["assertions"]]
    return (
        sum(1 for v in verdicts if v is not None),
        sum(1 for v in verdicts if v is True),
        len(verdicts),
    )


def cmd_collect(a: argparse.Namespace, log) -> None:
    cohort, cm = read_snapshot(_out(a.run_id, "draw.parquet"))
    # Through Python ints, never a float column: a 17-digit instance id does not survive
    # float64, and a frame built from records with a missing key becomes one.
    ok = [
        r for r in _read_log(_out(a.run_id, "rescans.jsonl")).values() if r.get("rescan_instance") is not None
    ]
    if not ok:
        sys.exit("nothing submitted yet")
    sub = pd.DataFrame(
        {
            "sha256": [r["sha256"] for r in ok],
            "rescan_instance": pd.array([int(r["rescan_instance"]) for r in ok], dtype="Int64"),
            "submitted_at": [r["submitted_at"] for r in ok],
        }
    )
    m = cohort.merge(sub, on="sha256", how="left")

    client = ApiClient(min_interval=1.0 / a.rate)
    submitted = m[m["rescan_instance"].notna()]
    if a.limit:
        submitted = submitted.head(a.limit)
    ids = [int(x) for x in submitted["rescan_instance"]] + [int(x) for x in submitted["instance_number"]]
    renders = _fetch_renders(client, ids, _out(a.run_id, "renders.jsonl"), log)
    m["status"] = [_status(r, renders) for r in m.itertuples(index=False)]
    counts = m["status"].value_counts()
    lab = m[m["status"] == "labelled"].copy()
    log.info("collected", extra={**{k: int(v) for k, v in counts.items()}, "api_calls": client.calls})

    lines = [
        f"forced collect -- run {a.run_id}: {len(m)} drawn, "
        f"{int((m['status'] != 'not_submitted').sum())} submitted, {client.calls} API calls this run",
        "status: " + ", ".join(f"{k}={v}" for k, v in counts.items()),
    ]
    per = m.groupby("stratum")["status"].value_counts().unstack(fill_value=0)
    lines += ["", per.to_string(), ""]
    if lab.empty:
        rep = _out(a.run_id, "collect.report.txt")
        rep.write_text("\n".join(lines) + "\n")
        print("\n".join(lines))
        print("no labelled files yet: run collect again once the rescans have closed their windows")
        return

    t_recs = [renders[int(i)] for i in lab["instance_number"]]
    l_recs = [renders[int(i)] for i in lab["rescan_instance"]]
    t_counts = pd.DataFrame(
        [_counts(r) for r in t_recs], columns=["n_definite", "n_malicious", "n_responded"]
    )
    l_counts = pd.DataFrame(
        [_counts(r) for r in l_recs], columns=["l_definite", "l_malicious", "l_responded"]
    )
    label_moment = pd.to_datetime([r["created"] for r in l_recs], utc=True)
    gap = label_moment - pd.DatetimeIndex(lab["scoring_moment"])
    gd = pd.Series(gap.total_seconds() / 86400.0)
    # The slice's counts at T came from the index; the render is authoritative. Report any drift.
    drift = int((t_counts["n_definite"].values != lab["n_definite"].values).sum())
    lines += [
        f"label gap (days): p10 {gd.quantile(0.1):.1f}  p50 {gd.median():.1f}  p90 {gd.quantile(0.9):.1f}"
        f"  min {gd.min():.1f}  max {gd.max():.1f}",
        f"definite verdicts at T: p50 {t_counts['n_definite'].median():.0f}; at the label scan:"
        f" p10 {l_counts['l_definite'].quantile(0.1):.0f}  p50 {l_counts['l_definite'].median():.0f}"
        f"  p90 {l_counts['l_definite'].quantile(0.9):.0f}",
        f"files whose definite count at T differs between the index and the render: {drift}",
    ]

    base = pd.DataFrame(
        {
            "sha256": lab["sha256"].values,
            "instance_number": lab["instance_number"].astype("int64").values,
            "scoring_moment": lab["scoring_moment"].values,
            "label_instance_number": lab["rescan_instance"].astype("int64").values,
            "label_moment": label_moment.tz_convert(None),
            "label_gap": [str(pd.Timedelta(x)) for x in gap],
            "n_definite": t_counts["n_definite"].astype("int64").values,
            "n_malicious": t_counts["n_malicious"].astype("int64").values,
            "n_responded": t_counts["n_responded"].astype("int64").values,
            "scan_config": pd.array([None] * len(lab), dtype="string"),
            "provenance": PROVENANCE_UNKNOWN,
            "incumbent_polyscore": lab["incumbent_polyscore"].astype("float64").values,
            "label_polyscore": [r["polyscore"] for r in l_recs],
        }
    )
    rows: list[dict] = []
    for sha, t, lr in zip(lab["sha256"], t_recs, l_recs, strict=True):
        rows += _assertion_rows(sha, "feature", t)
        rows += _assertion_rows(sha, "label", lr)
    assertions = pd.DataFrame(rows)
    assertions["verdict"] = assertions["verdict"].astype("boolean")
    assertions["instance_number"] = assertions["instance_number"].astype("int64")
    assertions["bid"] = assertions["bid"].astype("int64")
    assertions = assertions.sort_values(["sha256", "scan_role", "author"]).reset_index(drop=True)

    window = f"{cm['window_start']}_{cm['window_end']}"
    base_out = fresh(settings.path("base", f"forced_{a.run_id}.parquet"), a.overwrite)
    base_out.with_suffix(".assertions.parquet").unlink(missing_ok=True)
    # The run cohort's pi is the realized share per band, labelled over available: a file lost
    # after the draw (size cap, failed scan) lowers its band's pi instead of vanishing from it.
    # The design's pi_draw stays beside it; pi_base is a column, not a factor, as 01b's base pi
    # of 1 is not.
    realized = lab["stratum"].map(lab["stratum"].value_counts()).astype("int64")
    lab = lab.assign(n_draw=realized, pi=(realized / lab["n_available"]).astype("float64"))
    excluded = m[m["status"] != "labelled"].groupby("stratum")["status"].value_counts()
    excluded_after_draw = {f"{band}:{status}": int(n) for (band, status), n in excluded.items()}
    strata = [
        {**r, "n_drawn": r["n_draw"], "n_draw": int(lab["stratum"].eq(r["stratum"]).sum())}
        for r in cm["strata"]
    ]
    draw_cols = lab[["sha256", "stratum", "pi", "pi_draw", "pi_base", "n_available", "n_draw"]]
    base = base.merge(draw_cols[["sha256"]], on="sha256").sort_values("sha256").reset_index(drop=True)
    write_snapshot(
        base,
        base_out,
        stage="00b_collect",
        source="forced_rescan_api",
        run_id=a.run_id,
        window=window,
        window_start=cm["window_start"],
        window_end=cm["window_end"],
        horizon_days=settings.horizon_days,
        horizon_max_days=cm["max_age_days"],
        pi_base=cm["pi_base"],
        draw_content_sha256=cm["content_sha256"],
        statuses={k: int(v) for k, v in counts.items()},
        excluded_after_draw=excluded_after_draw,
        assertion_rows=int(len(assertions)),
        engine_key="author = engine id from the full render; author_name beside it",
        deviations=DEVIATIONS,
    )
    assertions.to_parquet(base_out.with_suffix(".assertions.parquet"), index=False)
    base_manifest = json.loads(base_out.with_suffix(".manifest.json").read_text())

    # 01b's cohort carries every base column plus the draw's; 02_compose reads n_definite and
    # n_responded off the cohort itself, so the run cohort is the base rows with the draw columns.
    run_cohort = (
        base.merge(draw_cols, on="sha256", how="inner")
        .sort_values(["stratum", "sha256"])
        .reset_index(drop=True)
    )
    run_out = fresh(settings.path("runs", a.run_id, "cohort.parquet"), a.overwrite)
    write_snapshot(
        run_cohort,
        run_out,
        stage="00b_collect",
        run_id=a.run_id,
        source="forced_rescan_api",
        base_snapshot=str(base_out),
        base_content_sha256=base_manifest["content_sha256"],
        base_window=window,
        horizon_max_days=cm["max_age_days"],
        cohort_size_requested=cm["cohort_size_requested"],
        band_edges=cm["band_edges"],
        min_definite=cm["min_definite"],
        targets=cm["targets"],
        strata=strata,
        underfilled=cm["underfilled"],
        excluded_after_draw=excluded_after_draw,
        deviations=DEVIATIONS,
    )
    lines += [
        "",
        f"base: {base_out} ({len(base)} rows, {len(assertions)} assertion rows)",
        f"run cohort: {run_out} ({len(run_cohort)} rows); next: make compose RUN={a.run_id}, then label",
    ]
    rep = _out(a.run_id, "collect.report.txt")
    rep.write_text("\n".join(lines) + "\n")
    print("\n".join(lines))


# ----------------------------------------------------------------------------- main


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--run-id", default=settings.run_id)
    ap.add_argument("--overwrite", action="store_true")
    sub = ap.add_subparsers(dest="cmd", required=True)

    # The frame's own rules, shared by the phases that build it.
    f = argparse.ArgumentParser(add_help=False)
    f.add_argument("--slice", action="append", required=True, help="an API slice parquet; repeat for a union")
    f.add_argument(
        "--top-up-slice",
        action="append",
        default=[],
        metavar="PARQUET",
        help="a further slice of the same window, read only after the slices before it: it tops up"
        " the bands they could not fill and moves no file they gave. Repeat for more, in order",
    )
    f.add_argument(
        "--reviewed",
        metavar="TSV",
        help="files a person found to be memory images where no rule says so: sha256 and note columns",
    )
    f.add_argument(
        "--min-age-days", type=int, default=settings.horizon_days, help="first scan at least this old"
    )
    f.add_argument(
        "--max-size-bytes",
        type=int,
        default=33554432,
        help="the rescan route's artifact-size limit under this key; larger files are out of frame",
    )
    f.add_argument(
        "--max-age-days", type=int, default=settings.horizon_max_days, help="and younger than this"
    )

    t = sub.add_parser(
        "static", parents=[f], help="a survey: what the index's layout fields say of the frame"
    )
    t.add_argument("--rate", type=float, default=3.0, help="index queries per second")
    t.add_argument("--batch", type=int, default=50, help="files per index query")
    t.add_argument(
        "--retry-absent", action="store_true", help="ask again for files the index had no document for"
    )

    b = sub.add_parser("bytes", parents=[f], help="read the bytes of the files the draw needs")
    b.add_argument("--cohort-size", type=int, default=settings.cohort_size)
    b.add_argument(
        "--samples",
        action="append",
        required=True,
        metavar="DIR",
        help="a directory of sample files named by sha256; repeat for several. A fetched file"
        " is kept in the first. They are live samples: read-only, never run",
    )
    b.add_argument("--workers", type=int, default=4, help="files read or fetched at a time")
    b.add_argument("--no-fetch", action="store_true", help="read only what the directories hold")
    b.add_argument(
        "--read-local",
        action="store_true",
        help="also read every frame file the directories hold, whether or not the draw needs it",
    )

    d = sub.add_parser("draw", parents=[f], help="band the slices at T and draw the cohort")
    d.add_argument("--cohort-size", type=int, default=settings.cohort_size)
    d.add_argument(
        "--continues",
        metavar="RUN",
        help="an earlier run that this draw tops up, from the same slices read first; its log and"
        " renders carry over",
    )

    s = sub.add_parser("submit", help="POST the rescans, resumably")
    s.add_argument("--rate", type=float, default=1.0, help="rescans per second")
    s.add_argument("--limit", type=int, default=0, help="submit at most this many (a canary)")
    s.add_argument("--retry-errors", action="store_true", help="re-POST the files whose last attempt failed")
    s.add_argument("--max-error-streak", type=int, default=10)
    s.add_argument("--dry-run", action="store_true")

    c = sub.add_parser("collect", help="read the forced scans back and write the base and run cohort")
    c.add_argument("--rate", type=float, default=3.0, help="render fetches per second")
    c.add_argument("--limit", type=int, default=0, help="collect at most this many submitted files (a test)")

    a = ap.parse_args()
    log = configure()
    phases = {
        "static": cmd_static,
        "bytes": cmd_bytes,
        "draw": cmd_draw,
        "submit": cmd_submit,
        "collect": cmd_collect,
    }
    phases[a.cmd](a, log)


if __name__ == "__main__":
    main()
