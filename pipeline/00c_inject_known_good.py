#!/usr/bin/env python3
"""Stage 00c — the injection arm: Microsoft-signed files already scanned, attested twice.

Decision 9's 5% known-good arm needs benign truth from outside the engine process. The
index already holds it: every PE scan carries the lief analyzer's Authenticode result, and
"signed by Microsoft, signature verified" is one query. The analyzer pins no CA bundle, so
its `verified` is a digest-and-signer check and not trust (a self-made chain passes), and
a second, independent check settles trust: VirusTotal's sigcheck verdict on the same hash,
which validates the chain against the Windows trust store. Only the signature attestation
is read from VirusTotal, never a detection (decisions/0015). Three phases, resumable:

  draw     the candidates: scanned-first PE files under the sha256 prefixes whose first scan
           has verdicts and whose lief tags say `verified` with a Microsoft signer. Files
           the engines flagged at T come first (the hardest negatives), then a seeded
           permutation of the rest.
  confirm  per candidate, the first scan's full render (the features, and the embedded
           chain) and VirusTotal's file object; one JSONL line each, paced for the key.
  collect  the trusted set -- both attestations, and a signing CA seen in enough confirmed
           chains -- written in 01a's and 01b's shapes with provenance and stratum
           injected_known_good and no inclusion probability.

Writes: data/injected/<run_id>/{draw.parquet, renders.jsonl, confirm.jsonl, confirm.parquet,
        collect.report.txt}; data/base/injected_<run_id>.parquet (+ .assertions.parquet,
        manifest); data/runs/<run_id>/injected.parquet (+ manifest)
Contract: specs/12-api-slice-pilot.md § The injection arm; specs/04-pipeline.md stage 00c.
"""

from __future__ import annotations

import argparse
import collections
import datetime as dt
import hashlib
import importlib.util
import json
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from polyscore_v2.api_source import (  # noqa: E402
    PE_GATE,
    ApiClient,
    flatten,
    inclusion_probability,
    to_frame,
    walk_slice,
)
from polyscore_v2.config import INJECTED_PROVENANCE, settings  # noqa: E402
from polyscore_v2.io import read_snapshot, write_snapshot  # noqa: E402
from polyscore_v2.logging_setup import configure  # noqa: E402
from polyscore_v2.runs import fresh  # noqa: E402

# The render-to-rows helpers are 00b's; a numbered script cannot be imported by name.
_spec = importlib.util.spec_from_file_location(
    "force_rescan", Path(__file__).with_name("00b_force_rescan.py")
)
force_rescan = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(force_rescan)

SIGNER_ORG = "Microsoft Corporation"
VT_API = "https://www.virustotal.com/api/v3"
#: VirusTotal renders the chain it validated as "leaf; intermediate; root": the last
#: element is the trust anchor from the Windows store, embedded in the file or not.
VT_ROOT_PREFIX = "Microsoft Root"
STRATUM = INJECTED_PROVENANCE
DEVIATIONS = [
    "drawn from files the platform already holds and scanned once; the attestation is external,"
    " the files are not",
    "the label is positive attestation (code signing, grade 2), not a later scan: no label scan, no horizon",
    "no inclusion probability: pi is NaN, excluded from every prevalence estimate and 1/pi weight",
    "VirusTotal is read for its signature check only; no detection count or verdict of its is stored",
    "provenance is unknown as elsewhere on the API path; the arm's own column says injected_known_good",
]
STATUSES = (
    "trusted",
    "chain_unpinned",
    "ours_failed",
    "vt_not_signed",
    "vt_other_root",
    "vt_unknown",
    "render_missing",
    "not_confirmed",
)


def _out(run_id: str, name: str) -> Path:
    return settings.path("injected", run_id, name)


def _now() -> str:
    return dt.datetime.now(dt.UTC).isoformat()


# ----------------------------------------------------------------------------- draw


def candidate_query(prefix: str, start: str | None, end: str | None) -> str:
    parts = [
        PE_GATE,
        f"artifact.sha256:{prefix}*",
        "scan.first_scan.detections.total:[1 TO *]",
        "lief.signature_tags:verified",
        f'lief.signer.organization:"{SIGNER_ORG}"',
    ]
    if start or end:
        parts.append(f"scan.first_scan.created:[{start or '*'} TO {end or '*'}}}")
    return " AND ".join(parts)


def cmd_draw(a: argparse.Namespace, log) -> None:
    for i, p in enumerate(a.prefix):
        for q in a.prefix[i + 1 :]:
            if p.startswith(q) or q.startswith(p):
                sys.exit(f"prefixes overlap, the union's pi would be wrong: {p!r} {q!r}")
    client = ApiClient()
    frames = []
    for prefix in a.prefix:
        cache = _out(a.run_id, f"slice_{prefix}")
        cache.mkdir(parents=True, exist_ok=True)
        docs, pages = walk_slice(client, candidate_query(prefix, a.window_start, a.window_end), cache)
        log.info("candidates", extra={"prefix": prefix, "docs": len(docs), "pages": pages})
        if docs:
            frames.append(to_frame([flatten(d) for d in docs]))
    if not frames:
        sys.exit("no candidates under these prefixes")
    df = pd.concat(frames, ignore_index=True).drop_duplicates("sha256")
    pi_base = float(sum(inclusion_probability(p) for p in a.prefix))

    frame = pd.DataFrame(
        {
            "sha256": df["sha256"],
            "instance_number": df["first_instance"].astype("int64"),
            "scoring_moment": df["first_created"],
            "n_definite": df["first_definite"].fillna(0).astype("int64"),
            "n_malicious": df["first_malicious"].fillna(0).astype("int64"),
            "n_responded": df["first_responded"].fillna(0).astype("int64"),
            "incumbent_polyscore": df["first_polyscore"].astype("float64"),
            "size": df["size"],
        }
    ).reset_index(drop=True)
    frame["flagged_at_t"] = frame["n_malicious"] > 0
    # Hardest first: a signed file the engines flagged is the negative worth the most
    # (estimand SS9). The rest in a seeded order, so a cut-short confirm is a random subsample.
    key = frame["sha256"].map(
        lambda s: hashlib.md5(f"inject:{s}:{settings.random_seed}".encode()).hexdigest()
    )
    frame = (
        frame.assign(_k=key)
        .sort_values(["flagged_at_t", "_k"], ascending=[False, True])
        .drop(columns="_k")
        .reset_index(drop=True)
    )
    cand = frame.head(a.candidates).copy()
    out = fresh(_out(a.run_id, "draw.parquet"), a.overwrite)
    write_snapshot(
        cand,
        out,
        stage="00c_draw",
        run_id=a.run_id,
        source="public-api",
        query=candidate_query("<prefix>", a.window_start, a.window_end),
        prefixes=list(a.prefix),
        pi_base=pi_base,
        window_start=a.window_start,
        window_end=a.window_end,
        frame_rows=int(len(frame)),
        frame_flagged_at_t=int(frame["flagged_at_t"].sum()),
        candidates_requested=a.candidates,
        drawn_at=_now(),
        deviations=DEVIATIONS,
    )
    print(
        f"inject draw -- run {a.run_id}: {len(frame)} Microsoft-signed, verified, scanned-first files under"
        f" {a.prefix} (pi_base {pi_base:.6g}); {int(frame['flagged_at_t'].sum())} flagged by an engine at T;"
        f" {len(cand)} candidates kept ({int(cand['flagged_at_t'].sum())} flagged first); written {out}"
    )


# ----------------------------------------------------------------------------- confirm


def _signature_evidence(res: dict) -> dict:
    """What the lief analyzer said about the signature, from the full render's metadata."""
    tools = {m.get("tool"): m for m in res.get("metadata") or []}
    lief = (tools.get("lief") or {}).get("tool_metadata") or {}
    signer = lief.get("signer") or {}
    chain = [
        {"is_ca": bool(c.get("is_ca")), "subject": c.get("subject"), "sha256": c.get("sha256")}
        for s in lief.get("signatures") or []
        for c in s.get("certificates") or []
    ]
    return {
        "tags": lief.get("signature_tags") or [],
        "signer_org": signer.get("organization"),
        "signer_cn": signer.get("common_name"),
        "signer_cert": signer.get("sha256"),
        "chain": chain,
        "chain_flags": [
            (s.get("chain_of_trust") or {}).get("chain_flags") for s in lief.get("signatures") or []
        ],
    }


def _fetch_renders(client: ApiClient, ids: list[int], cache: Path, log) -> dict[int, dict]:
    """Full renders by instance id, cached as JSONL with the signature evidence beside 00b's facts."""
    have: dict[int, dict] = {}
    if cache.exists():
        for line in cache.read_text().splitlines():
            if line.strip():
                rec = json.loads(line)
                have[rec["instance"]] = rec
    todo = [i for i in dict.fromkeys(ids) if i not in have or have[i].get("missing")]
    log.info(
        "renders", extra={"wanted": len(set(ids)), "cached": len(set(ids)) - len(todo), "to_fetch": len(todo)}
    )
    with cache.open("a") as fh:
        for n, iid in enumerate(todo, 1):
            res = (client.get("/instance", [("id", str(iid)), ("community", client.community)]) or {}).get(
                "result"
            )
            if res and res.get("id"):
                rec = {**force_rescan._extract_render(res), "signature": _signature_evidence(res)}
            else:
                rec = {"instance": iid, "missing": True, "assertions": []}
            have[iid] = rec
            fh.write(json.dumps(rec) + "\n")
            fh.flush()
            if n % 100 == 0:
                log.info("renders", extra={"done": n, "of": len(todo), "api_calls": client.calls})
    return have


class VirusTotal:
    """File-object reads, paced for the key's hourly quota. The key never leaves the header."""

    def __init__(self, api_key: str, per_hour: float) -> None:
        if not api_key:
            sys.exit("no VirusTotal key: set POLYSCORE_VT_API_KEY (or VT_API_KEY) in the environment")
        self.api_key = api_key
        self.min_interval = 3600.0 / per_hour
        self._last = 0.0
        self.calls = 0

    def file(self, sha256: str) -> tuple[int, dict]:
        req = urllib.request.Request(
            f"{VT_API}/files/{sha256}",
            headers={
                "x-apikey": self.api_key,
                "Accept": "application/json",
                "User-Agent": "polyscore-v2-pilot/0.1",
            },
        )
        for attempt in range(4):
            wait = self._last + self.min_interval - time.monotonic()
            if wait > 0:
                time.sleep(wait)
            self._last = time.monotonic()
            self.calls += 1
            try:
                with urllib.request.urlopen(req, timeout=60) as r:
                    return r.status, (json.load(r).get("data") or {}).get("attributes") or {}
            except urllib.error.HTTPError as e:
                e.read()
                if e.code == 404:
                    return 404, {}
                if e.code == 429 and attempt < 3:
                    time.sleep(60.0 * (attempt + 1))
                    continue
                if e.code in (401, 403):
                    sys.exit(f"VirusTotal refused the key ({e.code})")
                return e.code, {}
            except (urllib.error.URLError, TimeoutError, json.JSONDecodeError):
                if attempt == 3:
                    return 0, {}
                time.sleep(15.0 * (attempt + 1))
        return 0, {}


def _vt_fields(attrs: dict) -> dict:
    """The signature attestation alone; VirusTotal's detections are deliberately not read."""
    si = attrs.get("signature_info") or {}
    kd = attrs.get("known_distributors") or {}
    tv = attrs.get("trusted_verdict") or {}
    return {
        "vt_verified": si.get("verified"),
        "vt_signers": [s.strip() for s in str(si.get("signers") or "").split(";") if s.strip()],
        "vt_signer_statuses": [d.get("status") for d in si.get("signers details") or []],
        "vt_signing_date": si.get("signing date"),
        "vt_known_distributors": kd.get("distributors"),
        "vt_trusted_verdict_org": tv.get("organization"),
        "vt_first_submission": attrs.get("first_submission_date"),
    }


def cmd_confirm(a: argparse.Namespace, log) -> None:
    cand, _ = read_snapshot(_out(a.run_id, "draw.parquet"))
    logp = _out(a.run_id, "confirm.jsonl")
    done = force_rescan._read_log(logp)
    todo = cand[~cand["sha256"].isin(done)]
    if a.limit:
        todo = todo.head(a.limit)
    if todo.empty:
        print(f"nothing to confirm: {len(done)} of {len(cand)} candidates already have a record")
        return
    client = ApiClient()
    renders = _fetch_renders(
        client, [int(x) for x in todo["instance_number"]], _out(a.run_id, "renders.jsonl"), log
    )
    vt = VirusTotal(settings.vt_api_key, a.vt_rate)
    log.info("confirming", extra={"files": len(todo), "already": len(done), "vt_per_hour": a.vt_rate})
    with logp.open("a") as fh:
        for n, row in enumerate(todo.itertuples(index=False), 1):
            rec = renders.get(int(row.instance_number), {})
            status, attrs = vt.file(row.sha256)
            line = {
                "sha256": row.sha256,
                "instance_number": int(row.instance_number),
                "confirmed_at": _now(),
                "render_ok": not rec.get("missing") and bool(rec.get("assertions")),
                "ours": rec.get("signature"),
                "vt_status": status,
                **_vt_fields(attrs),
            }
            fh.write(json.dumps(line) + "\n")
            fh.flush()
            if n % 25 == 0:
                log.info("confirm", extra={"done": n, "of": len(todo), "vt_calls": vt.calls})
    print(
        f"confirmed {len(todo)} files this run ({vt.calls} VirusTotal calls);"
        f" {len(done) + len(todo)} of {len(cand)} have a record"
    )


# ----------------------------------------------------------------------------- collect


def _ms_ca_certs(ours: dict | None) -> list[dict]:
    return [
        c
        for c in (ours or {}).get("chain") or []
        if c.get("is_ca") and f"O={SIGNER_ORG}" in str(c.get("subject"))
    ]


def _status(rec: dict | None, pinned: set[str]) -> str:
    if rec is None:
        return "not_confirmed"
    if not rec.get("render_ok"):
        return "render_missing"
    if rec.get("vt_status") == 404:
        return "vt_unknown"
    if rec.get("vt_verified") != "Signed":
        return "vt_not_signed"
    signers = rec.get("vt_signers") or []
    if not signers or not signers[-1].startswith(VT_ROOT_PREFIX):
        return "vt_other_root"
    ours = rec.get("ours") or {}
    tags = set(ours.get("tags") or [])
    if "verified" not in tags or "chain-broken" in tags or ours.get("signer_org") != SIGNER_ORG:
        return "ours_failed"
    if not any(c.get("sha256") in pinned for c in _ms_ca_certs(ours)):
        return "chain_unpinned"
    return "trusted"


def cmd_collect(a: argparse.Namespace, log) -> None:
    cand, dm = read_snapshot(_out(a.run_id, "draw.parquet"))
    recs = force_rescan._read_log(_out(a.run_id, "confirm.jsonl"))
    renders = _fetch_renders(ApiClient(), [], _out(a.run_id, "renders.jsonl"), log)

    # The pin: a Microsoft CA certificate counts once it signed enough files that VirusTotal
    # trusts and our checks pass. One confirmed file cannot vouch for its own issuer.
    seen: collections.Counter[str] = collections.Counter()
    subject: dict[str, str] = {}
    for rec in recs.values():
        if _status(rec, pinned=set()) != "chain_unpinned":
            continue
        for c in _ms_ca_certs(rec.get("ours")):
            seen[c["sha256"]] += 1
            subject[c["sha256"]] = str(c.get("subject"))
    pinned = {sha for sha, n in seen.items() if n >= a.pin_min_files}

    cand["status"] = [_status(recs.get(s), pinned) for s in cand["sha256"]]
    counts = cand["status"].value_counts()
    trusted = cand[cand["status"] == "trusted"].copy()
    evidence = pd.DataFrame(
        [
            {
                "sha256": s,
                "status": st,
                "flagged_at_t": bool(f),
                "ours_tags": ",".join((recs.get(s) or {}).get("ours", {}).get("tags") or [])
                if recs.get(s)
                else None,
                "ours_signer_cn": ((recs.get(s) or {}).get("ours") or {}).get("signer_cn"),
                "ours_signer_cert": ((recs.get(s) or {}).get("ours") or {}).get("signer_cert"),
                "ours_ms_cas": ",".join(c["sha256"] for c in _ms_ca_certs((recs.get(s) or {}).get("ours"))),
                "vt_status": (recs.get(s) or {}).get("vt_status"),
                "vt_verified": (recs.get(s) or {}).get("vt_verified"),
                "vt_chain": "; ".join((recs.get(s) or {}).get("vt_signers") or []),
                "vt_known_distributors": ",".join((recs.get(s) or {}).get("vt_known_distributors") or [])
                or None,
                "vt_trusted_verdict_org": (recs.get(s) or {}).get("vt_trusted_verdict_org"),
                "vt_first_submission": (recs.get(s) or {}).get("vt_first_submission"),
                "confirmed_at": (recs.get(s) or {}).get("confirmed_at"),
            }
            for s, st, f in zip(cand["sha256"], cand["status"], cand["flagged_at_t"], strict=True)
        ]
    )
    ev_out = _out(a.run_id, "confirm.parquet")
    ev_out.unlink(missing_ok=True)
    evidence.to_parquet(ev_out, index=False)

    lines = [
        f"inject collect -- run {a.run_id}: {len(cand)} candidates, {len(recs)} confirmed,"
        f" {len(trusted)} trusted",
        "status: " + ", ".join(f"{k}={int(v)}" for k, v in counts.items()),
        f"pinned Microsoft CA certificates (seen in >= {a.pin_min_files} confirmed chains):",
    ]
    for sha in sorted(pinned, key=lambda s: -seen[s]):
        lines.append(f"  {seen[sha]:5d}  {sha[:16]}  {subject[sha][:90]}")
    unpinned = [(s, n) for s, n in seen.items() if s not in pinned]
    if unpinned:
        lines.append("  below the pin: " + ", ".join(f"{s[:12]}x{n}" for s, n in unpinned))
    blue = evidence[evidence["status"] == "trusted"]
    lines += [
        f"trusted: {int(trusted['flagged_at_t'].sum())} flagged by an engine at T,"
        f" {len(trusted) - int(trusted['flagged_at_t'].sum())} clean;"
        f" with a VirusTotal known-distributor marker {int(blue['vt_known_distributors'].notna().sum())},"
        f" with a trusted verdict {int(blue['vt_trusted_verdict_org'].notna().sum())}",
    ]
    if trusted.empty:
        rep = _out(a.run_id, "collect.report.txt")
        rep.write_text("\n".join(lines) + "\n")
        print("\n".join(lines))
        print("no trusted files yet: run confirm first")
        return

    t_recs = [renders[int(i)] for i in trusted["instance_number"]]
    t_counts = pd.DataFrame(
        [force_rescan._counts(r) for r in t_recs], columns=["n_definite", "n_malicious", "n_responded"]
    )
    n = len(trusted)
    base = pd.DataFrame(
        {
            "sha256": trusted["sha256"].values,
            "instance_number": trusted["instance_number"].astype("int64").values,
            "scoring_moment": trusted["scoring_moment"].values,
            "label_instance_number": pd.array([pd.NA] * n, dtype="Int64"),
            "label_moment": pd.Series([pd.NaT] * n, dtype="datetime64[ns]").values,
            "label_gap": pd.array([None] * n, dtype="string"),
            "n_definite": t_counts["n_definite"].astype("int64").values,
            "n_malicious": t_counts["n_malicious"].astype("int64").values,
            "n_responded": t_counts["n_responded"].astype("int64").values,
            "scan_config": pd.array([None] * n, dtype="string"),
            "provenance": INJECTED_PROVENANCE,
            "incumbent_polyscore": trusted["incumbent_polyscore"].astype("float64").values,
            "label_polyscore": float("nan"),
        }
    )
    rows: list[dict] = []
    for sha, t in zip(trusted["sha256"], t_recs, strict=True):
        rows += force_rescan._assertion_rows(sha, "feature", t)
    assertions = pd.DataFrame(rows)
    assertions["verdict"] = assertions["verdict"].astype("boolean")
    assertions["instance_number"] = assertions["instance_number"].astype("int64")
    assertions["bid"] = assertions["bid"].astype("int64")
    assertions = assertions.sort_values(["sha256", "scan_role", "author"]).reset_index(drop=True)

    base = base.sort_values("sha256").reset_index(drop=True)
    base_out = fresh(settings.path("base", f"injected_{a.run_id}.parquet"), a.overwrite)
    base_out.with_suffix(".assertions.parquet").unlink(missing_ok=True)
    pinned_cas = [
        {"sha256": s, "subject": subject[s], "files": seen[s]} for s in sorted(pinned, key=lambda s: -seen[s])
    ]
    rule = (
        f"VirusTotal signature_info.verified == 'Signed' with a '{VT_ROOT_PREFIX}*' trust anchor; lief tags"
        f" 'verified' and not 'chain-broken'; signer organization '{SIGNER_ORG}';"
        " a pinned Microsoft CA in the embedded chain"
    )
    meta = dict(
        run_id=a.run_id,
        source="index_authenticode+virustotal",
        prefixes=dm["prefixes"],
        pi_base=dm["pi_base"],
        draw_content_sha256=dm["content_sha256"],
        candidates=int(len(cand)),
        statuses={k: int(v) for k, v in counts.items()},
        rule=rule,
        pin_min_files=a.pin_min_files,
        pinned_cas=pinned_cas,
        label="benign by attestation, grade 2 (different modality: code signing)",
        assertion_rows=int(len(assertions)),
        engine_key="author = engine id from the full render; author_name beside it",
        deviations=DEVIATIONS,
    )
    write_snapshot(base, base_out, stage="00c_collect", **meta)
    assertions.to_parquet(base_out.with_suffix(".assertions.parquet"), index=False)
    base_manifest = json.loads(base_out.with_suffix(".manifest.json").read_text())

    cohort = base.assign(
        stratum=STRATUM,
        pi=float("nan"),
        pi_draw=float("nan"),
        pi_base=float(dm["pi_base"]),
        n_available=int(dm["frame_rows"]),
        n_draw=n,
    )
    run_out = fresh(settings.path("runs", a.run_id, "injected.parquet"), a.overwrite)
    write_snapshot(
        cohort,
        run_out,
        stage="00c_collect",
        base_snapshot=str(base_out),
        base_content_sha256=base_manifest["content_sha256"],
        **meta,
    )
    lines += [
        "",
        f"definite verdicts at T: p10 {t_counts['n_definite'].quantile(0.1):.0f}"
        f"  p50 {t_counts['n_definite'].median():.0f}"
        f"  p90 {t_counts['n_definite'].quantile(0.9):.0f}; malicious at T: "
        + ", ".join(f"{k}={v}" for k, v in sorted(t_counts["n_malicious"].value_counts().items())),
        f"base: {base_out} ({len(base)} rows, {len(assertions)} assertion rows)",
        f"arm: {run_out} ({len(cohort)} rows, stratum {STRATUM}, pi NaN); evidence: {ev_out}",
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

    d = sub.add_parser(
        "draw", help="the Microsoft-signed, verified, scanned-first candidates under the prefixes"
    )
    d.add_argument(
        "--prefix", action="append", required=True, help="a lowercase hex sha256 prefix; repeat for a union"
    )
    d.add_argument(
        "--candidates", type=int, default=600, help="how many to carry into confirm, flagged-at-T first"
    )
    d.add_argument("--window-start", default=None, help="first scan on or after this date (optional)")
    d.add_argument("--window-end", default=None, help="first scan before this date (optional)")

    c = sub.add_parser(
        "confirm", help="the first-scan render and VirusTotal's signature check, per candidate"
    )
    c.add_argument(
        "--limit", type=int, default=480, help="confirm at most this many this run (the daily quota)"
    )
    c.add_argument(
        "--vt-rate", type=float, default=230.0, help="VirusTotal lookups per hour, under the key's cap"
    )

    k = sub.add_parser("collect", help="decide the trusted set and write the arm in 01a's and 01b's shapes")
    k.add_argument(
        "--pin-min-files",
        type=int,
        default=5,
        help="confirmed chains a Microsoft CA must appear in to be pinned",
    )

    a = ap.parse_args()
    log = configure()
    {"draw": cmd_draw, "confirm": cmd_confirm, "collect": cmd_collect}[a.cmd](a, log)


if __name__ == "__main__":
    main()
