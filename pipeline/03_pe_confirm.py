#!/usr/bin/env python3
"""Step 3 — confirm PE membership against OpenSearch, through the Cloudflare Access door.

Writes newline-delimited sha256 of every artifact in the window whose pefile document
exists in the index. A rejected pefile document is stripped to {} and removed at
serialization, so `exists: pefile.imphash` is EXACT: field present <=> pefile.PE() parsed
the file. Safe to take from ES because the test is time-invariant.

Reaches the domain through kibana.polyswarm.network, which fronts the whole OpenSearch
REST API behind Cloudflare Access (measured 2026-10-02). No kubectl.

    cloudflared access login https://kibana.polyswarm.network          # browser SSO, once
    export CF_ACCESS_TOKEN=$(cloudflared access token -app https://kibana.polyswarm.network)
    # if the domain's security plugin wants an internal user on top (unverified):
    export POLYSCORE_ES_USER=... POLYSCORE_ES_PASSWORD=...

    python pipeline/03_pe_confirm.py --window-start 2026-09-08 --window-end 2026-10-01 --count-only
    python pipeline/03_pe_confirm.py --window-start 2026-09-08 --window-end 2026-10-01 > pe_confirmed.txt

Run --count-only FIRST. It is one request, read-only, and it settles whether the second
auth layer is needed: a 401 with a security-plugin body means set the ES user; a count
means you are through. stdlib only, so it runs before the venv exists.

Contract: specs/09-extraction-runbook.md step 3.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import sys
import urllib.error
import urllib.request

HOST = os.environ.get("POLYSCORE_ES_URL", "https://kibana.polyswarm.network").rstrip("/")
INDEX = os.environ.get("POLYSCORE_ES_INDEX", "metadata-*")


def _headers() -> dict[str, str]:
    tok = os.environ.get("CF_ACCESS_TOKEN")
    if not tok:
        sys.exit("CF_ACCESS_TOKEN unset: run `cloudflared access token -app https://kibana.polyswarm.network`")
    h = {"cf-access-token": tok, "Content-Type": "application/json"}
    u, p = os.environ.get("POLYSCORE_ES_USER"), os.environ.get("POLYSCORE_ES_PASSWORD")
    if u and p:
        h["Authorization"] = "Basic " + base64.b64encode(f"{u}:{p}".encode()).decode()
    return h


def _call(method: str, path: str, body: dict | None = None) -> dict:
    req = urllib.request.Request(f"{HOST}{path}", method=method, headers=_headers(),
                                 data=json.dumps(body).encode() if body is not None else None)
    try:
        with urllib.request.urlopen(req, timeout=120) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        text = e.read().decode(errors="replace")[:400]
        if e.code in (401, 403):
            sys.exit(f"{e.code} from OpenSearch after Access: the domain wants an internal user "
                     f"-- set POLYSCORE_ES_USER/PASSWORD (polyswarm_ro role). Body: {text}")
        if e.code == 302 or "cloudflareaccess" in text:
            sys.exit("Redirected to Cloudflare Access login: CF_ACCESS_TOKEN is missing or expired")
        sys.exit(f"HTTP {e.code} {path}: {text}")


def _query(start: str, end: str) -> dict:
    return {"bool": {"filter": [
        {"term":   {"meta_community": "_public"}},
        {"exists": {"field": "pefile.imphash"}},
        {"range":  {"scan.first_seen": {"gte": start, "lt": end}}},
    ]}}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--window-start", required=True)
    ap.add_argument("--window-end", required=True)
    ap.add_argument("--count-only", action="store_true", help="one _count request; run this first")
    ap.add_argument("--page", type=int, default=5000)
    a = ap.parse_args()
    q = _query(a.window_start, a.window_end)

    n = _call("POST", f"/{INDEX}/_count", {"query": q})["count"]
    print(f"# {n} confirmed-PE artifacts in [{a.window_start}, {a.window_end})", file=sys.stderr)
    if a.count_only:
        return

    page = _call("POST", f"/{INDEX}/_search?scroll=5m",
                 {"query": q, "size": a.page, "_source": ["artifact.sha256"], "sort": ["_doc"]})
    sid, seen = page["_scroll_id"], 0
    while page["hits"]["hits"]:
        for h in page["hits"]["hits"]:
            print(h["_source"]["artifact"]["sha256"]); seen += 1
        page = _call("POST", "/_search/scroll", {"scroll": "5m", "scroll_id": sid})
        sid = page["_scroll_id"]
    _call("DELETE", "/_search/scroll", {"scroll_id": sid})
    print(f"# wrote {seen} sha256 (count said {n})", file=sys.stderr)
    if seen != n:
        print("# WARNING: scroll total != count -- the index moved during the scroll", file=sys.stderr)


if __name__ == "__main__":
    main()
