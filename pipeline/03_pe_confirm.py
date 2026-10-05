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

`--direct` is the other door: inside `artifact-index-cli-terminal` (stage today; prod once
exec is granted) the domain is reachable without Cloudflare, and the pod's own
ELASTICSEARCH_URL / ELASTICSEARCH_USER / ELASTICSEARCH_PASSWORD carry the endpoint and the
internal user. Stage's kibana.internal.polyswarm.network door sits in a private DNS zone
(measured 2026-10-05), so on stage this is the only path. Stdin keeps kubectl cp out of it:

    kubectl --context us-stage-blue -n ai exec -i <cli-pod> -- python3 - \
        --window-start 2024-01-01 --window-end 2026-09-01 --count-only --direct \
        < pipeline/03_pe_confirm.py

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

INDEX = os.environ.get("POLYSCORE_ES_INDEX", "metadata-*")
DIRECT = False  # set by --direct: inside the CLI pod, no Cloudflare layer


def _host() -> str:
    if DIRECT:
        url = os.environ.get("POLYSCORE_ES_URL") or os.environ.get("ELASTICSEARCH_URL")
        if not url:
            sys.exit("--direct needs POLYSCORE_ES_URL or the pod's ELASTICSEARCH_URL")
        return url.rstrip("/")
    return os.environ.get("POLYSCORE_ES_URL", "https://kibana.polyswarm.network").rstrip("/")


def _headers() -> dict[str, str]:
    h = {"Content-Type": "application/json"}
    if not DIRECT:
        tok = os.environ.get("CF_ACCESS_TOKEN")
        if not tok:
            sys.exit("CF_ACCESS_TOKEN unset: run `cloudflared access token -app "
                     "https://kibana.polyswarm.network` -- or --direct inside the CLI pod")
        h["cf-access-token"] = tok
    u = os.environ.get("POLYSCORE_ES_USER") or (DIRECT and os.environ.get("ELASTICSEARCH_USER"))
    p = os.environ.get("POLYSCORE_ES_PASSWORD") or (DIRECT and os.environ.get("ELASTICSEARCH_PASSWORD"))
    if u and p:
        h["Authorization"] = "Basic " + base64.b64encode(f"{u}:{p}".encode()).decode()
    return h


def _call(method: str, path: str, body: dict | None = None) -> dict:
    req = urllib.request.Request(f"{_host()}{path}", method=method, headers=_headers(),
                                 data=json.dumps(body).encode() if body is not None else None)
    try:
        with urllib.request.urlopen(req, timeout=300) as r:
            out = json.loads(r.read())
    except urllib.error.HTTPError as e:
        _explain(e, path)
    # A shard that drops out mid-scroll is reported here and nowhere else; the page just
    # comes back short. Measured on stage 2026-10-05: 795,000 of 966,504 with exit 0.
    failed = (out.get("_shards") or {}).get("failed", 0)
    if failed:
        raise ShardFailure(f"{failed} shard(s) failed on {path}: {json.dumps(out['_shards'])[:400]}")
    return out


class ShardFailure(RuntimeError):
    """A page came back with a failed shard. Stage's node cancels scroll tasks under heap
    pressure (search backpressure: "heap usage exceeded"), and the page is simply short --
    measured 2026-10-05 at 795,000 and 760,000 of 966,504. The caller retries smaller."""


def _explain(e: urllib.error.HTTPError, path: str) -> None:
    text = e.read().decode(errors="replace")[:400]
    if e.code in (401, 403):
        sys.exit(f"{e.code} from OpenSearch: the domain wants an internal user -- set "
                 f"POLYSCORE_ES_USER/PASSWORD (door) or check ELASTICSEARCH_USER (--direct). "
                 f"Body: {text}")
    if e.code == 302 or "cloudflareaccess" in text:
        sys.exit("Redirected to Cloudflare Access login: CF_ACCESS_TOKEN is missing or expired")
    sys.exit(f"HTTP {e.code} {path}: {text}")


def _query(start: str, end: str) -> dict:
    return {"bool": {"filter": [
        {"term":   {"meta_community": "_public"}},
        {"exists": {"field": "pefile.imphash"}},
        {"range":  {"scan.first_seen": {"gte": start, "lt": end}}},
    ]}}


def _scroll(q: dict, page_size: int) -> list[str]:
    page = _call("POST", f"/{INDEX}/_search?scroll=5m",
                 {"query": q, "size": page_size, "_source": ["artifact.sha256"], "sort": ["_doc"]})
    sid, shas = page["_scroll_id"], []
    try:
        while page["hits"]["hits"]:
            shas.extend(h["_source"]["artifact"]["sha256"] for h in page["hits"]["hits"])
            page = _call("POST", "/_search/scroll", {"scroll": "5m", "scroll_id": sid})
            sid = page["_scroll_id"]
    finally:
        try:
            _call("DELETE", "/_search/scroll", {"scroll_id": sid})
        except (ShardFailure, SystemExit):
            pass
    return shas


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--window-start", required=True)
    ap.add_argument("--window-end", required=True)
    ap.add_argument("--count-only", action="store_true", help="one _count request; run this first")
    ap.add_argument("--page", type=int, default=2000, help="scroll page; halved on each shard failure")
    ap.add_argument("--retries", type=int, default=4)
    ap.add_argument("--direct", action="store_true",
                    help="inside the artifact-index CLI pod: no Cloudflare layer; endpoint and "
                         "user from the pod's ELASTICSEARCH_* env")
    a = ap.parse_args()
    global DIRECT
    DIRECT = a.direct
    q = _query(a.window_start, a.window_end)

    n = _call("POST", f"/{INDEX}/_count", {"query": q})["count"]
    print(f"# {n} confirmed-PE artifacts in [{a.window_start}, {a.window_end})", file=sys.stderr)
    if a.count_only:
        return

    # Buffered, not streamed: a retry must not leave half a list on stdout.
    page_size, shas = a.page, []
    for attempt in range(a.retries + 1):
        try:
            shas = _scroll(q, page_size)
            break
        except ShardFailure as e:
            print(f"# attempt {attempt + 1} at page {page_size}: {e}", file=sys.stderr)
            if attempt == a.retries:
                sys.exit("scroll kept losing shards; the node is under pressure -- retry later")
            page_size = max(page_size // 2, 100)
    for sha in shas:
        print(sha)
    seen = len(shas)
    print(f"# wrote {seen} sha256 (count said {n})", file=sys.stderr)
    if seen != n:
        # Not a warning: a short list is a biased gate, and the draw downstream cannot tell.
        sys.exit(f"scroll returned {seen} but count said {n}: rerun; if it repeats, the index "
                 f"moved during the scroll or a shard dropped out")


if __name__ == "__main__":
    main()
