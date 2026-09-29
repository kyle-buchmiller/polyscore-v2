# 09 — Extraction runbook

## Scope

How to actually run stage 01 against production from a workstation: what to
authenticate, what to run, in what order, and what each step should return.

## Invariants

- **Read-only throughout.** Nothing in this runbook writes to production.
- **No credential is ever committed, pasted into a transcript, or written into this
  repo.** They are read from the cluster into a shell variable and left there.
- **Every step's output is inspected before the next one runs.** Step 2 in particular
  can invalidate the plan; running step 4 without reading step 2 is the whole failure
  mode this ordering exists to prevent.

---

## What this pulls, and why

The deliverable is **one Parquet snapshot of ~10,000 Windows PE artifacts**, each carrying
two moments in its life and the engine evidence at each.

| What | Shape | Why we need it |
|---|---|---|
| **Artifact identity** | `sha256`, deduped | §1 counts per artifact, never per scoring event — a file a thousand customers look up counts once |
| **The feature scan (T)** | one `artifactinstance` row | §2 fixes the scoring moment at bounty reveal; every feature must be true at or before it |
| **The label scan (T+30)** | a second `artifactinstance` row, ≥30 days later | §4's horizon. This separation is the whole point — see below |
| **Engine assertions at each scan** | one row per engine: `author`, `verdict`, `engine_metadata`, `bid` | **the entire feature space** |
| **Sampling bookkeeping** | `stratum`, `pi`, `provenance` | §9. `pi` is the one column no later step can reconstruct |
| **PE static features** | ~120 columns from psstorage | stage 04, not here — see *What to expect when downloading* |

### Why *these* rows and not others

**The assertions are the model.** PolyScore is a **second-order** model: it never sees file
bytes, only what engines said about them ([`0002`](../decisions/0002-metadata-not-binaries.md)).
So the assertion rows are not context — they are the feature matrix. Everything else in the
pull exists to give them a timestamp and a label.

**Two scans, not one, is what makes the label legitimate.** If the label came from the same
scan as the features, it would be a threshold over the very columns being fitted — grade 0,
banned outright, and precisely what destroyed the 2023 model (its labelling function filtered
to `verdict == True` and then counted those same verdicts). Pulling a *second* scan 30 days
later makes the label grade 1: still engine-derived, but carrying information the features do
not. Full ladder in [`03-labels.md`](./03-labels.md), the decision in
[`0004`](../decisions/0004-labels-time-separated-for-the-pilot.md).

**Engine identity must be the address, never the display name.** `assertions.author` holds a
stable microengine address; the human-readable name is resolved at render time from an
external, mutable, unversioned lookup. The 2023 pipeline keyed features by name, so
`SentinelOne` and `SentinelOne Static ML` became two columns, names drifted *between training
runs*, and its committed models are mutually incomparable. Background: R2 in
[`07-requests.md`](./07-requests.md).

**`pi` is unrecoverable.** Inclusion probability depends on a band's population at draw time
and how much of its target share was already filled. Skip it and the cohort can never be
reweighted to natural prevalence — which means it can support ranking and never calibration.
One column, written once, or the pull was half-wasted.

Full field-level contract: [`02-data.md`](./02-data.md). The decisions that fix the
population, the moment and the draw: [`01-estimand.md`](./01-estimand.md) §1, §2, §9, §10.

---

## Why this is five steps and not one command

Every instinct says "just export it." Four things make that impossible here, and each one
independently forces a step.

**No single store holds the answer.** Postgres keeps per-scan history and the cohort filters
but cannot cheaply say whether a file is a PE. OpenSearch answers that exactly — and carries
neither `community` nor `scan_config`, so it cannot express the feed filter. The extraction
is inherently two-store, so *some* intersection step exists no matter how it is written.

**The GUIs structurally cannot produce this.** Kibana reads OpenSearch, which holds **one
document per file, overwritten on every rescan**, containing only `first_scan` and
`latest_scan`. It has no notion of "as of T" and never will. Superset is a dashboarding tool
over ClickHouse and Postgres; it can show you aggregates but cannot record a sampling design.
Neither can emit `pi`, and an export without `pi` is not a cohort — it is a spreadsheet.

**The public API is the wrong shape.** It is per-artifact lookup, rate-limited, and returns
the *current rendered view* with engine display names rather than addresses — which is
exactly the identity downgrade that broke the last model.

**The survey has to be able to stop the work.** Step 2 exists to test two assumptions that
were written before anyone saw data: that the contested band is ~45% of the population, and
that 10,000 artifacts have a T+30 scan to label from. If either is wrong, the right response
is to change the design — not to proceed with a cohort that was drawn anyway. A single
command has no place to put that decision.

There is a fifth reason that is really a lesson: the 2023 extraction **was** close to one
command, and it had no `ORDER BY`, no date window, no feed filter and no recorded sampling.
Its cohort cannot be reconstructed today. The steps below are each a place where that
failure was possible.

---

## The structural fact that shapes everything

**Every production data store is VPC-private.** The Postgres cluster is in private
subnets, OpenSearch is a `vpc-…` endpoint, ClickHouse is a ClusterIP service. There is
**no bastion, no developer VPN, and no `psql` wrapper.** (`charts/charts/vpn-concentrator`
is a Mullvad *egress* concentrator for sandbox detonation — not developer ingress.)

There are exactly three doors, and two of them are `kubectl`:

| Door | Use it for |
|---|---|
| `kubectl port-forward` to an in-cluster service | **Postgres** (via the pooler) and ClickHouse — lets you run local `.sql` files |
| `kubectl exec` into `artifact-index-cli-terminal` | **OpenSearch** and **psstorage** — the pod already holds the endpoints, credentials and the app's own clients |
| `kibana.polyswarm.network` | ad-hoc OpenSearch browsing, if you have a `polyswarm_ro` user |

---

## Permissions required

Two independent layers, and conflating them is the most likely way to get stuck.

**Layer 1 — AWS IAM**, for cluster authentication:

```bash
aws sso login --sso-session base
aws sts get-caller-identity --profile prod     # confirms the role you actually hold
```

`sam init` grants **`ReadOnlyProd`** by default; `AdminProd` needs an explicit `--admin`.
Read-only is the correct posture for everything in this runbook.

**Layer 2 — Kubernetes RBAC**, for what you may do once authenticated. **This is the one
that surprises people**, because two steps here need verbs that are *not* read-only in RBAC
terms: `kubectl exec` is `create` on `pods/exec`, and `port-forward` is `create` on
`pods/portforward`. Neither is included in the standard `view` ClusterRole. An IAM role named
"ReadOnly" mapped to `view` would let you list pods and block every step below.

Check all four in one go before starting:

```bash
kubectl --context us-prod auth can-i get    secrets          -n ai       # Step 0
kubectl --context us-prod auth can-i create pods/portforward -n pgpool   # Steps 1, 2, 4
kubectl --context us-prod auth can-i create pods/exec        -n ai       # Step 3
kubectl --context us-prod auth can-i create pods/portforward -n ai       # Stage 04 (optional)
```

| Step | IAM | Kubernetes | Store credential |
|---|---|---|---|
| 0 · `.env` | SSO session, prod account | `get secrets` in `ai` | — (this *reads* the credential) |
| 1 · Verify | ” | `create pods/portforward` in `pgpool` | Postgres user from `DB_URI_RO` |
| 2 · Survey | ” | same | same |
| 3 · PE confirm | ” | `create pods/exec` in `ai` | OpenSearch basic auth — **already in the pod env**, you never handle it |
| 4 · Draw | ” | `create pods/portforward` in `pgpool` | Postgres user from `DB_URI_RO` |
| 5 · Snapshot | — | — | local only |
| *(stage 04)* | ” | `create pods/exec` **or** `portforward` in `ai` | **none** — psstorage file GET is unauthenticated |

**No PolySwarm API key is needed for any read step.** One appears only if labels have to be
manufactured prospectively: `ai instance rescan` re-POSTs through the public API using the
service's `AKM_API_KEY`, which is already set inside the CLI pod. Separately, *knowing* that
key's value is what lets step 1 exclude internal re-submissions by `api_key` — which is why
it sits on the verification list rather than here.

---

## One-time setup

```bash
aws sso login --sso-session base        # the shared Identity Center session
psi setup                               # creates/repoints the kubeconfig contexts
kubectl config get-contexts             # expect us-prod, eu-prod, processing-prod, us-stage-blue, …
```

Two things worth knowing before you start:

- **The default prod role is `ReadOnlyProd`.** `sam init` grants `AdminProd` only with an
  explicit `--admin`. For this work the read-only role is the correct posture — if a step
  below fails on permissions, that is the guardrail, not a misconfiguration.
- **Contexts come from `psi setup`, not `sam`.** And the stage contexts are
  `us-stage-blue` / `eu-stage-blue` — there is no `us-stage`.

---

## Step 0 · Point `.env` at the read replica

The connection string lives in the cluster. Pull it, rewrite the host for the
port-forward, and strip the SQLAlchemy dialect suffix that `psql` does not understand:

```bash
# The app's own read-replica URI. NOTE: this prints a credential to your terminal.
RO_URI=$(kubectl --context us-prod -n ai get secret artifact-index-cli-secrets \
           -o jsonpath='{.data.DB_URI_RO}' | base64 -d)

# For SQLAlchemy (polyscore-v2) — keep the dialect, repoint the host:
echo "POLYSCORE_DB_URI=${RO_URI/@pgpool.pgpool.svc.cluster.local/@127.0.0.1:5432}" >> .env

# For psql — same thing without '+psycopg':
PSQL_URI="${RO_URI/+psycopg/}"
PSQL_URI="${PSQL_URI/@pgpool.pgpool.svc.cluster.local/@127.0.0.1:5432}"
```

**What `ai-ro` actually is.** The pooler maps the logical database `ai-ro` to the Aurora
**reader endpoint** (`…cluster-ro-…`). The read-only-ness is *physical* — a reader endpoint
cannot accept writes — rather than a restricted Postgres role. There is a `postgres_ro`
role, but it is created by `ai db fix-ro-user` for local/e2e only and does not exist in
prod. So: you cannot write through this connection even by accident, and you should still
not try.

Open the tunnel and leave it running:

```bash
kubectl --context us-prod -n pgpool get svc          # confirm the Service name first
kubectl --context us-prod -n pgpool port-forward svc/pgpool 5432:5432
```

> The pgdog chart is external, so `svc/pgpool` is inferred from `fullnameOverride: pgpool`
> rather than read from a rendered template. Check it once with `get svc`.

**Produces:** no data artifact — environment only.

- `.env` containing `POLYSCORE_DB_URI` pointed at `127.0.0.1:5432`
- a live `port-forward` process (leave the terminal open; every psql step needs it)

**Done when** `psql "$PSQL_URI" -c 'select 1'` returns `1`.

---

## Step 1 · Verify — `pipeline/sql/00_verify.sql`

```bash
psql "$PSQL_URI" -f pipeline/sql/00_verify.sql
```

**Expect:** seconds, six small result sets. Read every one; each decides a filter.

| Check | What a surprise means |
|---|---|
| `scan_configs` | any name beyond `default / feed / more-time / most-time` is a filter bug in waiting |
| `meta_community` | if `'_public'` returns nothing you filtered on the metrics bucketing (`'public'`) — the leading underscore is load-bearing |
| `extended_type` | tells you whether a `PE32%` pre-filter has usable recall, and whether `.NET` and `PE32+` are described as expected |
| feed behaviour | if feed rows are mostly *revealed* rather than storage-only, §10's breadth assumption needs revisiting |
| `any_detections` | two code reads disagreed; this settles it |
| clock check | a large constant offset between `created` and `completed`, or any `impossible_rows`, means the two columns are on different clocks and every duration downstream is wrong |

**Produces:** `data/reports/verify.txt` — six result sets, read by a human, not consumed
by any later stage.

```bash
psql "$PSQL_URI" -f pipeline/sql/00_verify.sql | tee data/reports/verify.txt
```

It is an input to *decisions*, not to code: its answers get hand-carried into the filters in
`01_survey.sql` / `02_draw.sql` and, where they change one, into `decisions/`.

**Done when** all six returned and none surprised you. A surprise is a stop, not a note.

---

## Step 2 · Survey — `pipeline/sql/01_survey.sql` ← **the decision point**

```bash
psql "$PSQL_URI" -f pipeline/sql/01_survey.sql | tee data/reports/survey.txt
```

**Expect:** minutes, not seconds — it aggregates over `assertions`. One row per stratum.

**This step draws nothing, and that is deliberate.** It exists so the two assumptions most
likely to be wrong get tested before anybody spends a download on them:

1. **Is the cohort there?** The `labellable` column — candidates that have a T+30 scan to
   label from — is the real cohort size. `artifacts` minus `labellable` is a *waiting*
   problem, not a data problem.
2. **Do the bands populate?** Compare `pct_of_labellable` against §9's targets
   (contested 45, leaning 15/15, consensus 10/10). Those numbers are a claim about where
   the hard cases live, written before anyone looked at data.

**If `contested` comes back at 3%, move the bands — not the draw.** Record the revision in
`decisions/`, per `99-open-questions.md`. If total `labellable` is far below 10,000, widen
the window forward or lower the cohort size and say so. **Do not relax the feed filter to
make the number look better.**

**Produces:** `data/reports/survey.txt` — one row per stratum, six or seven rows total.

| Column | Meaning |
|---|---|
| `stratum` | the six §9 bands plus `below_floor` |
| `artifacts` | candidates in that band |
| `labellable` | **the real cohort size** — those with a T+30 scan |
| `pct_of_labellable` | compare against §9's targets: 45 / 15 / 15 / 10 / 10 |
| `avg_definite_verdicts`, `avg_responded` | sanity check on engine coverage per band |

Human-read, like step 1 — nothing downstream parses it. Its output is a **go/no-go plus
possibly a revised band definition**, and a revision is recorded in `decisions/` before
step 4 runs.

**Done when** you can state, in one sentence, how many labellable artifacts exist and
whether the §9 shares survive contact with the data.

---

## Step 3 · Confirm PE via OpenSearch

The authoritative PE test cannot be asked of Postgres — see `02-data.md` for the
out-of-line trap that makes the obvious query return a set skewed toward *rejections*.

**The index is `metadata-*`, not `artifacts7`.** `artifacts7` is the template *directory*
(revision 7); the template's name is `artifacts` and its pattern is `metadata-*`. Concrete
indices are `metadata-<index_id>` where `index_id` is the number of whole weeks since the
Unix epoch of the artifact's `first_seen` (`floor(epoch / 604800)`). Every read path in
`artifact-index` queries the wildcard, and so should we.

OpenSearch is an AWS-managed VPC endpoint rather than a k8s Service, so `port-forward` does
not reach it. Run from the CLI pod, which already holds the endpoint and basic-auth
credentials:

```bash
kubectl --context us-prod -n ai exec -i deploy/artifact-index-cli-terminal -- \
  python - <<'PY' > data/snapshots/pe_confirmed.txt
from artifact_index.app import web
from artifact_index import app as ai
with web.app_context():
    body = {"query": {"bool": {"filter": [
                {"term":   {"meta_community": "_public"}},
                {"exists": {"field": "pefile.imphash"}},
                {"range":  {"scan.first_seen": {"gte": "2026-09-08", "lt": "2026-10-01"}}},
            ]}},
            "_source": ["artifact.sha256"]}
    page = ai.elastic.search(index="metadata-*", body=body, scroll="5m", size=5000)
    sid = page["_scroll_id"]
    while page["hits"]["hits"]:
        for h in page["hits"]["hits"]:
            print(h["_source"]["artifact"]["sha256"])
        page = ai.elastic.scroll(scroll_id=sid, scroll="5m")
PY
wc -l data/snapshots/pe_confirmed.txt
```

`exists: pefile.imphash` is **exact** here: a rejected `pefile` document is stripped to
`{}` and removed from the ES document entirely, so presence of the field ⟺ `pefile.PE()`
parsed the file. Taking this one fact from ES is safe precisely because it is
**time-invariant** — a file's bytes do not change, so whether the parser handled them
cannot drift. Nothing time-varying may come from ES.

> `app.elastic` is an **OpenSearch** client (`opensearch-py`). Do not
> `from elasticsearch import …` inside that pod.

**Produces:** `data/snapshots/pe_confirmed.txt` — newline-delimited sha256, one per line,
no header.

```
3f5a1c...  (64 hex chars)
b91e07...
```

This is the **confirmed PE population**, and it is the denominator `π_i` will be computed
against — which is why it must exist before step 4 and not after.

**Done when** `wc -l` is a plausible fraction of step 2's `labellable` count. A number far
*below* it means the mimetype pre-filter was admitting non-PE files (expected — it admits
CAB, MSI, MS Access and VBE). A number far *above* it means the date range in the ES query
does not match the SQL window.

---

## Step 4 · Draw — `pipeline/sql/02_draw.sql`

Load the confirmed set into a temp table **in the same session** as the draw, then run it:

```bash
psql "$PSQL_URI" \
  -c "CREATE TEMP TABLE pe_confirmed (sha256 char(64) PRIMARY KEY);" \
  -c "\copy pe_confirmed FROM 'data/snapshots/pe_confirmed.txt'" \
  -f pipeline/sql/02_draw.sql \
  --csv -o data/snapshots/cohort.csv
```

**The temp table and the draw must share one `psql` invocation** — a temp table dies with
its session, and a second invocation silently gets an empty one, which would draw from
nothing.

**Expect:** ~10,000 rows, seconds once the survey has warmed the same joins.

**Check three things before using the output**, per the notes at the foot of the SQL:

- `n_draw = ceil(cohort_size × share)` for every band. Where `n_draw = n_available`
  instead, that band **under-filled** — report the shortfall, never back-fill from a
  neighbour.
- `pi ≤ 1.0` everywhere. `pi = 1.0` means a band was taken whole: legitimate, but that
  band carries no sampling variance.
- Row count equals the sum of `n_draw`. A mismatch means a join fanned out.

**Produces:** `data/snapshots/cohort.csv` — one row per drawn artifact, ~10,000 rows.

| Column | Note |
|---|---|
| `sha256` | the artifact |
| `instance_number` | the **feature** scan (T) — join assertions on this |
| `scoring_moment` | T; every feature must be true at or before it |
| `label_instance_number`, `label_moment` | the **label** scan (T+30) |
| `stratum` | §9 band |
| `n_definite`, `n_malicious` | the inputs to `m`, kept so the band is auditable |
| **`pi`** | **inclusion probability — the irreplaceable column** |
| `provenance` | `organic` here; the injection arm is added separately |
| `n_available`, `n_draw` | per-band, carried so under-fill is visible in the file itself |

**Done when** the three checks at the foot of `02_draw.sql` pass: `n_draw` matches the
target for every band, `pi ≤ 1.0` everywhere, and the row count equals the sum of `n_draw`.

---

## Step 5 · Freeze the snapshot

```bash
make extract     # 01_extract.py: cohort + assertions -> parquet + manifest
```

From here the **snapshot, not the query, is the unit of reproducibility.** Re-running the
query next week returns different rows and silently invalidates every downstream stage.
The manifest records the query, the window, the seed, the row count and a content hash.

**Produces:** `data/snapshots/<run>.parquet` + `<run>.manifest.json` — **the unit of
reproducibility from here on.**

The Parquet is **long, not wide**: one row per `(sha256, instance_number, author)`, so ~20–30
rows per artifact per scan and two scans per artifact. Stage 04 pivots it to the wide feature
matrix; keeping it long here means a re-pivot never needs a re-download.

| Column group | Columns |
|---|---|
| keys | `sha256`, `instance_number`, `author` |
| evidence | `verdict` (nullable bool), `engine_metadata`, `bid` |
| timing | `scoring_moment`, `label_moment`, `scan_role` (`feature` \| `label`) |
| bookkeeping | `stratum`, `pi`, `provenance` — **never features**, enforced by `BOOKKEEPING_NOT_FEATURES` |

Parquet, never CSV: it keeps column types and will not silently turn a hash into a number, or
`verdict IS NULL` into `False`.

The manifest records the query text, the window, the seed, the row count, the estimand
version and a content hash — everything needed to prove a later result came from this cohort.

**Done when** the manifest's row count matches the Parquet's, and `estimand_version` reads
`4`.

---

## What to expect when downloading

**Volumes** (estimated from the schema, not measured — treat as order-of-magnitude):

| What | Rows | Size |
|---|---|---|
| Cohort | ~10,000 | trivial |
| Assertions at T | ~20–30 per artifact ⇒ 200–300k | |
| Assertions at T+30 | same again | |
| **Stage 01 total** | **~400–600k rows** | **~100 MB raw, far less as Parquet** |

**Stage 01 is small and fast.** The expensive fetch is deliberately *not* here.

**The slow part comes later, at stage 04.** PE static features live in psstorage, not
Postgres, because in us-prod anything over **2000 bytes** goes out-of-line and a parsed-PE
document is far larger. So stage 04 makes ~10,000 blob fetches:

```
ps://artifact-index/metadata/<136 hex chars>        # sha256 + sha1 + md5 concatenated
s3://ps-storage-prodv2-artifact-index/metadata/ab/cd/ef/<key>
```

Three things about those blobs:

- They are **gzip-compressed** with `content-encoding: gzip`. The client handles it; a raw
  `aws s3 cp` gives you gzip bytes.
- The `metadata` namespace has **no expiration policy**, so they are not lifecycle-reaped.
- File GET on the storage service is **unauthenticated** (`AllowAny`), so a port-forward to
  `svc/polyswarm-storage-web:5702` reads blobs with no credential.

The `storage` CLI is already on PATH inside the pod:

```bash
kubectl --context us-prod -n ai exec deploy/artifact-index-cli-terminal -- \
  storage file download 'ps://artifact-index/metadata/<key>' | gunzip
```

Because that fetch runs **after** the draw, it touches only the 10,000 drawn artifacts
rather than the whole candidate pool — which is the main reason the draw comes first.

---

## What can go wrong

| Symptom | Cause |
|---|---|
| `'_public'` returns zero rows | you filtered on `'public'`; the stored values carry leading underscores |
| Feed rows survive the filter | `scan_config <> 'feed'` drops NULLs silently — use `IS DISTINCT FROM` |
| The cohort is far smaller than the survey promised | the ES confirmation ran *after* the draw. It must run before, or `π_i` is computed against a population that then shrinks |
| The draw returns nothing | the temp table and the draw were in different `psql` invocations |
| OpenSearch query returns nothing | wrong index — it is `metadata-*`, not `artifacts7` |
| A duration looks impossible | `created` and `completed` may be on different clocks; step 1(f) settles it |
| Sort order looks scrambled | something ordered by `number`, which is a **random 17-digit integer**. `id` is the time-ordered column |

---

## Not yet answered

These are operational facts nobody has recorded, and each blocks something specific:

- **ClickHouse `hash_searches` retention.** No `TTL` in the migration, so how far back the
  lookup data goes is unknown. Gates F11.
- **Whether `kibana.polyswarm.network` proxies the full REST API** or only `_dashboards/`.
  The tunnel route is configured in the Cloudflare dashboard, not in `charts`. Verify with
  one `GET /` before depending on it.
- **The exact pgdog and ClickHouse Service names** — both charts are external or
  operator-rendered. `kubectl get svc` settles each in one command.
