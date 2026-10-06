# 09 — Extraction runbook

## Scope

How to actually run stage 01 against production from a workstation: what to
authenticate, what to run, in what order, and what each step should return.

Extraction is **two-tier** ([`0010`](../decisions/0010-natural-rescans-for-training-forced-for-validation.md)):
one **base pull** of everything eligible in a window, then any number of **run draws**
from that base — locally, seeded, sized by `POLYSCORE_COHORT_SIZE`. Scaling from 10k to
1M+ is a change to that one variable. Retraining never touches the database. Runs are
isolated under `data/runs/<run_id>/` and may run concurrently. A separate, small
**forced-rescan validation set** is the one thing that still waits on prod.

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
| **The label scan** | a second `artifactinstance` row — a **natural** rescan inside `[30, horizon_max_days]` for training; a **forced** one at ≈30 for validation | §4's two arms. This separation is the whole point — see below |
| **Engine assertions at each scan** | one row per engine: `author`, `verdict`, `engine_metadata`, `bid` | **the entire feature space** |
| **Sampling bookkeeping** | `stratum`, `pi`, `provenance`, `label_gap` | §9. `pi` is the one column no later step can reconstruct; `label_gap` is what makes the training arm's heterogeneity visible |
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

## Why this is eight steps and not one command

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

There are exactly three doors, and only two of them are `kubectl` — and the third turns
out to matter more than it first looked:

| Door | Use it for |
|---|---|
| `kubectl port-forward` to an in-cluster service | **Postgres** (via the pooler) and ClickHouse — lets you run local `.sql` files |
| `kubectl exec` into `artifact-index-cli-terminal` | **OpenSearch** and **psstorage** — the pod already holds the endpoints, credentials and the app's own clients |
| **`kibana.polyswarm.network`** — the OpenSearch REST API behind Cloudflare Access | the **PE gate** (step 3) and the **PE static features** (stage 04), **with no `kubectl` at all** — see *The OpenSearch door* below |

### The OpenSearch door

**Measured 2026-10-02.** Every path on `kibana.polyswarm.network` — `/_dashboards/`,
`/_cat/indices`, `/metadata-*/_count`, `/_cluster/health` — returns a **302 to Cloudflare
Access login**, not a 404. So the tunnel routes the **whole OpenSearch domain**, and the
only thing in front of it is an Access policy that a Kibana login already passes. The
app's own metadata names the scripted path: `cloudflared access curl`.

That changes what needs the CLI pod. Two things live in OpenSearch that this runbook
needs, and both are **time-invariant** facts about a file's bytes — the only kind ES is
safe for:

| Need | Where in ES | Replaces |
|---|---|---|
| **PE gate** — `exists: pefile.imphash` | `metadata-*` | step 3's `kubectl exec` |
| **PE static features** — 35 `pefile.*` + 14 `lief.*` fields, read from the index mapping | `metadata-*` | stage 04's ~10k psstorage blob fetches, **for A's window** |

```bash
# one-time: install the Access CLI (a user-bin tool; the tracked route is sam.yaml binaries:)
curl -sSL -o ~/.local/bin/cloudflared \
  https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64
chmod +x ~/.local/bin/cloudflared

# one-time per session: browser SSO, then a cached token
cloudflared access login https://kibana.polyswarm.network
export CF_ACCESS_TOKEN=$(cloudflared access token -app https://kibana.polyswarm.network)

# the first test — a single count, no scroll
curl -sS -H "cf-access-token: $CF_ACCESS_TOKEN" -u "$ES_USER:$ES_PASS" \
  "https://kibana.polyswarm.network/metadata-*/_count" \
  -H 'Content-Type: application/json' -d '{"query":{"exists":{"field":"pefile.imphash"}}}'
```

> **The second layer, settled 2026-10-05 from the charts rather than the wire.** `shifty`'s
> chart carries *both* a Cloudflare Access service token and `OPENSEARCH_USER` /
> `OPENSEARCH_PASSWORD` for this same host, so the domain's security plugin does want an
> internal user behind Access; `-u` (or `POLYSCORE_ES_USER/PASSWORD`) carries it. The prod
> door itself is still unexercised from a workstation — nobody has run `cloudflared access
> login` here yet — and the read-only internal user to pair with it has to come from
> wherever `shifty`'s does, because `ReadOnlyProd` cannot read prod secrets.
>
> **Stage has a door of its own, and it is unreachable from a workstation.** The stage
> tunnel routes `kibana.internal.polyswarm.network` to stage's `vpc-elastic-01…` domain —
> exactly artifact-index's stage `ELASTICSEARCH_URL` — but that hostname lives in a private
> DNS zone (no public record, and no WARP client on this box). On stage, step 3 runs
> **inside the CLI pod** with `03_pe_confirm.py --direct`, which takes endpoint and user from
> the pod's own `ELASTICSEARCH_*` env. Same script, same query, no door.

**What this door does not open:** Postgres. Steps 1, 2, 4 and 5 still ride the
`pgpool` port-forward, which still needs an EKS access entry for `ReadOnlyProd`. The
blocker narrows to exactly that one thing.

**Try it by hand first, in Discover.** Index pattern `metadata-*` (or the alias
`artifacts`), and this DQL gives step 3's count without writing a line:

```
meta_community:"_public" and pefile.imphash:* and scan.first_seen >= "2026-09-08" and scan.first_seen < "2026-10-01"
```

**Run 2026-10-05: 25,265,459 hits** over Sep 8 – Oct 1. Read it correctly: ES has no
`scan_config`, so this is the **§10 training population, feeds included** — and the sample
documents say so plainly (six `.exe` within 16 bytes of each other, filename = sha256,
scanned once, ~190 ms apart: a polymorphic feed). The §1 customer population is an unknown
minority of it. Volume is not the constraint anywhere in this project; ~1M PE/day means
1M+ samples is one day of traffic.

> **The constraint is time, and it is arithmetic.** The §1 window opens 2026-09-08 and the
> training arm needs a natural rescan **≥30 days** after T. So nothing in this window can
> be labellable before **Oct 8**, and the whole window is not aged until **~Oct 31** — and
> then only the fraction that someone actually rescanned. A base pull over the §1 window
> is a **November** artifact. To have a training set sooner, pull a window that is already
> aged (pre-September) and take the PE gate from the Postgres heuristic, since ES coverage
> back there is ~37% — which is Estimand B's path applied to A. The forced **validation**
> tranche for Sep 8 is due **Oct 8** regardless, and has to be enqueued before then.

Two more numbers worth one Discover query each: the same DQL **without** `pefile.imphash:*`
gives the parse-failure rate; and `scan.first_seen < "2026-09-08" and scan.latest_scan.created >= "2026-09-08"`
is a rough proxy for how often old artifacts get rescanned at all.

Coverage caveat: before September 2026 the index was ~37% populated and biased toward
successfully-analysed files. For **A's window** that is moot. For **Estimand B**, ES
cannot be the feature source for pre-September artifacts — those still need psstorage.

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

> **Measured 2026-09-29: `ReadOnlyProd` has no EKS access entry on `prod-v3` at all.**
> Not a `view` mapping that blocks `exec` — no mapping. The token mints, the cluster
> rejects it, and every step below fails at the first `kubectl`. `AdminProd` is mapped,
> and so is stage's `AdminNonProd`. Resolving this is an infra change — an access entry
> for `ReadOnlyProd` bound to a custom role granting exactly the verbs below — and the
> stock `AmazonEKSViewPolicy` will not do it. Until then, stage is the rehearsal target.

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
| 3 · PE confirm | **none** (via the OpenSearch door) | **none** | Cloudflare Access (your SSO, via `cloudflared`) + possibly an OpenSearch internal user. Fallback: `create pods/exec` in `ai` |
| 4 · Draw | ” | `create pods/portforward` in `pgpool` | Postgres user from `DB_URI_RO` |
| 5 · Snapshot | — | — | local only |
| *(stage 04)* | none for A's window | none — PE features come from the OpenSearch door | psstorage (unauthenticated GET) only for pre-September artifacts, i.e. Estimand B |

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
`02a_frame_chunk.sql` / `02b_label_chunk.sql` and, where they change one, into `decisions/`.

**Done when** all six returned and none surprised you. A surprise is a stop, not a note.

---

## Step 2 · Survey — `01_extract.py --sample-pct 10 --survey` ← **the decision point**

```bash
.venv/bin/python pipeline/01_extract.py \
  --window-start 2026-09-08 --window-end 2026-10-01 \
  --sample-pct 10 --survey --horizon-max-days 365     # a wide bound: the survey is what sets it
```

**Expect:** minutes. It walks the same frame and label chunks step 4 will, over a
deterministic 10% of artifacts (`hashtext(sha256)`), prints the table below, writes the
sampled frame to `data/base/<window>.sample10.frame.parquet`, and stops before any
assertion is pulled. Shares and percentiles are as good from 10% as from all; counts
scale by 100/pct and the report says so. (`01_survey.sql` is retired: a separate
aggregate query over the whole population blew a 30-minute statement timeout on stage,
and one extraction code path cannot disagree with itself.)

**This step draws nothing, and that is deliberate.** It exists so the two assumptions most
likely to be wrong get tested before anybody spends a download on them:

1. **Is the cohort there?** The `labellable` column — candidates that have a T+30 scan to
   label from — is the real cohort size. `artifacts` minus `labellable` is a *waiting*
   problem, not a data problem.
2. **Do the bands populate?** Compare `pct_of_labellable` against §9's targets
   (contested 45, leaning 15/15, consensus 10/10). Those numbers are a claim about where
   the hard cases live, written before anyone looked at data.

**If `contested` comes back at 3%, move the bands — not the draw.** Record the revision in
`decisions/`, per `99-open-questions.md`. If total `labellable` is far below the cohort
size, widen the window forward or lower the cohort size and say so. **Do not drop feeds to
make the bands look like §1**: the survey counts the §10 population (feeds in, decision
0010) with the same filters as the base pull — it *is* the base pull's frame — so the two row counts can agree, and
the `customer_*` columns are the §1 subset. Thinness *there* bounds what calibration can
claim, not what training can use.

> **Why this matters, measured on stage 2026-10-05.** The survey still carried the §1 feed
> exclusion after decision 0010 removed it from the base pull, and reported **278**
> artifacts in 2024-01-01 → 2026-09-01. The same window in Postgres holds 4.72M `_public`
> instances over 3.32M artifacts, **1.58M of them revealed and 1.22M with assertions** —
> feeds are 3.52M of the instances. `default` on stage is 1.13M never-completed instances
> over just 68k artifacts and **2,681** artifacts ever revealed: the same test hashes
> stored over and over. The 25-row stage base on disk predates the fix (`pe_gate:
> skipped-REHEARSAL`) and is rehearsal-only.

**Produces:** `data/reports/survey_<window>_p<pct>.txt` — a header with the frame,
labellable and customer counts, then one row per stratum of the labellable rows.

| Column | Meaning |
|---|---|
| header `frame` | artifacts whose first-ever reveal is in the window (the sample's) |
| header `labellable` / `customer labellable` | **the real base size**, and its §1 subset — what stage 08 calibrates on and the headline is sliced to |
| `stratum` | the five drawn §9 bands plus `below_floor` |
| `labellable`, `share_%`, `target_%` | per band, against §9's 45 / 15 / 15 / 10 / 10 |
| `gap_p50`, `gap_p90`, `gap_max` | the realized T → label gap in days — **`horizon_max_days` is read off `gap_p90`** |
| `def_min`, `def_p10`, `def_med` | answering-engine coverage per band — what the floor is set against |
| `customer` | §1 rows in the band |
| `fills_up_to` | the largest cohort this band can fill at its share; the smallest bounds the draw |

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

**Preferred: through the OpenSearch door, no `kubectl`.** After the one-time
`cloudflared access login` above:

```bash
.venv/bin/python pipeline/03_pe_confirm.py --window-start 2026-09-08 --window-end 2026-10-01 --count-only
.venv/bin/python pipeline/03_pe_confirm.py --window-start 2026-09-08 --window-end 2026-10-01 \
    > data/pe_confirmed/prod_2026-09-08_2026-10-01.txt
```

`--count-only` is the first thing to run: one `_count` request that also settles whether
an internal user is needed behind Access.

**From the CLI pod — `--direct`.** OpenSearch is an AWS-managed VPC endpoint rather than
a k8s Service, so `port-forward` does not reach it; the pod already holds the endpoint and
basic-auth credentials as `ELASTICSEARCH_URL` / `ELASTICSEARCH_USER` / `ELASTICSEARCH_PASSWORD`,
and `--direct` reads exactly those. The script is stdlib-only and is fed over stdin, so
nothing is copied into the pod:

```bash
POD=$(kubectl --context us-stage-blue -n ai get pods -o name | grep artifact-index-cli-terminal)
kubectl --context us-stage-blue -n ai exec -i "$POD" -- python3 - \
    --window-start 2024-01-01 --window-end 2026-09-01 --count-only --direct < pipeline/03_pe_confirm.py
kubectl --context us-stage-blue -n ai exec -i "$POD" -- python3 - \
    --window-start 2024-01-01 --window-end 2026-09-01 --direct < pipeline/03_pe_confirm.py \
    > data/pe_confirmed/stage_2024-01-01_2026-09-01.txt
```

This is the stage path (stage's door is private-DNS only) and the prod path once `exec`
is granted; the door is for a workstation that has neither. **Stage, 2026-10-05: 966,504**
confirmed-PE artifacts in that window — against 1.22M revealed-with-assertions artifacts in
Postgres, so the PE share of the base is only known after step 4 intersects them.

> **Scrolls on stage lose shards silently.** Two full scrolls ended at 795,000 and 760,000
> of 966,504 with exit 0 and no error anywhere except `_shards.failed` on one page:
> OpenSearch's search backpressure cancelling shard tasks for heap pressure
> (`rejected_execution_exception: heap usage exceeded`). The script now fails any page
> with a failed shard, retries the whole scroll at half the page size (`--page`,
> `--retries`), buffers the list so a retry cannot leave half of it on stdout, and exits
> non-zero if the final total disagrees with `_count`. A short gate is a biased gate, and
> nothing downstream can tell.

`exists: pefile.imphash` is **exact** here: a rejected `pefile` document is stripped to
`{}` and removed from the ES document entirely, so presence of the field ⟺ `pefile.PE()`
parsed the file. Taking this one fact from ES is safe precisely because it is
**time-invariant** — a file's bytes do not change, so whether the parser handled them
cannot drift. Nothing time-varying may come from ES.

> `app.elastic` is an **OpenSearch** client (`opensearch-py`). Do not
> `from elasticsearch import …` inside that pod.

**Produces:** `data/pe_confirmed/<env>_<window>.txt` — newline-delimited sha256, one per
line, no header.

```
3f5a1c...  (64 hex chars)
b91e07...
```

This is the **confirmed PE population**, and it is the denominator `π_i` will be computed
against — which is why it must exist before step 4 and not after.

**Done when** the script exits 0 — it refuses to when the scroll total differs from
`_count`. Then read `wc -l` against step 2: a number far *below* `labellable` means the
mimetype pre-filter was admitting non-PE files (expected — it admits CAB, MSI, MS Access
and VBE); a number far *above* `artifacts` means either the ES date range does not match
the SQL window, or — as on stage — the index holds far more *stored* PE than Postgres has
*revealed* scans.

---

## Step 4 · Base pull — `01_extract.py` (`02a_frame_chunk.sql` + `02b_label_chunk.sql`)  *(tier one)*

**No sampling happens here.** This pulls **every** eligible artifact in the window that
already has a natural later scan inside `[horizon_days, horizon_max_days]`, with the
counts needed to band it. `π_base = 1`. It runs rarely, and it is the reproducibility
unit everything else keys on.

```bash
.venv/bin/python pipeline/01_extract.py \
  --window-start 2026-09-08 --window-end 2026-10-01 \
  --horizon-max-days 90 \
  --pe-confirmed data/pe_confirmed/prod_2026-09-08_2026-10-01.txt
```

**It is chunked, and it resumes.** The one-statement form was a second full scan of
`artifactinstance` hash-joined to the whole frame through a disk-spilling aggregate, with
every per-artifact step a nested loop over the population — measured on stage 2026-10-05
at 1.2M artifacts: a 30-minute statement timeout, then a 78-minute port-forward. Now:

| Statement | Once per | What it does |
|---|---|---|
| `02a_frame_chunk.sql` | week of `created` (`--chunk-days`), from `window_start − --slack-days` | every artifact whose **first-ever** reveal is in the window, with its T scan. `created` is indexed where `completed` is not, and `completed ≥ created` always; an anti-join on `ix_artifactinstance_sha256` finds "first ever" |
| `02b_label_chunk.sql` | 5,000 frame rows, carried in as `unnest()` arrays | the nearest natural later scan in bound and the verdict counts at T; rows with none are **unlabellable** |
| `03_assertions_pull.sql` | 5,000 instance numbers | step 5 |

Every chunk is cached under `data/base/.cache/<window>_p<pct>_h<bound>/`; a run killed
by a tunnel's lifetime re-runs and picks up where it stopped (`--no-cache` to refuse the
cache). No statement is near a timeout.

> **Why this is a Python stage and not a `psql -f`.** The replica is a **hot standby**
> (`pg_is_in_recovery() = true`) and refuses `CREATE TEMP TABLE` outright — measured
> 2026-10-01 on stage, and prod's reader endpoint is the same kind of thing. So the
> confirmed-PE set cannot be joined in SQL. `01_extract.py` walks the frame chunks
> ungated, applies the confirmed set **in pandas between the frame and the label chunks**
> (less work, and the base Parquet is exactly the confirmed-PE population, so the run
> draw's `π` is over confirmed-PE band populations). The keys for the label and assertion
> chunks ride in as array parameters for the same reason. `psql` remains the right tool
> for step 1, a single read-only query.

For a stage rehearsal where the CLI pod is unreachable, `--no-pe-gate` skips the filter;
the manifest records `pe_gate: skipped-REHEARSAL` and such a base is never trained on.

**Set `horizon_max_days` from step 2's `gap_p90`**, not from the placeholder. On stage,
natural gaps ran 92 days median for contested and 218 for consensus-clean; the bound is
doing real work and a wrong one silently changes the population.

**Produces:** `data/base/<window>.parquet` with a manifest carrying the query hash (over
the three SQL files **and** the variables — `01b_draw` refuses a base pulled by different
ones), window, bound, PE-gate mode, the frame / after-gate / labellable / unlabellable
counts and the **content hash** — and, from the same run, `<window>.assertions.parquet`
(step 5) and the **control sample**: `<window>.control.parquet` (+ manifest, with
`control_pi`) and `<window>.control.assertions.parquet`, a seeded `--control-size`
(default 10k) of unlabellable artifacts with their T assertions, for stage 06's rescan
probe and never for training. The content hash goes into every run manifest, which is
how "which base did this model come from" is always answerable.

| Column | Note |
|---|---|
| `sha256`, `instance_number`, `scoring_moment` | the feature scan (T) |
| `label_instance_number`, `label_moment`, `label_gap` | the natural label scan |
| `n_definite`, `n_malicious`, `n_responded` | **the band inputs** — stratum is computed at draw time, not here, so band edges can be revised without a re-pull |
| `scan_config`, `provenance` | carried, not filtered: `feed` / `customer`. **The base is the §10 training population, feeds included**; stage 08 narrows to §1. Measured in Discover 2026-10-05: 25.3M public PE in 24 days, visibly feed-dominated |
| `incumbent_polyscore` | the incumbent's output for the T scan — baseline 4, denied as a feature |

**Done when** the manifest's `labellable_rows` agrees with step 2's labellable count
scaled by 100/pct (the survey ran before the PE gate; the gap is the gate's work), and
the row count equals `labellable_rows`.

---

## Step 5 · Assertions pull — `pipeline/sql/03_assertions_pull.sql`

Long form, both scans, every artifact in the base. **Stream it; never materialize it in a
client.** At 1M artifacts this is ~30M rows.

Runs inside `01_extract.py`, immediately after the base pull — nothing to invoke
separately. The keys cannot sit in a temp table on the hot standby, so they ride in as a
**`bigint[]` parameter**, `5,000` instance numbers per query, and the frames are
concatenated. At 1M artifacts that is ~400 queries, which is also how the pull streams
rather than materializing 30M rows at once.

`engine_metadata` is **projected** — `malware_family` and a short named list — never
pulled whole. Every added field is multiplied by ~30M rows.

**Produces:** `data/base/<window>.assertions.parquet` — one row per `(sha256, scan_role,
author)` — and `<window>.control.assertions.parquet`, the control sample's T scans
(`scan_role = 'feature'` only). The 4th engine state (never responded) is the *absence*
of a row and is reconstructed in stage 04 against the roster at T.

**Done when** the distinct `instance_number` count equals twice the base's artifact count,
and the control file's equals the control sample's.

---

## Step 6 · Run draw — `pipeline/01b_draw.py`  *(tier two — this is what you repeat)*

```bash
POLYSCORE_RUN_ID=run-01 POLYSCORE_RANDOM_SEED=20260922 POLYSCORE_COHORT_SIZE=10000 \
  .venv/bin/python pipeline/01b_draw.py
```

**Never touches the database.** Reads the base Parquet, computes each artifact's stratum
from `n_malicious / n_definite` using the band edges in config, draws `cohort_size`
stratified per §9 with the seed, records `π = n_draw / n_available` per row, writes under
`data/runs/<run_id>/`.

**To scale to 1M, change `POLYSCORE_COHORT_SIZE`.** Nothing else. The base already holds
everything; the draw just takes more of it — and reports per-stratum under-fill if a band
cannot supply its share, never back-filling from a neighbour.

**To run several at once:**

```bash
for s in 1 2 3 4 5; do
  POLYSCORE_RUN_ID=stab-$s POLYSCORE_RANDOM_SEED=$s .venv/bin/python pipeline/01b_draw.py &
done; wait
```

They read one immutable file and write to disjoint directories. This is the input to the
process-stability measurement in [`05-evaluation.md`](./05-evaluation.md): same base,
different seeds, how far apart do the models land?

**Produces:** `data/runs/<run_id>/cohort.parquet` + `manifest.json`. The manifest carries
the base hash, seed, cohort size, estimand version, band edges, `horizon_max_days`, and
per-stratum `n_available` / `n_draw`.

**Done when** the three checks hold — `n_draw` matches target per band or under-fill is
reported, `π ≤ 1` everywhere, row count equals the sum of `n_draw` — **and** a second run
with the same seed and base produces a byte-identical `cohort.parquet`. If it does not,
that is a pipeline bug and nothing downstream can be trusted until it is found.

> **Rehearsed on stage 2026-10-01** against a 25-artifact base. Same seed twice: parquet
> **byte-identical**, content hash identical. Different seed: 7 of 9 artifacts shared.
> `POLYSCORE_COHORT_SIZE` 10 → 9 rows, 20 → 14 rows, nothing else changed. Under-fill
> reported on three bands and back-filled on none. Five runs launched concurrently all
> completed from one base hash into disjoint directories. The claims in §11 are measured,
> not asserted.

---

## Step 7 · Validation tranche — the one thing that still waits on prod

Draw `validation_size` artifacts (~2k) from the window **blind to rescan history** — not
from the base, which by construction contains only artifacts someone already rescanned.
Enqueue a forced rescan for each day's submissions 30 days after that day:

```bash
# one tranche per day; start/end are TIMESTAMPS, not ids
kubectl --context us-prod -n ai exec deploy/artifact-index-cli-terminal -- \
  ai instance rescan '2026-09-08 00:00' '2026-09-09 00:00' -c 50
```

Harvest after the horizon. The gap is ≈30 by construction and the selection is ours.

**This set is never trained on.** It is what §8's decision and §11's stability spread are
judged against — the one place the label is unselected and homogeneous. It waits 30 days
**once**, and 2k rescans is a trivial load.

**Produces:** `data/validation/<window>.parquet`, same shape as a run cohort, `provenance
= forced`.

---

## Step 8 · Freeze the run snapshot

```bash
make extract     # 01_extract.py: cohort + assertions -> parquet + manifest
```

From here the **snapshot, not the query, is the unit of reproducibility.** Re-running the
query next week returns different rows and silently invalidates every downstream stage.
The manifest records the query, the window, the seed, the row count and a content hash.

**Produces:** `data/runs/<run_id>/snapshot.parquet` + `manifest.json` — the cohort joined
to its assertions, isolated per run. **The base is the unit of reproducibility; the run
snapshot is what a model is trained on.**

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

**At 10k, stage 01 is small and fast.** The expensive fetch is deliberately *not* here.

**At 1M**, the base pull is the heavy step and it runs once:

| | 10k | 1M |
|---|---|---|
| base artifacts | — | ~1M rows, trivial |
| assertions | ~400–600k rows | **~30M rows**, ~1–2 GB as Parquet with the projection |
| run draw | seconds | seconds — it is a local stratified sample |
| pivot (stage 04) | pandas is fine | **arrow in artifact-keyed chunks**; do not load the matrix whole |

The base pull at 1M is a heavy query on a shared replica. It runs rarely, and everything
"repeated, quick, concurrent" happens over the Parquet it produces — that is the whole
reason for the two tiers.

**The slow part was going to be stage 04 — and for A it may not exist.** The PE static
block — 35 `pefile.*` and 14 `lief.*` fields — is **indexed in OpenSearch** and reachable
through the OpenSearch door in bulk, time-invariant and therefore safe to take from ES.
For A's window that replaces the blob fetch entirely.

The psstorage path remains for **pre-September artifacts** (Estimand B), where ES coverage
is ~37% and biased. There, in us-prod anything over **2000 bytes** goes out-of-line and a
parsed-PE document is far larger, so stage 04 makes one blob fetch per artifact:

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
| `ReadOnlySqlTransaction: cannot execute CREATE TABLE` | you tried a temp table on the reader. It is a hot standby; keys go in as query parameters, which is what `01_extract.py` does |
| OpenSearch query returns nothing | wrong index — it is `metadata-*`, not `artifacts7` |
| A duration looks impossible | `created` and `completed` may be on different clocks; step 1(f) settles it |
| Sort order looks scrambled | something ordered by `number`, which is a **random 17-digit integer**. `id` is the time-ordered column |
| Two runs with the same seed differ | a pipeline bug — the draw consulted something other than the base and the seed. Nothing downstream is trustworthy until found |
| A run's cohort is smaller than `cohort_size` | a band under-filled. Correct behaviour; read the manifest's per-stratum report and do not back-fill |
| Stage 04 runs out of memory | the matrix was loaded whole. At 1M it must be pivoted in artifact-keyed chunks |
| The base is huge and slow to pull | expected at 1M; it runs once. If it is being re-pulled per run, the two tiers have been collapsed and concurrency and reproducibility are both gone |
| Validation AUC far below held-out training AUC | the natural rescans were selected on something the T-features do not carry. This is the finding the validation set exists to produce |

---

## Measuring the rescan rate (and watching the validation tranche)

The one question ES could not answer — *how many artifacts get rescanned at all* — has a
dashboard answer from **2026-09-28 onward**: the `artifact_index.scan.submitted` counter,
tagged `endpoint:rescan` and split by `actor` and `plan`. Details and the first six days'
numbers in [`02-data.md`](./02-data.md).

Two uses here:

- **Sizing the training arm.** `endpoint:rescan` by `plan`, daily. Measured: ~360/day,
  ~90% one `plan:other` account in ~500-row batches, ~23/day organic enterprise. Read that
  before trusting "natural rescans" as an unselected label source — they are not.
- **Confirming the validation tranche ran.** Forced rescans through `ai instance rescan`
  carry **`actor:internal`**. The day after each tranche, `endpoint:rescan actor:internal`
  should show roughly the tranche size. Zero means it did not enqueue. This is cheaper and
  faster than querying Postgres for the new instance rows.

**For the §1 window itself the counter is blind** — it did not exist. That rescan rate
still comes from `01_extract.py --sample-pct 10 --survey` once the port-forward is possible.

---

## Not yet answered

These are operational facts nobody has recorded, and each blocks something specific:

- **ClickHouse `hash_searches` retention.** No `TTL` in the migration, so how far back the
  lookup data goes is unknown. Gates F11.
- ~~Whether `kibana.polyswarm.network` proxies the full REST API~~ — **settled 2026-10-02:
  it does.** Every REST path returns a 302 to Cloudflare Access, not a 404. What is still
  unverified is the layer behind Access — whether the domain's security plugin wants an
  OpenSearch internal user on top. One `_count` request settles it.
- **The exact pgdog and ClickHouse Service names** — both charts are external or
  operator-rendered. `kubectl get svc` settles each in one command.
