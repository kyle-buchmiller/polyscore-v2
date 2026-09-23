# 06 — Signals and the combiner

## Scope

What a signal is, how signals reach the score, and the contract the combiner honours.
Covers the two signal families that exist today — Authenticode/signature and sandbox —
and the rules any future family must follow.

## Invariants

- **A signal is an observation, not a score.** Its producer never sets its weight.
- The composition is **fitted, not asserted**. A hand-picked multiplier is banned.
- **Presence is never a feature.** It routes; what was *observed* is what informs.
- Absence is at least four distinct states and is never encoded as a blank.

---

## Rendered as a diagram

The serving half of [**Build and Serve**](https://claude.ai/artifact/EHDK37N6ZgJ8EjpHaa5wKZ) draws this path end to end — upload,
analyzers and bounty in parallel, reveal, the evidence document, base model, combiner,
coverage gate, and the late-arriving sandbox re-score. Solid boxes are live today, dashed
are this spec.

That page is a **rendering of this spec, not a second source of truth.** If they disagree,
this file wins. Link is internal and privately shared.

## 1 · Why a combiner rather than a boost

`polyscore` must remain a single number: customers have integrations that read one field
and threshold on it, and that constraint is not negotiable. The question is only where
the composition happens.

```
engine verdicts + features ──→ base model ──→ raw score ─┐
                                                          │
signature signals ───────────────────────────────────────┼──→ COMBINER ──→ polyscore
                                                          │   (small,        one number,
sandbox signals ─────────────────────────────────────────┘    fitted)        calibrated
```

The combiner is a small model — logistic regression over roughly five to fifteen inputs:
the base score plus signal indicators. In ML terms this is **stacking**. It buys four
properties that a post-hoc boost cannot:

**It stays a probability.** Fitted on outcomes, so the output means what it says.
`score × 2.0, clamp` does not — and that specific arithmetic is the live neonscan defect,
where category multipliers on a 0–1 score make a container of entirely clean files report
1.0.

**Signals can be added without retraining the base model.** Refitting a fifteen-parameter
combiner is minutes; retraining the base is weeks. This is where operational agility
belongs.

**Attribution is exact.** On a small linear combiner each input's contribution to the
score *is* `coefficient × value`. The drill-down is arithmetic, not an approximation the
way SHAP over a large tree ensemble would be.

**Interaction is handled.** A broken signature on a file thirty engines already flagged
adds almost nothing; the same signal on a file nobody flagged adds a great deal. A fixed
boost applies the same nudge to both.

### The rule that keeps it honest

**A signal producer publishes an observation. The combiner decides what it is worth.**

Without this, every team adding a signal negotiates its own weight, and within two
quarters the score is a hand-tuned aggregate again. A signal record may carry the
producer's own *confidence in the observation* — "this cert chain is broken, 0.99" — but
never a claim about maliciousness.

---

## 2 · The signal record

```json
{
  "type": "chain-broken",          // closed vocabulary, see SS4
  "source": "lief",                // which analyzer produced it
  "observed_at": "2026-09-22T11:04:00Z",
  "confidence": 0.99,              // producer's confidence in the OBSERVATION
  "detail": "BAD_SIGNATURE: content does not match signature"
}
```

`observed_at` is load-bearing: it is what the as-of rule in
[`02-data.md`](./02-data.md) checks against the scoring moment.

There is deliberately no `severity` and no `weight`. Severity is a presentation concern
and may be derived from the fitted coefficient; it is not an input.

---

## 3 · Presence, absence, and coverage tiers

Absence is not one thing, and collapsing it is how the 0.3346 constant happened — there,
"said clean", "said nothing" and "unknown engine" all became `0.0`. The same mistake is
available here and costs the same.

Every signal family encodes presence in **at least four states**:

| State | Meaning |
|---|---|
| `not_applicable` | the check cannot apply — an unsigned file has no signature to verify |
| `not_attempted` | eligible, but never run — the gate did not fire, or it is still queued |
| `attempted_failed` | run, but produced nothing usable — detonation timed out, parser rejected the file |
| `observed` | ran and produced a result, whose contents are the signals |

`not_applicable` and `observed_clean` are different facts and must not share an encoding.
An unsigned binary is not a binary with a valid signature.

### Coverage tier

The set of signal families available for an artifact is its **coverage tier**, and the
tier is a **routing key, never a feature**. Two artifacts in different tiers were drawn
from different evidence populations; a combiner fitted across both learns an average that
is wrong for each.

The practical rule for now: fit **one** combiner with presence encoded as above, but
**report calibration separately per tier**. If the reliability curves diverge, split into
a combiner per tier. That keeps it a data-driven decision rather than an architectural
guess, and it avoids committing scarce adjudicated labels to a split that may not be
needed.

---

## 4 · Signature signals (available today)

DN-8374 landed Authenticode verification via LIEF. It does not assert "stolen" — no such
determination exists in the platform — but it produces structured facts an analyst can
reason from, and a combiner can weight.

Available: `lief.signature_tags`, `chain_of_trust.{chain_verified, chain_flags, reason,
trusted_by_bundle}`, `check_flags`, and per-certificate `{subject, issuer, serial_number,
sha1, sha256, valid_from, valid_to, is_ca, key_type, rsa_key_size, signature_algorithm}`.

### Why these must be separate signals, not one "signature invalid" flag

DN-8374's authors went to real trouble to keep these apart, and collapsing them would
undo exactly that work:

| Observation | What it actually means |
|---|---|
| `BAD_SIGNATURE` | content does not match the signature — **someone modified a signed binary** |
| `CERT_EXPIRED` + valid countersignature | entirely normal; a timestamped signature outlives its certificate |
| `weak-digest-sha1` / `-md5` | legacy digest; mildly suspicious, and also just old software |
| `self_signed` | common in both malware and internal tooling |

`CHAIN_TIME_FLAGS` deliberately does not earn `chain-broken` for this reason. A single
boost on "signature invalid" would re-collapse the distinction the analyzer exists to
preserve.

### Certificate reputation — the near-term opportunity

`certificates.sha256` and `.sha1` are **thumbprints**, which is the join key a
stolen-certificate list would need. The list is what is missing, and it does not have to
be bought: *a cert thumbprint that has signed N artifacts later adjudicated malicious* is
computable from the corpus this repo already assembles.

That derived reputation is engine-adjacent and carries the usual caveat, so it is a
**feature**, never a label — but it is the cheapest route to the capability the bosses
asked for.

---

## 5 · Sandbox signals — four problems and their handling

Sandbox behaviour is the most genuinely *independent* evidence available, because it is a
different modality: what the file did, not what somebody thought of it. It is also the
signal family with the most ways to go wrong.

### Problem 1 — selection. Presence is downstream of the label.

Detonation is **gated, not sampled**. `evaluate()` returns immediately unless
`polyunite.malware_family` resolves, and families are derived from engine assertions. A
file nobody detected never gets a family, so it is never detonated. Benign-side coverage
is therefore close to zero, and roughly 3.9% of a day's artifacts are sandboxed at all.

**Handling.** Presence routes; it never informs. Within the sandboxed population the
question *"given that it was detonated, what did it do?"* is legitimate — the selection
has already happened and we are conditioning on it, not learning from it.

> **Recommendation, and the highest-leverage thing on this page.** Add a **small random
> detonation arm** — a fixed fraction of artifacts detonated regardless of family
> resolution. Without it, sandbox evidence can only ever inform artifacts engines already
> flagged, which is the region where the score matters least. With it, sandbox becomes
> usable across the whole population and supplies genuinely independent evidence in the
> uncertain middle. It is a platform change, it is small, and nothing else unlocks this.

### Problem 2 — timing. Results arrive after the scoring moment.

Reports land minutes to hours after submission; the scoring moment is bounty reveal.

**Handling.** This is what the two-stage shape is for, and it needs no new machinery:

```
t0  reveal          base model + available signals  ->  polyscore v1   tier: no_sandbox
t1  report lands    re-run the COMBINER only         ->  polyscore v2   tier: with_sandbox
```

The base model is not re-run — only the fifteen-parameter combiner, which is cheap. Score
observations are already append-only and versioned per
[`04-pipeline.md`](./04-pipeline.md) and rebuild item 10, so a second observation is the
normal case rather than an exception. Every observation carries `scored_at`,
`model_version`, `combiner_version` and its coverage tier, and exports pin the observation
they rendered.

A score that moves must be explainable, and here it is: `components.contributions` names
exactly what changed it.

### Problem 3 — lossiness. The index carries a fraction of the evidence.

Roughly 1.8% of detonations emit a Suricata TLS SNI into OpenSearch and ~11% log DNS,
against 15.6% in the full report on object storage — an ~8.7× difference the index never
ingested. Separately, CAPE's `behavior.enhanced` block is **deleted before storage**
(`del behavior['enhanced']`), so the rich process and registry event stream is not
retained anywhere queryable.

**Handling.** Scope accordingly: meaningful behavioural features mean **pulling reports
from object storage**, not reading the index. Anyone costing "add sandbox to PolyScore"
should budget for that, and should not assume the index is a cheap substitute.

### Problem 4 — asymmetry. Silence proves nothing.

Observed bad behaviour is strong positive evidence. *Absence* of bad behaviour is weak
negative evidence, because evasive samples detect the sandbox and exit, and because
plenty of benign software needs a click, an argument, a live server or a specific OS
build. One cohort of 255 garbled-Go samples produced 2 network flows and 0 extracted IPs
at a median PolyScore of 1.0000.

**Handling.** The four-state encoding from §3, with `attempted_failed` kept strictly
distinct from `observed` with nothing found. Let the combiner learn the asymmetry — it
will, if the states are distinguishable. Never treat a failed detonation as evidence of
innocence.

### The sandbox signal vocabulary

Prefer **behavioural primitives over vendor aggregate scores**. `cape_malscore`,
`triage_analysis_score` and `triage_static_score` are weighted sums of signature hits
authored from the same threat intelligence that drives AV signatures — using them while
labelling by engine consensus reintroduces the circularity one layer down, and they drift
whenever an upstream rule set updates, with no change to anything in this repo.

| Signal | Derived from | Strength |
|---|---|---|
| `c2-contacted` | `cape_config.address`, `.url`, `.c2_url`, `extracted_c2_ips` (CAPE and Triage) | **strongest** — a live callback is hard to explain innocently |
| `campaign-identified` | `extracted.config.campaign` | strong |
| `network-alert` | `suricata_alerts.dstip` / `.srcip` | moderate |
| `dropped-files` | `dropped[]` — presence and count | moderate |
| `detonation-failed` | run attempted, no execution | **asymmetric** — see problem 4 |

Aggregate scores may be carried in `components` for human drill-down. They are not
combiner inputs without a recorded decision saying why.

---

## 6 · Output schema

```json
{
  "polyscore": 0.87,
  "status": "scored",
  "coverage_tier": "with_sandbox",
  "components": {
    "model_probability": 0.42,
    "signals": [ { "type": "chain-broken", "source": "lief", "…": "…" } ],
    "contributions": [
      { "source": "engine_evidence", "logit": 0.31 },
      { "source": "chain-broken",    "logit": 1.84 },
      { "source": "c2-contacted",    "logit": 2.05 }
    ],
    "base_model_version": "…",
    "combiner_version": "…"
  }
}
```

`polyscore` is the combiner's output and remains the single number customers threshold
on. `model_probability` is the base model's own output, exposed for drill-down and for
diagnosing which half moved when the score changes.

Rank derives from `polyscore` — and per decision 0001, ranking uses the **raw** combiner
score at full precision, never the rounded or display value.

---

## 7 · Adding a new signal family

Four things, before any code:

1. **A closed vocabulary** of signal types, with what each observation means.
2. **Presence semantics** — which of the four states apply, and what produces each.
3. **The as-of story** — when the observation becomes available relative to the scoring
   moment, and therefore whether it lands in the first observation or a later one.
4. **Independence** — is this downstream of engine verdicts or of the label? If yes, say
   so; it may still be a feature, but it can never be a label and its selection effects
   must be recorded.

Then refit the combiner and compare reliability per coverage tier before and after. A
signal that does not move calibration is not free: it costs a parameter and an
explanation.
