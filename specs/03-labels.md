# 03 — Labels

## Scope

The label taxonomy, the independence grades, and how the pilot's labels are produced.

## Invariants

- **The answer must come from somewhere the inputs did not.**
- Grade 0 is banned. Grade 1 may train and may never calibrate.
- The calibration and test sets take grade 3 only.

## The failure being avoided

The 2023 model's answer column was built by counting how many engines called a file
malicious and thresholding at three — using the very verdicts that are the model's
inputs. A model that perfectly reproduced the vote count would have scored flawlessly
and known nothing. Every metric that pipeline ever produced is uninterpretable for that
one reason.

Notably, the 2022 whitepaper **explicitly rejects** this method by name, listing
"combine malice labels from multiple anti-malware vendors" among approaches it
considered and discarded.

## Independence grades

| Grade | Where the answer comes from | May train | May calibrate / test |
|---|---|---|---|
| **0 — fatal** | a threshold on the same scan's verdicts | no | no |
| **1 — usable** | the *same* engines, read *30 days later* | **yes** | no |
| **2 — better** | a different modality: detonation behaviour, code-signing, curated known-good | yes | partially |
| **3 — gold** | a human adjudicating against §3 of the estimand | yes | **yes — only this** |

Grade 1 is the pilot's training label. It breaks the fatal circularity because the label
carries information the features do not — but it is still engine-derived, so it can
never validate a calibration curve.

## Taxonomy

| Label | Definition |
|---|---|
| `known_good` | positively attested legitimate — valid signature from a known publisher, NSRL, distro package |
| `benign` | adjudicated not harmful, but not attested |
| `unwanted` | PUP, adware, bundleware, disclosed miners — legal, disclosed, nobody would install knowingly |
| `dual_use` | legitimate tool frequently abused — PsExec, packers, RAT frameworks |
| `malicious` | meets the consent test in estimand §3 |
| `undecidable` | evidence genuinely conflicts, or dual review disagreed |
| `excluded` | EICAR, test files, corrupt or non-scannable |

Train on `malicious` vs `benign` ∪ `known_good`. Exclude `unwanted`, `dual_use`,
`undecidable` and `excluded` from both classes and **report their rates** — the
`undecidable` rate in particular is a finding, not a nuisance: it measures how much of
the problem is intrinsically ambiguous and therefore caps how good any model can get.

### Worked edges

A covert miner is `malicious`; a disclosed one is `unwanted`. PsExec is `dual_use` — an
informed owner would consent to a sysadmin tool. A Cobalt Strike beacon with an
attacker's address baked in is `malicious` even though the framework installer is
`dual_use`; configuration changes the answer. A legitimate signed DLL abused by
sideloading is `benign` — the file is fine, the campaign is not, and we score files.

## Producing the pilot's labels

1. **Wait out the horizon**, then pull each artifact's verdicts again at T+30.
2. **Count independent clusters, not engines.** Five detections are not five opinions if
   four of those vendors license the same signature feed. Three independent *clusters*
   is a far stronger bar at identical cost.
3. **Weight family specificity.** Two independent clusters naming a specific family is
   near-dispositive; five engines saying `Trojan.Generic` is weak. Generic and heuristic
   names are discounted.
4. **Require stability.** A count steady for weeks is settled; one oscillating between 1
   and 4 is `undecidable` rather than forced.
5. **Mine the retractions.** A vendor that detected a file and later *stopped* is
   actively asserting "we were wrong." These are the strongest negatives available and
   they land exactly on the hard cases. The old extraction already pulls them and throws
   the signal away.
6. **Carve out a gold slice** — even 200 files, hand-adjudicated against estimand §3,
   drawn **at random** rather than from the interesting end.

## Why the gold slice matters more than its size suggests

Two hundred files cannot train anything. What they do is **measure how wrong the cheap
labels are** — an error rate that is otherwise completely unknown and that caps model
quality. They also tell you whether the cluster threshold should be three or four, and
they are the only thing that can ever validate a calibration curve.

Draw at random. Adjudicating the files the model found interesting teaches you only
about the region the model already believed in — that is verification bias, and it is
how a system becomes confident about what it already thought.
