# 0015 — The injection arm: Microsoft-signed files already scanned, attested twice

- **Status:** Accepted
- **Date:** 2026-11-10
- **Affects:** `specs/01-estimand.md` (§9 The injection arm), `specs/04-pipeline.md` (stage 00c),
  `specs/12-api-slice-pilot.md` (§ The injection arm), `pipeline/00c_inject_known_good.py`,
  `src/polyscore_v2/config.py` (`vt_api_key`)
- **Amends:** the wording of estimand §9 — "not drawn from PolySwarm" becomes "not *selected*
  by PolySwarm's engines": the files are ones the platform already holds and scanned once;
  what is external is the attestation.

## Context

Run `forced-a` carried the 95% organic draw and no injection arm (0 of the 500 rows decision 9
reserves), because the arm's named sources do not exist yet: the R9 corpus has no owner, and
the platform's known-good catalogue is nearly invisible in the index (three catalogued PE
documents on a 1/256 slice, all from the `commercial` feed) and cannot be scanned through the
public API in any case — a catalogued hash is declined at submission with no bounty and no
bytes stored (artifact-index `specs/05-known-good.md`).

Meanwhile every PE scan since DN-8374 carries the lief analyzer's Authenticode result, mapped
in the metadata index: `lief.signature_tags`, `lief.signer.{organization, sha256}`, every
certificate in the embedded chain. Measured 2026-11-10 on a 1/256 slice of scanned-first PE
files: ~18,000 platform-wide with a verified signature whose signer organization is Microsoft
Corporation, ~171,000 with a verified signature from any signer; of the Microsoft ones about
one in nine was flagged by at least one engine at T.

Two things the analyzer's `verified` is not. It pins no CA bundle, so a self-made chain
passes (the first "Microsoft" candidate examined was signed by "Inspect Element Ltd" on an
untrusted root, which VirusTotal's sigcheck rejected). And its `chain-verified` tag needs
every embedded link valid *now*, so a genuine, timestamped Windows binary whose leaf has since
expired carries neither `chain-verified` nor `chain-broken`.

## Decision

The injection arm is drawn from the index and admitted on **two independent attestations**:

1. **Ours**, computed on the bytes by the lief analyzer: `verified` in the signature tags
   (the file's digest matches the signed digest and the signer's signature checks against
   the embedded leaf), not `chain-broken`, signer organization `Microsoft Corporation`, and a
   **pinned Microsoft CA** in the embedded chain — a CA certificate (`is_ca`, `O=Microsoft
   Corporation`) seen in at least five chains that passed the other checks. One confirmed
   file cannot vouch for its own issuer.
2. **VirusTotal's**, on the same hash: `signature_info.verified == "Signed"` — sigcheck's
   validation against the Windows trust store — with a trust anchor whose name starts with
   `Microsoft Root`. VirusTotal's `known_distributors` and `trusted_verdict` markers are
   recorded beside it, not required: they were absent on a genuine Windows DLL.

Only the signature attestation is read from VirusTotal. **No VirusTotal detection count,
verdict or engine result is stored or used anywhere** — a third-party aggregator's verdicts
are grade 1 at best (`specs/03-labels.md`), and the arm's label is grade 2 by the different
modality of code signing, not by anyone's detections.

The arm's rows carry `provenance = injected_known_good`, `stratum = injected_known_good`,
`label = benign` by attestation, no label scan, and **no inclusion probability** (`pi` is NaN):
they anchor the feature space and describe no population, exactly as §9 says. Candidates are
taken hardest-first — the Microsoft-signed files the engines flagged at T, then a seeded
permutation of the clean ones.

## Consequences

- Stage `00c` (draw, confirm, collect) produces `data/base/injected_<run>.parquet` and
  `data/runs/<run>/injected.parquet` in 01a's and 01b's shapes, with the evidence per candidate
  in `data/injected/<run>/confirm.parquet`. It does **not** merge the arm into the run's
  cohort: every stage from 02 on weights rows by `1/pi`, and the arm has none. Admitting it
  into a run is the next change — an attested branch in 03, the injected-vs-organic probe in
  06 (today hard-coded `n/a`), and `1/pi` weights that read NaN as zero in 02, 05, 06, 07, 08
  and 09 — and is recorded in `specs/99-open-questions.md`.
- VirusTotal's quota bounds the arm's growth to the key's daily allowance, and a lookup by
  hash reveals interest in that hash to VirusTotal; both are acceptable for public Windows
  binaries and would not be for a customer file.
- Microsoft-signed binaries sit at the easy end of §9's value ordering. The flagged-at-T
  subset is the part that teaches; the clean rest anchors the bottom of the scale. Unsigned
  known-good (internal builds, distro packages) is still owed and still R9's.
- The 0.0 band leadership requires for trusted-source files (`specs/06-signals.md` §8) has,
  in this arm, its first measurable population: the same rule that admits a file here is a
  candidate definition of "attested by a trusted source".

## Rejected

- **A list from a Windows install, checked against VirusTotal.** The arm needs engine
  verdicts at a first scan, not hashes; most installed files were never submitted here, and
  the catalogued ones cannot be scanned. Using VirusTotal's verdicts to train a competing
  score is also a terms question this design does not need to raise.
- **The platform's known-good catalogue as the source.** Not loaded or not re-indexed in
  prod (the three-document measurement above); worth a question to the artifact-index team.
- **Our analyzer's `verified` alone.** Not trust: see Context.
- **Requiring VirusTotal's blue known-distributor marker.** Rarer than "Signed" even on
  genuine Windows files; recorded, not required.
