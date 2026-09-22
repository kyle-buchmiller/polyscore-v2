# 0002 — Train on metadata, not file bytes

- **Status:** Accepted
- **Date:** 2026-09-22
- **Affects:** `specs/02-data.md`

## Context

Two approaches were on the table: train on file content (disassembly, byte n-grams,
opcode sequences) or on the engine verdicts and derived metadata.

Content-based static classification is a real and well-established technique. It is also
exactly what the ~40 engines on the platform already do.

## Decision

PolyScore stays a **second-order model**: it aggregates opinions about a file, not the
file itself. No binaries are required for the pilot.

## Alternatives considered

| Option | Why not |
|---|---|
| Static content classifier | Competes with our own suppliers at the thing they specialise in, using less data than they have. Does not extend to URLs or domains, where there is no file. |
| Hybrid — content features alongside verdicts | Defensible later, but the scoring path passes `path=None` and never fetches bytes, so it needs an architecture change for uncertain gain. |

## Consequences

- The pilot needs **zero binaries downloaded**. `pefile` and `lief` already run on every
  eligible file and their output is stored, so imphash, certificate chains, section
  entropy and import lists are available without fetching anything.
- Static features earn their place as **conditioning variables** — telling the model
  whose opinion to trust on this kind of file — rather than as detectors in their own
  right.
- PolyScore's defensible edge is that it is the only thing that sees all forty opinions
  at once. That framing should survive into how the product is described.
