#!/usr/bin/env python3
"""Run a pipeline/sql/*.sql file without needing the psql binary.

The .sql files are written for psql -- they use `\\set name value` and the
`:name` / `:'name'` substitution forms -- because psql is what an operator on a
workstation reaches for. This runner understands that same subset so the files
stay single-source: identical text runs under psql and under this.

    .venv/bin/python pipeline/run_sql.py pipeline/sql/00_verify.sql
    .venv/bin/python pipeline/run_sql.py pipeline/sql/b01_survey.sql --set window_start=2026-09-08

Read-only by construction: it opens a read-only transaction and sets a
statement timeout, so a runaway query on a shared replica cannot sit there.
"""

from __future__ import annotations

import argparse
import pathlib
import sys

import psycopg

from polyscore_v2.sql import dsn_from_env as load_dsn, load_sql  # shared with 01_extract


def render(cur) -> str:
    if cur.description is None:
        return f"({cur.rowcount} rows affected)"
    cols = [d.name for d in cur.description]
    rows = [[("" if v is None else str(v)) for v in r] for r in cur.fetchall()]
    widths = [max(len(c), *(len(r[i]) for r in rows)) if rows else len(c)
              for i, c in enumerate(cols)]
    line = "-+-".join("-" * w for w in widths)
    head = " | ".join(c.ljust(w) for c, w in zip(cols, widths))
    body = [" | ".join(r[i].ljust(w) for i, w in enumerate(widths)) for r in rows]
    return "\n".join([head, line, *body, f"({len(rows)} rows)"])


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("sql_file", type=pathlib.Path)
    ap.add_argument("--env", type=pathlib.Path, default=pathlib.Path(".env"))
    ap.add_argument("--set", action="append", default=[], metavar="NAME=VALUE")
    ap.add_argument("--timeout", default="600s", help="statement_timeout (default 600s)")
    args = ap.parse_args()

    overrides = dict(kv.split("=", 1) for kv in args.set)
    statements, variables = load_sql(args.sql_file, overrides)

    if variables:
        print(f"-- variables: {variables}\n")

    failed = 0
    with psycopg.connect(load_dsn(args.env), connect_timeout=15) as conn:
        conn.read_only = True
        with conn.cursor() as cur:
            cur.execute(f"SET statement_timeout = '{args.timeout}'")
            for n, stmt in enumerate(statements, 1):
                preview = " ".join(stmt.split())[:90]
                print(f"\n=== [{n}/{len(statements)}] {preview}…\n", flush=True)
                try:
                    cur.execute(stmt)
                    print(render(cur), flush=True)
                except Exception as exc:                       # noqa: BLE001
                    # Keep going so the later statements still run, but say so at exit:
                    # a timed-out survey that exits 0 reads as "done" to whatever called it.
                    print(f"!! FAILED: {type(exc).__name__}: {exc}", file=sys.stderr, flush=True)
                    failed += 1
                    if conn.closed or conn.broken:
                        # The replica (or the port-forward under it) went away: nothing left to
                        # roll back, and nothing after this can run. Measured 2026-10-05 when the
                        # tunnel hit its lifetime 78 minutes into a survey.
                        sys.exit(f"connection lost after {n - 1} statement(s); {failed} failed")
                    conn.rollback()
    if failed:
        sys.exit(f"{failed} of {len(statements)} statement(s) failed")


if __name__ == "__main__":
    main()
