#!/usr/bin/env python3
"""Run a pipeline/sql/*.sql file without needing the psql binary.

The .sql files are written for psql -- they use `\\set name value` and the
`:name` / `:'name'` substitution forms -- because psql is what an operator on a
workstation reaches for. This runner understands that same subset so the files
stay single-source: identical text runs under psql and under this.

    .venv/bin/python pipeline/run_sql.py pipeline/sql/00_verify.sql
    .venv/bin/python pipeline/run_sql.py pipeline/sql/01_survey.sql --set window_start=2026-09-08

Read-only by construction: it opens a read-only transaction and sets a
statement timeout, so a runaway query on a shared replica cannot sit there.
"""

from __future__ import annotations

import argparse
import pathlib
import re
import sys

import psycopg

SET_RE = re.compile(r"^\s*\\set\s+(\w+)\s+(.*?)\s*$", re.MULTILINE)


def load_dsn(env_path: pathlib.Path) -> str:
    for line in env_path.read_text().splitlines():
        if line.startswith("POLYSCORE_DB_URI="):
            uri = line.split("=", 1)[1].strip()
            return uri.replace("postgresql+psycopg://", "postgresql://")
    raise SystemExit(f"POLYSCORE_DB_URI not found in {env_path}")


def extract_vars(sql: str, overrides: dict[str, str]) -> tuple[str, dict[str, str]]:
    """Pull `\\set` declarations out of the text; CLI overrides win."""
    variables = {m.group(1): m.group(2).strip("'") for m in SET_RE.finditer(sql)}
    variables.update(overrides)
    return SET_RE.sub("", sql), variables


def substitute(sql: str, variables: dict[str, str]) -> str:
    """Apply psql's :'name' (quoted) and :name (bare) forms.

    The negative lookbehind is load-bearing: without it, `state::text` would have
    its `:text` treated as a variable reference.
    """
    for name, value in variables.items():
        sql = re.sub(rf"(?<!:):'{name}'", f"'{value}'", sql)
        sql = re.sub(rf"(?<!:):{name}\b", value, sql)
    return sql


def split_statements(sql: str) -> list[str]:
    """Split on semicolons that are not inside a string literal or a comment."""
    out, buf, in_str, in_comment = [], [], False, False
    i = 0
    while i < len(sql):
        ch = sql[i]
        if in_comment:
            if ch == "\n":
                in_comment = False
            buf.append(ch)
        elif in_str:
            buf.append(ch)
            if ch == "'":
                if i + 1 < len(sql) and sql[i + 1] == "'":   # escaped quote
                    buf.append(sql[i + 1]); i += 1
                else:
                    in_str = False
        elif ch == "-" and i + 1 < len(sql) and sql[i + 1] == "-":
            in_comment = True; buf.append(ch)
        elif ch == "'":
            in_str = True; buf.append(ch)
        elif ch == ";":
            stmt = "".join(buf).strip()
            if stmt:
                out.append(stmt)
            buf = []
        else:
            buf.append(ch)
        i += 1
    tail = "".join(buf).strip()
    if tail:
        out.append(tail)
    return [s for s in out if not all(l.strip().startswith("--") or not l.strip()
                                      for l in s.splitlines())]


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
    raw = args.sql_file.read_text()
    body, variables = extract_vars(raw, overrides)
    statements = split_statements(substitute(body, variables))

    if variables:
        print(f"-- variables: {variables}\n")

    with psycopg.connect(load_dsn(args.env), connect_timeout=15) as conn:
        conn.read_only = True
        with conn.cursor() as cur:
            cur.execute(f"SET statement_timeout = '{args.timeout}'")
            for n, stmt in enumerate(statements, 1):
                preview = " ".join(stmt.split())[:90]
                print(f"\n=== [{n}/{len(statements)}] {preview}…\n")
                try:
                    cur.execute(stmt)
                    print(render(cur))
                except Exception as exc:                       # noqa: BLE001
                    print(f"!! FAILED: {type(exc).__name__}: {exc}", file=sys.stderr)
                    conn.rollback()


if __name__ == "__main__":
    main()
