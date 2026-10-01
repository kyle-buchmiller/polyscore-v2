"""Run the pipeline/sql/*.sql files from Python, honouring psql's \\set subset.

The .sql files are written for psql because that is what an operator reaches for. This
module understands the same `\\set name value` and `:name` / `:'name'` forms, so one text
runs under psql or under the pipeline. Shared by run_sql.py and 01_extract.py.
"""

from __future__ import annotations

import pathlib
import re

SET_RE = re.compile(r"^\s*\\set\s+(\w+)\s+(.*?)\s*$", re.MULTILINE)


def dsn_from_env(env_path: pathlib.Path = pathlib.Path(".env")) -> str:
    for line in env_path.read_text().splitlines():
        if line.startswith("POLYSCORE_DB_URI="):
            return line.split("=", 1)[1].strip().replace("postgresql+psycopg://", "postgresql://")
    raise SystemExit(f"POLYSCORE_DB_URI not found in {env_path}")


def load_sql(path: pathlib.Path, overrides: dict[str, str] | None = None) -> tuple[list[str], dict[str, str]]:
    """Return the file's statements with variables substituted, and the variables used."""
    raw = path.read_text()
    variables = {m.group(1): m.group(2).strip("'") for m in SET_RE.finditer(raw)}
    variables.update(overrides or {})
    body = SET_RE.sub("", raw)
    for name, value in variables.items():
        # the lookbehind keeps `state::text` from reading `:text` as a variable
        body = re.sub(rf"(?<!:):'{name}'", f"'{value}'", body)
        body = re.sub(rf"(?<!:):{name}\b", value, body)
    return split_statements(body), variables


def split_statements(sql: str) -> list[str]:
    """Split on semicolons outside string literals and `--` comments; drop comment-only chunks."""
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
                if i + 1 < len(sql) and sql[i + 1] == "'":
                    buf.append("'"); i += 1
                else:
                    in_str = False
        elif ch == "-" and sql[i + 1 : i + 2] == "-":
            in_comment = True; buf.append(ch)
        elif ch == "'":
            in_str = True; buf.append(ch)
        elif ch == ";":
            s = "".join(buf).strip()
            if s: out.append(s)
            buf = []
        else:
            buf.append(ch)
        i += 1
    tail = "".join(buf).strip()
    if tail: out.append(tail)
    return [s for s in out
            if not all(l.strip().startswith("--") or not l.strip() for l in s.splitlines())]
