"""Run the pipeline/sql/*.sql files from Python, honouring psql's \\set subset.

The .sql files are written for psql because that is what an operator reaches for. This
module understands the same `\\set name value` and `:name` / `:'name'` forms, so one text
runs under psql or under the pipeline. Shared by run_sql.py and 01_extract.py.
"""

from __future__ import annotations

import hashlib
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


def statements_sha256(statements: list[str]) -> str:
    """The hash 01_extract records as `query_sha256`: over the rendered statements."""
    return hashlib.sha256("\n".join(statements).encode()).hexdigest()


def base_query_drift(manifest: dict, sql_path: pathlib.Path) -> str | None:
    """Re-render `sql_path` with the base's own variables and compare to its `query_sha256`.

    None when the base was pulled by the query on disk; otherwise a one-line reason.
    A base that predates a change to 02_base_pull.sql is not wrong in any way a draw can
    see: the 25-row stage rehearsal base ran through the draw, five stability runs and
    stage 02 after decision 0010 had changed the population under it. So it is checked.
    """
    recorded = manifest.get("query_sha256")
    if not recorded:
        return "base manifest records no query_sha256"
    if not sql_path.exists():
        return f"{sql_path} not found; cannot verify the base against it"
    statements, _ = load_sql(sql_path, manifest.get("variables") or {})
    if statements_sha256(statements) != recorded:
        return (f"base was pulled by a different {sql_path.name} than the one on disk "
                f"(recorded {recorded[:12]}...): re-pull, or set POLYSCORE_ALLOW_STALE_BASE=1")
    return None
