"""Run the pipeline/sql/*.sql files from Python, honouring psql's \\set subset.

The .sql files are written for psql because that is what an operator reaches for. This
module understands the same `\\set name value` and `:name` / `:'name'` forms, so one text
runs under psql or under the pipeline. Shared by run_sql.py and 01_extract.py.
"""

from __future__ import annotations

import hashlib
import json
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
    """Hash over rendered statements -- what pre-restructure manifests recorded."""
    return hashlib.sha256("\n".join(statements).encode()).hexdigest()


def query_sha256(sql_dir: pathlib.Path, files: list[str], variables: dict) -> str:
    """The hash 01_extract records as `query_sha256`: the SQL files it ran, in order, plus
    the variables it ran them with. Parameterized files render at execution time, so the
    text and the parameters are hashed together rather than a rendering."""
    h = hashlib.sha256()
    for name in files:
        h.update((sql_dir / name).read_text().encode()); h.update(b"\0")
    h.update(json.dumps(variables, sort_keys=True, default=str).encode())
    return h.hexdigest()


def base_query_drift(manifest: dict, sql_dir: pathlib.Path) -> str | None:
    """Recompute the base's query hash from the SQL on disk and compare.

    None when the base was pulled by the queries on disk; otherwise a one-line reason.
    A base that predates a change to the extraction SQL is not wrong in any way a draw
    can see: the 25-row stage rehearsal base ran through the draw, five stability runs and
    stage 02 after decision 0010 had changed the population under it. So it is checked.
    """
    recorded = manifest.get("query_sha256")
    if not recorded:
        return "base manifest records no query_sha256"
    files = manifest.get("query_files")
    variables = manifest.get("variables") or {}
    if files:
        missing = [f for f in files if not (sql_dir / f).exists()]
        if missing:
            return f"{missing} not found under {sql_dir}; cannot verify the base against them"
        now = query_sha256(sql_dir, files, variables)
    else:
        # A pre-restructure manifest: one \set file rendered with its variables.
        legacy = sql_dir / "02_base_pull.sql"
        if not legacy.exists():
            return f"{legacy} not found; cannot verify a pre-restructure base against it"
        statements, _ = load_sql(legacy, variables)
        now = statements_sha256(statements)
    if now != recorded:
        return (f"base was pulled by different extraction SQL than the files on disk "
                f"(recorded {recorded[:12]}...): re-pull, or set POLYSCORE_ALLOW_STALE_BASE=1")
    return None
