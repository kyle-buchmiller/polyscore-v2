"""The base is only as current as the query that pulled it -- and nothing else says so."""
from polyscore_v2.sql import base_query_drift, load_sql, statements_sha256

SQL = """\\set window_start '2026-09-08'
\\set horizon_days 30
SELECT * FROM t WHERE completed >= :'window_start'::timestamp AND gap >= :horizon_days;
"""


def _manifest(path, overrides):
    statements, variables = load_sql(path, overrides)
    return {"query_sha256": statements_sha256(statements), "variables": variables}


def test_current_base_has_no_drift(tmp_path):
    path = tmp_path / "02_base_pull.sql"
    path.write_text(SQL)
    manifest = _manifest(path, {"window_start": "2024-01-01"})
    assert base_query_drift(manifest, path) is None


def test_variables_are_the_bases_own_not_the_defaults(tmp_path):
    # A base pulled with an override must verify against the file even though the
    # file's \\set default differs -- the manifest's variables win, not the defaults.
    path = tmp_path / "02_base_pull.sql"
    path.write_text(SQL)
    manifest = _manifest(path, {"window_start": "2024-01-01", "horizon_days": "45"})
    assert manifest["variables"]["horizon_days"] == "45"
    assert base_query_drift(manifest, path) is None


def test_edited_query_is_drift(tmp_path):
    path = tmp_path / "02_base_pull.sql"
    path.write_text(SQL)
    manifest = _manifest(path, {})
    path.write_text(SQL.replace("gap >= :horizon_days", "gap >= :horizon_days AND feed IS NULL"))
    reason = base_query_drift(manifest, path)
    assert reason and "different 02_base_pull.sql" in reason


def test_missing_hash_or_file_is_reported(tmp_path):
    path = tmp_path / "02_base_pull.sql"
    path.write_text(SQL)
    assert "no query_sha256" in base_query_drift({}, path)
    manifest = _manifest(path, {})
    assert "not found" in base_query_drift(manifest, tmp_path / "missing.sql")
