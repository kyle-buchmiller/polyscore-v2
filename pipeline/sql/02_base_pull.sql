-- 02 · Base pull — every eligible artifact in the window, with its natural label scan.
--
-- NO SAMPLING HAPPENS HERE. pi_base = 1. This is tier one of the two-tier extraction
-- (estimand SS11, decisions/0010): one heavy query that runs rarely and is the
-- reproducibility unit. Every run draw -- 10k or 1M, one seed or fifty -- samples
-- from the Parquet this produces, locally, never from the database again.
--
-- WHY NOT STRATIFY HERE. Band edges are parameters that may be revised once stage 02
-- has reported how the bands populate. Baking a stratum into the base would force a
-- re-pull to change them. So the base carries n_malicious and n_definite per
-- artifact and the run draw computes the stratum from the current edges, recording
-- which edges it used in its manifest. The base is edge-agnostic.
--
-- WHY NATURAL RESCANS. The training arm draws from scans that already happened; the
-- gap is recorded per row and bounded above. The forced-rescan VALIDATION arm is a
-- separate, small pull (runbook step 6) and is never trained on.
--
-- THE PE GATE IS NOT HERE. The replica is a hot standby and refuses CREATE TEMP TABLE
-- (measured 2026-10-01: pg_is_in_recovery() = true, ReadOnlySqlTransaction on any
-- CREATE), so the confirmed-PE set cannot be joined in SQL. 01_extract.py applies it
-- in pandas AFTER this pull and BEFORE writing the base, so the base Parquet is still
-- the confirmed set and the run draw's pi is still computed over confirmed-PE band
-- populations. The mimetype predicate below is the cheap pre-filter only.

\set window_start     '2026-09-08'
\set window_end       '2026-10-01'
\set horizon_days     30
\set horizon_max_days 90      -- SET FROM 01_survey's gap_p90. Provisional.

WITH scoped AS (
    SELECT ai.number, ai.sha256, ai.completed
      FROM artifactinstance ai
     WHERE ai.meta_community = '_public'
       AND ai.artifact_type  = 'FILE'
       AND ai.completed IS NOT NULL
       AND ai.failed IS NOT TRUE
       AND ai.state::text <> 'KNOWN_GOOD'
       AND ai.scan_config IS DISTINCT FROM 'feed'
       AND COALESCE(ai.actions->>'scan', ai.actions->>'_default', 'true')::boolean
       AND ai.mimetype IN ('application/x-dosexec',
                           'application/vnd.microsoft.portable-executable',
                           'application/x-msdownload')   -- pre-filter; NOT the PE gate
       AND ai.completed >= :'window_start'::timestamp
),
first_ever AS (
    SELECT ai.sha256, min(ai.completed) AS first_reveal
      FROM artifactinstance ai
     WHERE ai.completed IS NOT NULL AND ai.failed IS NOT TRUE
       AND ai.sha256 IN (SELECT sha256 FROM scoped)
     GROUP BY ai.sha256
),
feature_scan AS (
    SELECT DISTINCT ON (s.sha256)
           s.sha256, s.number AS instance_number, s.completed AS scoring_moment
      FROM scoped s
      JOIN first_ever f ON f.sha256 = s.sha256 AND f.first_reveal = s.completed
     WHERE f.first_reveal >= :'window_start'::timestamp
       AND f.first_reveal <  :'window_end'::timestamp
     ORDER BY s.sha256, s.number
),
label_scan AS (
    -- Nearest NATURAL scan inside [horizon, horizon_max]. DISTINCT ON so the instance
    -- number and the timestamp come from the same row.
    SELECT DISTINCT ON (fs.sha256)
           fs.sha256,
           ai.number    AS label_instance_number,
           ai.completed AS label_moment,
           ai.completed - fs.scoring_moment AS label_gap
      FROM feature_scan fs
      JOIN artifactinstance ai
        ON ai.sha256 = fs.sha256
       AND ai.completed >= fs.scoring_moment + (:horizon_days     || ' days')::interval
       AND ai.completed <  fs.scoring_moment + (:horizon_max_days || ' days')::interval
     WHERE ai.completed IS NOT NULL AND ai.failed IS NOT TRUE
     ORDER BY fs.sha256, ai.completed ASC
),
verdicts AS (
    SELECT fs.sha256,
           count(*) FILTER (WHERE a.verdict IS NOT NULL) AS n_definite,
           count(*) FILTER (WHERE a.verdict IS TRUE)     AS n_malicious,
           count(*)                                       AS n_responded
      FROM feature_scan fs
      JOIN assertions a ON a.instance_id = fs.instance_number
     GROUP BY fs.sha256
)
SELECT fs.sha256,
       fs.instance_number,
       fs.scoring_moment,
       l.label_instance_number,
       l.label_moment,
       l.label_gap,
       v.n_definite,
       v.n_malicious,
       v.n_responded,
       'organic' AS provenance
  FROM feature_scan fs
  JOIN label_scan l ON l.sha256 = fs.sha256       -- INNER: no natural label, not in the base
  JOIN verdicts   v ON v.sha256 = fs.sha256
 ORDER BY fs.sha256;                               -- deterministic; the base is content-hashed

-- WHAT TO CHECK
-- 1. Row count against 01_survey's `labellable`. They should agree; a gap means the
--    horizon_max_days bound or the PE confirmation moved the population.
-- 2. The content hash of the Parquet this becomes goes into every run manifest. Two
--    base pulls of the same window on different days WILL differ -- the database
--    moved -- and that is why a run records which base it drew from.
