-- 02b · Label chunk -- for a CHUNK of frame rows, the nearest natural later scan inside
-- [horizon_days, horizon_max_days] and the verdict counts at T.
--
-- The chunk rides in as parallel arrays through unnest(): the replica is a hot standby
-- and cannot hold a temp table of the keys. LEFT JOINs keep every frame row: a row with
-- NULL label columns is UNLABELLABLE -- counted by the survey, drawn into the control
-- sample for the rescan probe, and never in the base.
--
-- NOT a \set file: the placeholders are named psycopg parameters (parsed even in comments).

WITH fs AS (
    -- char(64), not text: artifactinstance.sha256 is CHAR(64), and a text-typed key makes
    -- the join cast the column and lose ix_artifactinstance_sha256 -- measured 2026-10-05:
    -- a full sequential scan of 6M rows per chunk, 25 s for 25 artifacts.
    SELECT * FROM unnest(%(sha256s)s::char(64)[], %(instance_numbers)s::bigint[], %(moments)s::timestamp[])
                  AS t(sha256, instance_number, scoring_moment)
),
label_scan AS (
    SELECT DISTINCT ON (fs.sha256)
           fs.sha256,
           ai.number    AS label_instance_number,
           ai.completed AS label_moment,
           ai.completed - fs.scoring_moment AS label_gap
      FROM fs
      JOIN artifactinstance ai
        ON ai.sha256 = fs.sha256
       AND ai.completed >= fs.scoring_moment + make_interval(days => %(horizon_days)s)
       AND ai.completed <  fs.scoring_moment + make_interval(days => %(horizon_max_days)s)
     WHERE ai.completed IS NOT NULL AND ai.failed IS NOT TRUE
       AND EXISTS (SELECT 1 FROM assertions x WHERE x.instance_id = ai.number)   -- a scan, not an ingestion record
     ORDER BY fs.sha256, ai.completed ASC
),
verdicts AS (
    SELECT fs.sha256,
           count(*) FILTER (WHERE a.verdict IS NOT NULL) AS n_definite,
           count(*) FILTER (WHERE a.verdict IS TRUE)     AS n_malicious,
           count(*)                                       AS n_responded
      FROM fs
      JOIN assertions a ON a.instance_id = fs.instance_number   -- .number, NOT .id
     GROUP BY fs.sha256
)
SELECT fs.sha256,
       l.label_instance_number,
       l.label_moment,
       l.label_gap,
       v.n_definite,
       v.n_malicious,
       v.n_responded
  FROM fs
  LEFT JOIN label_scan l ON l.sha256 = fs.sha256
  LEFT JOIN verdicts   v ON v.sha256 = fs.sha256
 ORDER BY fs.sha256;
