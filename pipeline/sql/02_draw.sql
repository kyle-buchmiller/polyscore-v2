-- 02 · The draw — stratified, with pi recorded per row.
--
-- PRECONDITION: a temp table `pe_confirmed(sha256 char(64) primary key)` holding
-- the OpenSearch-confirmed PE set. Stage 01 populates it.
--
--   CREATE TEMP TABLE pe_confirmed (sha256 char(64) PRIMARY KEY);
--   -- then COPY / execute_values the confirmed hashes in
--
-- WHY THAT ORDER MATTERS. It is tempting to draw first and prune non-PE rows
-- afterwards. That silently corrupts pi: the inclusion probability is
-- n_drawn / n_available, and pruning after the draw changes n_available without
-- changing the recorded pi. Every 1/pi reweighting downstream -- the natural
-- prevalence view, the intercept correction, every rate metric -- would then be
-- wrong by a factor nobody can recover. Confirm the population, THEN draw.
--
-- Deterministic: the permutation is keyed by md5(sha256 || seed), so the same
-- seed and the same confirmed set reproduce the same cohort exactly. It does
-- NOT depend on connection state the way setseed()/random() does.

\set window_start '2026-09-08'
\set window_end   '2026-10-01'
\set horizon_days 30
\set cohort_size  10000
\set seed         '20260922'
\set min_definite 5

WITH scoped AS (
    SELECT ai.number, ai.sha256, ai.completed
      FROM artifactinstance ai
      JOIN pe_confirmed pc ON pc.sha256 = ai.sha256      -- the PE gate, applied FIRST
     WHERE ai.meta_community = '_public'
       AND ai.artifact_type  = 'FILE'
       AND ai.completed IS NOT NULL
       AND ai.failed IS NOT TRUE
       AND ai.state::text <> 'KNOWN_GOOD'
       AND ai.scan_config IS DISTINCT FROM 'feed'
       AND COALESCE(ai.actions->>'scan', ai.actions->>'_default', 'true')::boolean
),
first_ever AS (
    SELECT ai.sha256, min(ai.completed) AS first_reveal
      FROM artifactinstance ai
     WHERE ai.completed IS NOT NULL
       AND ai.failed IS NOT TRUE
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
    SELECT fs.sha256,
           min(ai.completed) AS label_moment,
           min(ai.number)    AS label_instance_number
      FROM feature_scan fs
      JOIN artifactinstance ai
        ON ai.sha256 = fs.sha256
       AND ai.completed >= fs.scoring_moment + (:horizon_days || ' days')::interval
     WHERE ai.completed IS NOT NULL AND ai.failed IS NOT TRUE
     GROUP BY fs.sha256
),
verdicts AS (
    SELECT fs.sha256,
           count(*) FILTER (WHERE a.verdict IS NOT NULL) AS n_definite,
           count(*) FILTER (WHERE a.verdict IS TRUE)     AS n_malicious
      FROM feature_scan fs
      JOIN assertions a ON a.instance_id = fs.instance_number
     GROUP BY fs.sha256
),
eligible AS (
    SELECT fs.sha256, fs.instance_number, fs.scoring_moment,
           l.label_moment, l.label_instance_number,
           v.n_definite, v.n_malicious,
           CASE
             WHEN v.n_malicious::float / v.n_definite = 0    THEN 'consensus_clean'
             WHEN v.n_malicious::float / v.n_definite <= 0.2 THEN 'leaning_clean'
             WHEN v.n_malicious::float / v.n_definite <  0.8 THEN 'contested'
             WHEN v.n_malicious::float / v.n_definite <  1.0 THEN 'leaning_malicious'
             ELSE 'consensus_malicious'
           END AS stratum
      FROM feature_scan fs
      JOIN label_scan l ON l.sha256 = fs.sha256      -- INNER: unlabellable is not eligible
      JOIN verdicts   v ON v.sha256 = fs.sha256
     WHERE v.n_definite >= :min_definite             -- below_floor is its own stratum,
),                                                    -- reported but never drawn into a band
targets(stratum, target_share) AS (
    VALUES ('contested',           0.45),
           ('leaning_malicious',   0.15),
           ('leaning_clean',       0.15),
           ('consensus_malicious', 0.10),
           ('consensus_clean',     0.10)
    -- injected_known_good (0.05) is NOT drawn here: it is externally sourced,
    -- has no inclusion probability by construction, and never participates in
    -- prevalence estimation. See estimand SS9 "The injection arm".
),
sizes AS (
    SELECT stratum, count(*) AS n_available FROM eligible GROUP BY stratum
),
quota AS (
    SELECT t.stratum,
           s.n_available,
           LEAST(s.n_available,
                 ceil(:cohort_size * t.target_share)::int) AS n_draw
      FROM targets t
      JOIN sizes   s USING (stratum)
),
ranked AS (
    SELECT e.*,
           row_number() OVER (PARTITION BY e.stratum
                              ORDER BY md5(e.sha256 || :'seed')) AS rn
      FROM eligible e
)
SELECT r.sha256,
       r.instance_number,
       r.scoring_moment,
       r.label_instance_number,
       r.label_moment,
       r.stratum,
       r.n_definite,
       r.n_malicious,
       q.n_draw::float / q.n_available AS pi,      -- THE column. Without it the
       'organic'                       AS provenance,  -- cohort is ranking-only.
       q.n_available,
       q.n_draw
  FROM ranked r
  JOIN quota  q USING (stratum)
 WHERE r.rn <= q.n_draw
 ORDER BY r.stratum, r.rn;

-- WHAT TO CHECK IN THE OUTPUT, BEFORE USING IT
--
-- 1. For every stratum, is n_draw = ceil(cohort_size * share)? If n_draw equals
--    n_available instead, that band UNDER-FILLED. Report the shortfall. Do not
--    back-fill from a neighbouring band -- that silently changes the draw and
--    makes pi a lie for both bands.
-- 2. Is pi <= 1.0 everywhere? pi = 1.0 means the band was taken whole, which is
--    legitimate but means that band carries no sampling variance.
-- 3. Does the row count match the sum of n_draw? A mismatch means a join fanned out.
