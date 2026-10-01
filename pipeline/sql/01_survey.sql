-- 01 · Survey — counts and the band histogram. NO DRAW HAPPENS HERE.
--
-- This is the decision point. It answers two questions that can invalidate the
-- plan before a single row is downloaded:
--   1. Does the SS1 population actually contain ~10,000 usable artifacts?
--   2. Do the SS9 bands populate anywhere near their target shares?
-- Read specs/01-estimand.md SS9 before reading the output.
--
-- Read-only. Expect minutes, not seconds -- it aggregates over assertions.

\set window_start '2026-09-08'
\set window_end   '2026-10-01'
\set horizon_days 30

-- Scans that are in-scope per estimand SS1, revealed, and PE-ish.
-- mimetype is NECESSARY BUT NOT SUFFICIENT: WINDOWS_EXECUTABLE_MIMETYPES also
-- admits CAB, MSI, MS Access and VBE, so the authoritative PE gate is the
-- OpenSearch pass in 02. This list is the three that are actually PE-bearing.
WITH scoped AS (
    SELECT ai.number, ai.sha256, ai.completed
      FROM artifactinstance ai
     WHERE ai.meta_community = '_public'          -- NOTE the leading underscore
       AND ai.artifact_type  = 'FILE'
       AND ai.completed IS NOT NULL               -- revealed; NOT window_closed
       AND ai.failed IS NOT TRUE
       AND ai.state::text <> 'KNOWN_GOOD'
       AND ai.scan_config IS DISTINCT FROM 'feed' -- IS DISTINCT FROM: NULL is common
       AND COALESCE(ai.actions->>'scan', ai.actions->>'_default', 'true')::boolean
       AND ai.mimetype IN ('application/x-dosexec',
                           'application/vnd.microsoft.portable-executable',
                           'application/x-msdownload')
),
-- The artifact's FIRST EVER reveal, not merely its first in-window one.
-- Estimand SS4 measures the horizon from first sighting, so an artifact whose
-- true first sighting predates the window is a different object and is dropped.
first_ever AS (
    SELECT ai.sha256, min(ai.completed) AS first_reveal
      FROM artifactinstance ai
     WHERE ai.completed IS NOT NULL
       AND ai.failed IS NOT TRUE
       AND ai.sha256 IN (SELECT sha256 FROM scoped)
     GROUP BY ai.sha256
),
-- T: the feature scan. One per artifact, per SS1's per-artifact counting rule.
feature_scan AS (
    SELECT DISTINCT ON (s.sha256)
           s.sha256, s.number AS instance_number, s.completed AS scoring_moment
      FROM scoped s
      JOIN first_ever f
        ON f.sha256 = s.sha256
       AND f.first_reveal = s.completed
     WHERE f.first_reveal >= :'window_start'::timestamp
       AND f.first_reveal <  :'window_end'::timestamp
     ORDER BY s.sha256, s.number          -- deterministic on a reveal-time tie
),
-- T+30: does a later scan exist to label from? Without one the row is
-- unlabellable and must not be counted as available.
label_scan AS (
    -- NEAREST scan at or after the horizon, deliberately UNBOUNDED above here --
    -- the survey's job is to show how far out the tail actually goes so the
    -- tolerance in 02_draw.sql can be set from data rather than guessed.
    SELECT DISTINCT ON (fs.sha256)
           fs.sha256,
           ai.completed AS label_moment,
           ai.completed - fs.scoring_moment AS label_gap
      FROM feature_scan fs
      JOIN artifactinstance ai
        ON ai.sha256 = fs.sha256
       AND ai.completed >= fs.scoring_moment + (:horizon_days || ' days')::interval
     WHERE ai.completed IS NOT NULL
       AND ai.failed IS NOT TRUE
     ORDER BY fs.sha256, ai.completed ASC
),
-- m, at the feature scan. Denominator is engines that gave a DEFINITE verdict.
-- verdict IS NULL (answered "unknown") and no-row (never responded) are both
-- excluded rather than folded into benign -- see estimand SS9.
verdicts AS (
    SELECT fs.sha256,
           count(*) FILTER (WHERE a.verdict IS NOT NULL) AS n_definite,
           count(*) FILTER (WHERE a.verdict IS TRUE)     AS n_malicious,
           count(*)                                       AS n_responded
      FROM feature_scan fs
      JOIN assertions a ON a.instance_id = fs.instance_number   -- .number, NOT .id
     GROUP BY fs.sha256
),
banded AS (
    SELECT fs.sha256,
           v.n_definite,
           v.n_responded,
           (l.sha256 IS NOT NULL) AS labellable,
           l.label_gap,
           CASE WHEN v.n_definite IS NULL OR v.n_definite < 5 THEN 'below_floor'
                ELSE CASE
                  WHEN v.n_malicious::float / v.n_definite = 0   THEN 'consensus_clean'
                  WHEN v.n_malicious::float / v.n_definite <= 0.2 THEN 'leaning_clean'
                  WHEN v.n_malicious::float / v.n_definite < 0.8  THEN 'contested'
                  WHEN v.n_malicious::float / v.n_definite < 1.0  THEN 'leaning_malicious'
                  ELSE 'consensus_malicious'
                END
           END AS stratum
      FROM feature_scan fs
      LEFT JOIN verdicts   v ON v.sha256 = fs.sha256
      LEFT JOIN label_scan l ON l.sha256 = fs.sha256
)
SELECT stratum,
       count(*)                                   AS artifacts,
       count(*) FILTER (WHERE labellable)         AS labellable,
       round(100.0 * count(*) FILTER (WHERE labellable)
             / nullif(sum(count(*) FILTER (WHERE labellable)) OVER (), 0), 1)
                                                  AS pct_of_labellable,
       round(avg(n_definite)::numeric, 1)         AS avg_definite_verdicts,
       round(avg(n_responded)::numeric, 1)        AS avg_responded,
       -- The label-gap distribution. T+30 is a TARGET, not a floor: a label taken
       -- at T+400 carries far more detection accrual than one at T+31, so a long
       -- tail here means the label means different things across rows.
       justify_interval(percentile_disc(0.50)
             WITHIN GROUP (ORDER BY label_gap))    AS gap_p50,
       justify_interval(percentile_disc(0.90)
             WITHIN GROUP (ORDER BY label_gap))    AS gap_p90,
       justify_interval(max(label_gap))            AS gap_max,
       -- Coverage at T. A band whose artifacts answer with far fewer engines than
       -- typical is not comparable to one at full coverage: m over 7 of ~16 engines
       -- is a small and possibly biased sample, and its apparent movement by the
       -- horizon is largely the sample filling in rather than anyone learning.
       -- This is what the answering-engine floor must be set against.
       min(n_definite)                             AS definite_min,
       percentile_disc(0.10) WITHIN GROUP (ORDER BY n_definite) AS definite_p10
  FROM banded
 GROUP BY stratum
 ORDER BY artifacts DESC;

-- HOW TO READ THIS
--
-- `labellable` is the real cohort size. `artifacts` minus `labellable` is the
-- count with no T+30 scan yet, which is a WAITING problem, not a data problem.
--
-- Compare pct_of_labellable against the SS9 targets:
--     contested 45 | leaning_* 15 each | consensus_* 10 each
-- The targets are a claim about where the hard cases live, made before anyone
-- looked. If `contested` comes back at 3%, the bands move -- not the draw.
--
-- THE GAP COLUMNS SET A PARAMETER. gap_p50/p90/max are what 02_draw.sql's
-- horizon_max_days should be chosen from. If p90 is ~35 days, a 90-day tolerance
-- is generous and harmless. If p90 is 200 days, most labels are not T+30 labels at
-- all and the horizon needs rethinking before the draw -- not after.
-- Compare gaps ACROSS strata too: if contested rows carry systematically longer
-- gaps than consensus ones, label heterogeneity is correlated with difficulty,
-- which is the worst available shape for it.
--
-- `below_floor` is the answering-engine floor (specs/99-open-questions.md), set
-- to 5 here as a PLACEHOLDER. If this bucket is large, the floor is doing more
-- work than intended and needs choosing deliberately rather than guessing.
--
-- If total labellable is far below 10,000, the options in order of preference:
--   widen the window forward (more recent artifacts, shorter horizon wait);
--   lower the cohort size and say so;
--   admit non-public communities and record the skew.
-- Do NOT relax the feed filter to make the number look better.
