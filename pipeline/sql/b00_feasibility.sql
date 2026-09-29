-- B00 · Feasibility — three questions that decide whether Estimand B is possible.
--
-- Run these BEFORE b01_survey.sql and before writing any B filter. Each can end
-- the exercise on its own, and each is cheap relative to what it prevents.
-- See specs/10-estimand-b-settled-state.md.
--
-- COST WARNING: unlike A's 00_verify, these scan the full history rather than a
-- 30-day window. Run them on the read replica, expect minutes to tens of minutes,
-- and run them one at a time rather than as a script.

-- ============================================================================
-- Q1 · How far back does the data actually go?
--      "Ten years" is an assumption. If the answer is four, B buys less breadth
--      than expected and its era axis has fewer cells than planned.
-- ============================================================================
SELECT min(created) AS earliest,
       max(created) AS latest,
       count(*)     AS total_instances
  FROM artifactinstance;

SELECT date_trunc('year', created)::date        AS yr,
       count(*)                                  AS instances,
       count(DISTINCT sha256)                    AS artifacts,
       count(*) FILTER (WHERE completed IS NOT NULL) AS revealed
  FROM artifactinstance
 GROUP BY 1 ORDER BY 1;
--   EXPECT: a ramp. A year with instances but near-zero `revealed` is a year
--   whose rows cannot serve as a scoring moment at all -- see Q2.

-- ============================================================================
-- Q2 · When did each filter column START being written?
--      THE TRAP THIS EXISTS FOR: a column added in year N is NULL on every row
--      before it. `scan_config IS DISTINCT FROM 'feed'` then passes every
--      pre-column row regardless of what it was, so a filter that works
--      perfectly on recent data silently becomes a no-op on old data -- and a
--      feed-contaminated cohort enters with nothing looking wrong.
--
--      This is a PROXY for the migration history, not a substitute. Read the
--      migrations too; this tells you where to look.
-- ============================================================================
SELECT date_trunc('year', created)::date AS yr,
       count(*)                           AS rows,
       round(100.0 * count(scan_config)    / count(*), 1) AS pct_scan_config,
       round(100.0 * count(meta_community) / count(*), 1) AS pct_meta_community,
       round(100.0 * count(actions)        / count(*), 1) AS pct_actions,
       round(100.0 * count(api_key)        / count(*), 1) AS pct_api_key,
       round(100.0 * count(completed)      / count(*), 1) AS pct_completed,
       round(100.0 * count(extended_type)  / count(*), 1) AS pct_extended_type
  FROM artifactinstance
 GROUP BY 1 ORDER BY 1;
--   READ IT AS: the first year a column goes from ~0% to substantially non-zero
--   is roughly when it began being written. B's window MUST START AT OR AFTER
--   the latest such year across every column its filters depend on -- otherwise
--   the filters are decorative for the earlier part of the range.
--
--   If that cutoff lands close to A's window, B buys little and should be
--   reconsidered rather than rescued.

-- ============================================================================
-- Q3 · Engine roster stability — how big is the era-stable vocabulary?
--      B's central risk is that a feature vector keyed by engine address is
--      mostly never-responded outside a given engine's lifetime, and that
--      missingness correlates with age. This sizes the problem.
--
--      EXPENSIVE. Consider restricting to revealed instances, or sampling.
-- ============================================================================
WITH per_year AS (
    SELECT date_trunc('year', ai.created)::date AS yr,
           a.author,
           count(*) AS assertions
      FROM artifactinstance ai
      JOIN assertions a ON a.instance_id = ai.number
     WHERE ai.completed IS NOT NULL
     GROUP BY 1, 2
    HAVING count(*) >= 100        -- ignore engines with a trivial presence in a year
)
SELECT yr, count(*) AS engines_active
  FROM per_year GROUP BY yr ORDER BY yr;

-- The intersection: engines present in EVERY year of the span. This is the
-- era-stable per-engine vocabulary, and its size is the price of B.
WITH per_year AS (
    SELECT date_trunc('year', ai.created)::date AS yr, a.author
      FROM artifactinstance ai
      JOIN assertions a ON a.instance_id = ai.number
     WHERE ai.completed IS NOT NULL
     GROUP BY 1, 2
    HAVING count(*) >= 100
),
span AS (SELECT count(DISTINCT yr) AS n_years FROM per_year)
SELECT count(*) AS engines_present_every_year
  FROM (SELECT author FROM per_year
         GROUP BY author
        HAVING count(DISTINCT yr) = (SELECT n_years FROM span)) s;
--   READ IT AS: if this comes back at 8 engines out of ~250, the era-stable
--   per-engine vocabulary is nearly empty and B must lean almost entirely on
--   aggregate features. That is a real cost and it is what the A-restricted run
--   in SSB8 exists to price. If it comes back at 80, B is cheap.
--
--   Either way, DO NOT widen the span to make this number look better -- the
--   number IS the finding.
