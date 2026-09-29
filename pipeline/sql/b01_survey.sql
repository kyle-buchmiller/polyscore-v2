-- B01 · Convergence survey — B's decision point. NO DRAW HAPPENS HERE.
--
-- A's survey asks "do the bands populate?". B's asks a harder question first:
-- HOW MANY ARTIFACTS EVER CONVERGE, and does that vary by era? If convergence
-- yield collapses in older years, B's breadth is illusory -- the old artifacts
-- are present but unlabellable, and B degenerates into a slower A.
--
-- Output is a FUNNEL per era, so you can see exactly which condition does the
-- killing rather than only that something did.
--
-- PREREQUISITE: b00_feasibility.sql. In particular `window_start` below must be
-- at or after the year every filter column began being written (b00 Q2) --
-- otherwise the filters are decorative for the earlier part of the range.
--
-- COST: this joins assertions across the full history. Minutes to tens of
-- minutes on the replica. Narrow `window_start` first if it will not return.

\set window_start   '2019-01-01'     -- SET FROM b00 Q2. Do not guess.
\set min_elapsed_days   365
\set min_later_scans      3
\set stability_k          3
\set stability_span_days 90
\set min_definite         5

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
                           'application/x-msdownload')
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
     ORDER BY s.sha256, s.number
),
-- Every scan strictly after T, with that scan's malicious count.
--
-- NOTE: the criterion in SSB3 is stability of the INDEPENDENT CLUSTER count, not
-- the raw engine count. Clustering does not exist yet (it is orphaned in
-- polyscore-pipeline and listed as R8), so this uses n_malicious as a STAND-IN.
-- It is the optimistic direction: correlated engines moving together look like
-- one change, so real clustering can only make convergence look *less* settled,
-- never more. Treat this survey's yield as an UPPER BOUND.
later AS (
    SELECT fs.sha256,
           ai.number,
           ai.completed,
           count(*) FILTER (WHERE a.verdict IS TRUE)     AS n_malicious,
           count(*) FILTER (WHERE a.verdict IS NOT NULL) AS n_definite
      FROM feature_scan fs
      JOIN artifactinstance ai
        ON ai.sha256 = fs.sha256
       AND ai.completed > fs.scoring_moment
      JOIN assertions a ON a.instance_id = ai.number
     WHERE ai.completed IS NOT NULL AND ai.failed IS NOT TRUE
     GROUP BY fs.sha256, ai.number, ai.completed
),
ranked AS (
    SELECT *, row_number() OVER (PARTITION BY sha256 ORDER BY completed DESC) AS rn
      FROM later
),
agg AS (
    SELECT fs.sha256,
           fs.scoring_moment,
           count(r.number)                                      AS n_later,
           max(r.completed) - fs.scoring_moment                 AS elapsed,
           -- the convergence test, over the last K scans
           count(DISTINCT r.n_malicious) FILTER (WHERE r.rn <= :stability_k) AS distinct_states,
           max(r.completed) FILTER (WHERE r.rn <= :stability_k)
             - min(r.completed) FILTER (WHERE r.rn <= :stability_k)          AS stable_span,
           max(r.n_definite)  FILTER (WHERE r.rn = 1)           AS final_definite,
           max(r.n_malicious) FILTER (WHERE r.rn = 1)           AS final_malicious
      FROM feature_scan fs
      LEFT JOIN ranked r ON r.sha256 = fs.sha256
     GROUP BY fs.sha256, fs.scoring_moment
)
SELECT date_trunc('year', scoring_moment)::date AS era,
       count(*)                                                          AS candidates,
       count(*) FILTER (WHERE n_later >= :min_later_scans)               AS f1_enough_scans,
       count(*) FILTER (WHERE n_later >= :min_later_scans
                          AND elapsed >= (:min_elapsed_days || ' days')::interval)
                                                                          AS f2_old_enough,
       count(*) FILTER (WHERE n_later >= :min_later_scans
                          AND elapsed >= (:min_elapsed_days || ' days')::interval
                          AND distinct_states = 1
                          AND stable_span >= (:stability_span_days || ' days')::interval)
                                                                          AS f3_converged,
       count(*) FILTER (WHERE n_later >= :min_later_scans
                          AND elapsed >= (:min_elapsed_days || ' days')::interval
                          AND distinct_states = 1
                          AND stable_span >= (:stability_span_days || ' days')::interval
                          AND final_definite >= :min_definite)            AS f4_labellable,
       round(100.0 * count(*) FILTER (WHERE n_later >= :min_later_scans
                          AND elapsed >= (:min_elapsed_days || ' days')::interval
                          AND distinct_states = 1
                          AND stable_span >= (:stability_span_days || ' days')::interval
                          AND final_definite >= :min_definite) / nullif(count(*), 0), 1)
                                                                          AS pct_yield
  FROM agg
 GROUP BY era
 ORDER BY era;

-- HOW TO READ THIS
--
-- Read ACROSS a row to see which condition kills artifacts:
--   candidates -> f1 is the rescan-coverage problem (most files are scanned once)
--   f1 -> f2    is simply age; it should be ~100% for old eras
--   f2 -> f3    is genuine non-convergence: still moving after years
--   f3 -> f4    is engine coverage at the final scan
--
-- Read DOWN the pct_yield column to see whether B's breadth is real. A yield of
-- 30% in 2024 and 2% in 2019 means the old artifacts exist but are not usable,
-- and B is a slower A wearing a decade's clothes. That is a STOP, not a reason
-- to loosen the criterion -- loosening it relabels unsettled artifacts as
-- settled, which is the one thing B must not do.
--
-- Compare f4_labellable against A's cohort size. B has to be materially larger
-- AND spread across eras to be worth the era-stable feature restriction it
-- forces (SSB8, SSB9).
--
-- The parameters above are placeholders chosen before anyone looked. A's churn
-- rate is the evidence that should set min_elapsed_days; until A has run, treat
-- every number here as provisional and record any change in decisions/.
