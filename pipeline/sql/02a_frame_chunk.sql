-- 02a · Frame chunk -- every artifact whose FIRST-EVER reveal falls in the window, among
-- instances CREATED in [created_from, created_to).
--
-- Why chunked by `created`: it is indexed (ix_artifactinstance_created_id_meta_community)
-- and `completed` is not, and completed >= created always, so the window on `completed`
-- is applied in-row while the created range bounds the scan. 01_extract.py walks the
-- range from window_start - slack to window_end a week at a time; each statement is
-- small, and the run resumes by chunk.
--
-- Why an anti-join for "first ever": the aggregate form (min(completed) per sha256 over
-- the whole table for every scoped sha256) was a second full scan hash-joined to all of
-- scoped through a disk-spilling aggregate -- measured 2026-10-05 on stage, it blew a
-- 30-minute statement timeout and a 78-minute one. NOT EXISTS probes ix_artifactinstance_sha256
-- once per candidate row instead. A row with an earlier completed instance ANYWHERE in
-- time is not the first sighting and is dropped; the artifact then appears in no chunk.
--
-- NOT a \set file: the placeholders are named psycopg parameters, and a doubled percent is a
-- literal one. (A placeholder-shaped token anywhere in this file, comments included, is parsed.)

WITH scoped AS (
    SELECT ai.number, ai.sha256, ai.completed, ai.scan_config, ai.polyscore
      FROM artifactinstance ai
     WHERE ai.created >= %(created_from)s AND ai.created < %(created_to)s
       AND ai.meta_community = '_public'          -- NOTE the leading underscore
       AND ai.artifact_type  = 'FILE'
       AND ai.completed IS NOT NULL               -- revealed; NOT window_closed
       AND ai.failed IS NOT TRUE
       AND ai.state::text <> 'KNOWN_GOOD'
       -- A SCAN has assertions. A completed instance with none is an ingestion record --
       -- measured on stage 2026-10-05: feed rows with result = TRUE, quorum_mask = TRUE,
       -- completed ~30 s after created, and zero assertion rows, about 23 percent of revealed
       -- artifacts. They carry a verdict by provenance, not by engines, and are neither
       -- a T scan nor a label scan here.
       AND EXISTS (SELECT 1 FROM assertions x WHERE x.instance_id = ai.number)
       -- NO feed exclusion (decision 0010 / SS10): scan_config is carried as provenance.
       AND COALESCE(ai.actions->>'scan', ai.actions->>'_default', 'true')::boolean
       AND ai.mimetype IN ('application/x-dosexec',
                           'application/vnd.microsoft.portable-executable',
                           'application/x-msdownload')   -- pre-filter; NOT the PE gate
       AND ai.completed >= %(window_start)s AND ai.completed < %(window_end)s
       AND (abs(hashtext(ai.sha256)) %% 100) < %(sample_pct)s   -- deterministic artifact sample; 100 = all
)
SELECT DISTINCT ON (s.sha256)
       s.sha256,
       s.number    AS instance_number,
       s.completed AS scoring_moment,
       s.scan_config,
       s.polyscore AS incumbent_polyscore    -- baseline 4, never a feature
  FROM scoped s
 WHERE NOT EXISTS (SELECT 1
                     FROM artifactinstance e
                    WHERE e.sha256 = s.sha256
                      AND e.completed IS NOT NULL AND e.failed IS NOT TRUE
                      AND e.completed < s.completed
                      AND EXISTS (SELECT 1 FROM assertions x WHERE x.instance_id = e.number))
 ORDER BY s.sha256, s.completed, s.number;      -- deterministic on a reveal-time tie
