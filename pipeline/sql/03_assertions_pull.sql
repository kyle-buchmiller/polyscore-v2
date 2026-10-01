-- 03 · Assertions pull — long form, both scans, for every artifact in the base.
--
-- One row per (sha256, scan_role, author). This is the feature space; the base
-- artifact table from 02 is its index. Projected, never whole: engine_metadata is
-- JSONB that can run to kilobytes per row, and at 1M artifacts x 2 scans x ~15
-- engines that is tens of gigabytes. Pull the fields the model uses and nothing else.
--
-- PRECONDITION: base_scans(instance_number bigint, sha256 char(64), scan_role text)
-- temp table loaded from the 02 output -- two rows per artifact, 'feature' and 'label'.
-- Stream this; do not materialize it in a client. See runbook step 5.

SELECT b.sha256,
       b.scan_role,
       b.instance_number,
       a.author,                                    -- the ADDRESS, never a name
       a.verdict,                                   -- nullable boolean: the 3rd state
       a.bid,
       a.engine_metadata->>'malware_family' AS malware_family,
       a.engine_metadata->>'scanner'        AS scanner_version
       -- add fields here deliberately; every one is multiplied by ~30M rows
  FROM base_scans b
  JOIN assertions a ON a.instance_id = b.instance_number   -- .number, NOT .id
 ORDER BY b.sha256, b.scan_role, a.author;

-- The 4th state -- an engine that never responded -- is the ABSENCE of a row here.
-- Stage 04 reconstructs it against the engine roster at the scoring moment; nothing
-- in this file can represent it, and that is correct.
