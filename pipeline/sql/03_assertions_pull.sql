-- 03 · Assertions pull — long form, for a CHUNK of scan instance numbers.
--
-- One row per (instance_number, author). 01_extract.py runs this once per chunk of
-- instance numbers (both scans of every base artifact) and attaches sha256 and
-- scan_role in pandas from the base. Chunking is how it streams: at 1M artifacts this
-- is ~30M rows and must never be materialized by one query.
--
-- NOT a \set file: %(instance_numbers)s is a psycopg parameter (a bigint array). The
-- replica is a hot standby and cannot hold a temp table of the keys, so the keys ride
-- in as a parameter instead (measured 2026-10-01).
--
-- Projected, never whole: engine_metadata is JSONB that can run to kilobytes per row.
-- Every field added here is multiplied by ~30M rows.

SELECT a.instance_id AS instance_number,
       a.author,                                    -- the ADDRESS, never a name
       a.verdict,                                   -- nullable boolean: the 3rd state
       a.bid,
       a.engine_metadata->>'malware_family' AS malware_family,
       a.engine_metadata->>'scanner'        AS scanner_version
  FROM assertions a
 WHERE a.instance_id = ANY(%(instance_numbers)s)    -- .number, NOT .id
 ORDER BY a.instance_id, a.author;

-- The 4th state -- an engine that never responded -- is the ABSENCE of a row here.
-- Stage 04 reconstructs it against the engine roster at the scoring moment; nothing
-- in this file can represent it, and that is correct.
