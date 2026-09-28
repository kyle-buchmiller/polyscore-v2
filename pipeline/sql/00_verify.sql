-- 00 · Verification — run these BEFORE anything else.
-- Each one decides a filter in 03_draw.sql. None needs a model or a label.
-- Read-only. Expect all of them to return in seconds.
-- See specs/99-open-questions.md "Verify against prod before stage 01 runs".

-- (a) Is the scan_config value domain what the seed says?
--     The four names come from a seed and the table is mutable, so the feed
--     filter rests on this being exhaustive.
SELECT name, bounty_duration FROM scan_configs ORDER BY name;
--     EXPECT: default, feed, more-time, most-time. Any extra name is a filter bug.

-- (b) What meta_community values actually exist, and at what volume?
--     Values carry LEADING UNDERSCORES. If '_public' returns nothing you have
--     filtered on the metrics bucketing ('public') by mistake.
SELECT meta_community, count(*)
  FROM artifactinstance
 WHERE created >= now() - interval '30 days'
 GROUP BY 1 ORDER BY 2 DESC;
--     EXPECT: '_public' dominant, '_development' present, private names in the tail.

-- (c) How does libmagic actually describe PE files here?
--     Decides whether an extended_type pre-filter has usable recall. Recall only
--     -- OpenSearch is the authoritative gate -- but a bad guess silently drops
--     64-bit or .NET binaries.
SELECT extended_type, count(*)
  FROM artifactinstance
 WHERE mimetype = 'application/x-dosexec'
   AND created >= now() - interval '30 days'
 GROUP BY 1 ORDER BY 2 DESC LIMIT 50;
--     EXPECT: 'PE32 executable ...' and 'PE32+ executable ...' at the top.
--     WATCH FOR: '.Net assembly' variants, and 'unknown filetype' (a libmagic
--     timeout, which is persisted and then drives analyzer selection).

-- (d) Do feed rows behave as assumed -- storage-only, and in which community?
--     polyfeeder's community is per-sink DB config, not a static value.
SELECT scan_config,
       meta_community,
       count(*)                                                   AS rows,
       count(*) FILTER (WHERE actions->>'_default' = 'false')     AS storage_only,
       count(*) FILTER (WHERE completed IS NOT NULL)              AS revealed
  FROM artifactinstance
 WHERE created >= now() - interval '7 days'
 GROUP BY 1, 2 ORDER BY 3 DESC;
--     EXPECT: scan_config='feed' rows are overwhelmingly storage_only and
--     rarely revealed. If they are mostly revealed, SS10's breadth assumption
--     changes and the feed filter is load-bearing in a way we did not plan for.

-- (e) Is `any_detections` ever written? Two independent code reads disagreed.
SELECT count(*)                                    AS total,
       count(any_detections)                       AS non_null,
       count(*) FILTER (WHERE any_detections)      AS true_rows
  FROM artifactinstance
 WHERE created >= now() - interval '7 days';
--     EXPECT (per the code): non_null = 0. If not, someone else writes it.

-- (f) Are `created` and `completed` on the same clock?
--     created comes from Postgres now() (server-local); completed from Python
--     datetime.now(timezone.utc); the column type carries no timezone. If the
--     session TZ is not UTC these differ by a fixed offset and every duration
--     we compute is wrong.
SHOW timezone;
SELECT percentile_disc(0.5) WITHIN GROUP (ORDER BY completed - created) AS median_reveal_lag,
       min(completed - created) AS min_lag,
       count(*) FILTER (WHERE completed < created) AS impossible_rows
  FROM artifactinstance
 WHERE completed IS NOT NULL
   AND created >= now() - interval '7 days';
--     EXPECT: median_reveal_lag on the order of the bounty duration (seconds to
--     minutes), min_lag >= 0, impossible_rows = 0.
--     A large constant offset, or impossible_rows > 0, means the two clocks differ.
