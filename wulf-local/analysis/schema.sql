CREATE TABLE IF NOT EXISTS wulf_local_probe_observations (
    observation_id      VARCHAR,
    run_id              VARCHAR,
    test_id             VARCHAR,
    track               VARCHAR,
    timestamp           TIMESTAMP,
    platform            VARCHAR,
    local_track         VARCHAR,
    hardening_profile   VARCHAR,
    worker_name         VARCHAR,
    pod_name            VARCHAR,
    node_name           VARCHAR,
    workerd_version     VARCHAR,
    v8_version          VARCHAR,
    probe_result        JSON,
    host_trace          JSON,
    metadata            JSON
);

-- The canonical Workerwulf result stays inside probe_result. The surrounding
-- row carries local-only execution context needed for hardening comparisons.
--
-- Parquet partitioning should happen at export time, for example:
--
-- COPY (
--   SELECT * FROM wulf_local_probe_observations
-- )
-- TO 'out/wulf-local-observations'
-- (FORMAT PARQUET, PARTITION_BY (platform, local_track, hardening_profile));

-- Import collector output:
--
-- INSERT INTO wulf_local_probe_observations
-- SELECT
--   observation_id,
--   run_id,
--   test_id,
--   track,
--   CAST(timestamp AS TIMESTAMP),
--   platform,
--   local_track,
--   hardening_profile,
--   worker_name,
--   pod_name,
--   node_name,
--   workerd_version,
--   v8_version,
--   probe_result::JSON,
--   host_trace::JSON,
--   metadata::JSON
-- FROM read_json_auto('wulf-local/out/*/observation.jsonl');
