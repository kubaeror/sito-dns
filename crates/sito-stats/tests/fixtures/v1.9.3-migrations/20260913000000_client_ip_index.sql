-- Migration: index query_log by client_ip for per-client stats windows.
--
-- get_client_stats() groups/filters by client_ip for a ts window, but the
-- initial schema only indexed (client_name, ts). This composite index lets
-- SQLite seek the window per client instead of scanning the table.
CREATE INDEX IF NOT EXISTS idx_ql_client_ip_ts ON query_log(client_ip, ts);
