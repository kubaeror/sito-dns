-- Migration: Initial query_log and stats_hourly schema per section 14.1
CREATE TABLE IF NOT EXISTS query_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts INTEGER NOT NULL,                 -- unix millis
    client_ip TEXT NOT NULL,             -- or masked
    client_name TEXT,
    qname TEXT NOT NULL,
    qtype INTEGER NOT NULL,
    rcode INTEGER,
    verdict TEXT NOT NULL,               -- allowed|blocked|whitelisted|rewritten|stale
    rule TEXT,                           -- matched rule
    list_source TEXT,
    upstream TEXT,
    elapsed_us INTEGER,
    dnssec TEXT,                         -- secure|insecure|bogus
    proto TEXT                           -- udp|tcp|dot|doh|doq|doh3
);

CREATE INDEX IF NOT EXISTS idx_ql_ts ON query_log(ts);
CREATE INDEX IF NOT EXISTS idx_ql_qname_ts ON query_log(qname, ts);
CREATE INDEX IF NOT EXISTS idx_ql_client_ts ON query_log(client_name, ts);

CREATE TABLE IF NOT EXISTS stats_hourly (
    hour INTEGER PRIMARY KEY,
    queries INTEGER NOT NULL DEFAULT 0,
    blocked INTEGER NOT NULL DEFAULT 0,
    cached INTEGER NOT NULL DEFAULT 0,
    top_domains TEXT,                    -- JSON: [[qname, count], ...] top 100
    top_clients TEXT
);
