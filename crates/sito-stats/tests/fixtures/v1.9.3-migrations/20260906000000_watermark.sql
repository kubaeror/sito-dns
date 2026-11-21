-- Migration: Add stats_watermark table to track aggregation progress
CREATE TABLE IF NOT EXISTS stats_watermark (
    key TEXT PRIMARY KEY,
    last_id INTEGER NOT NULL DEFAULT 0,
    last_ts INTEGER NOT NULL DEFAULT 0
);
