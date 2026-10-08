-- Sentinel Evidence SQLite Schema

CREATE TABLE IF NOT EXISTS sources (
    source_id TEXT PRIMARY KEY,
    content_hash TEXT NOT NULL UNIQUE,
    declared_host TEXT,
    collection_metadata TEXT,
    export_metadata TEXT,
    byte_size INTEGER NOT NULL,
    acquisition_time_if_known TEXT,
    exporter_version TEXT,
    original_source_mapping TEXT
);

CREATE TABLE IF NOT EXISTS events (
    event_id TEXT PRIMARY KEY,
    source_id TEXT NOT NULL,
    source_locator TEXT NOT NULL,
    original_timestamp_text TEXT,
    normalized_timestamp TEXT,
    timestamp_status TEXT,
    host TEXT,
    provider TEXT,
    channel TEXT,
    original_event_id TEXT,
    event_record_id INTEGER,
    process_guid TEXT,
    parent_process_guid TEXT,
    raw_fields TEXT NOT NULL,
    parse_status TEXT,
    FOREIGN KEY(source_id) REFERENCES sources(source_id)
);

CREATE TABLE IF NOT EXISTS runs (
    run_id TEXT PRIMARY KEY,
    source_hashes TEXT,
    parser_version TEXT,
    detector_version TEXT,
    rule_version TEXT,
    policy_version TEXT,
    model_digest TEXT,
    prompt_digest TEXT,
    parameters TEXT,
    limits TEXT,
    software_revision TEXT,
    timestamps TEXT,
    output_hashes TEXT
);

CREATE INDEX IF NOT EXISTS idx_events_source ON events(source_id);
CREATE INDEX IF NOT EXISTS idx_events_process_guid ON events(process_guid);
CREATE INDEX IF NOT EXISTS idx_events_parent_process_guid ON events(parent_process_guid);
