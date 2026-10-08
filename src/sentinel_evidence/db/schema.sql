-- Sentinel Evidence SQLite Schema

CREATE TABLE IF NOT EXISTS sources (
    file_hash TEXT PRIMARY KEY,
    file_path TEXT NOT NULL,
    line_number INTEGER NOT NULL,
    raw_hash TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS events (
    event_id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    host TEXT NOT NULL,
    process_guid TEXT,
    pid INTEGER,
    image TEXT,
    command_line TEXT,
    parent_process_guid TEXT,
    parent_image TEXT,
    user TEXT,
    file_hash TEXT NOT NULL,
    raw_fields TEXT NOT NULL,
    FOREIGN KEY(file_hash) REFERENCES sources(file_hash)
);

CREATE INDEX IF NOT EXISTS idx_events_host ON events(host);
CREATE INDEX IF NOT EXISTS idx_events_process_guid ON events(process_guid);
CREATE INDEX IF NOT EXISTS idx_events_parent_process_guid ON events(parent_process_guid);
