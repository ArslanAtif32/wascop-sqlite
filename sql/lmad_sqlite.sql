-- SQLite schema for WAScope. Safe to run repeatedly.
CREATE TABLE IF NOT EXISTS request_record (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    flow_id TEXT DEFAULT '',
    host TEXT DEFAULT '',
    port TEXT DEFAULT '',
    hash TEXT DEFAULT '',
    method TEXT DEFAULT '',
    referer TEXT,
    url TEXT,
    content_type TEXT DEFAULT '',
    response TEXT,
    response_exists_sensitive INTEGER DEFAULT 0,
    response_sensitive TEXT,
    path TEXT,
    path_exist_sensitive INTEGER DEFAULT 0,
    path_sensitive TEXT,
    get_params TEXT,
    get_exist_sensitive INTEGER DEFAULT 0,
    get_sensitive TEXT,
    post_params TEXT,
    post_exist_sensitive INTEGER DEFAULT 0,
    post_sensitive TEXT,
    create_time INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS request_record_second (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host TEXT DEFAULT '',
    hash TEXT DEFAULT '',
    method TEXT DEFAULT '',
    content_type TEXT DEFAULT '',
    referer TEXT,
    origin_url TEXT,
    url TEXT,
    gen_params TEXT,
    response_hash TEXT DEFAULT '',
    response TEXT,
    response_exists_sensitive INTEGER DEFAULT 0,
    response_sensitive TEXT,
    create_time INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_request_record_hash ON request_record(hash);
CREATE INDEX IF NOT EXISTS idx_request_record_second_hash ON request_record_second(hash);
CREATE INDEX IF NOT EXISTS idx_request_record_second_host ON request_record_second(host);
