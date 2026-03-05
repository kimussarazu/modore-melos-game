CREATE TABLE IF NOT EXISTS audit_logs (
  id TEXT PRIMARY KEY,
  created_at_ms INTEGER NOT NULL,
  action TEXT NOT NULL,
  room_tag TEXT NOT NULL,
  ip TEXT NOT NULL,
  ip_masked TEXT NOT NULL,
  ip_hash TEXT NOT NULL,
  user_agent TEXT NOT NULL,
  uid TEXT NOT NULL,
  pubkey TEXT NOT NULL,
  event_id TEXT NOT NULL,
  target_event_id TEXT NOT NULL,
  name TEXT NOT NULL,
  text TEXT NOT NULL,
  is_deleted INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at
ON audit_logs (created_at_ms DESC);

CREATE INDEX IF NOT EXISTS idx_audit_logs_event_id
ON audit_logs (event_id);

CREATE INDEX IF NOT EXISTS idx_audit_logs_target_event_id
ON audit_logs (target_event_id);

CREATE TABLE IF NOT EXISTS melos_visitors (
  room_tag TEXT NOT NULL,
  ip_hash TEXT NOT NULL,
  melos_number INTEGER NOT NULL,
  assigned_at_ms INTEGER NOT NULL,
  PRIMARY KEY (room_tag, ip_hash)
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_melos_visitors_room_number
ON melos_visitors (room_tag, melos_number);
