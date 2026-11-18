-- Opt-in comparison with the previous scheduled report.
--
-- compare_previous = 0 (default): the scheduled email has no "changes since the
-- previous report" section, and nothing is stored or read for comparison.
-- compare_previous = 1: after each SUCCESSFUL send, a small numeric snapshot is
-- kept (counts and stable risk codes only: no names, hostnames, IPs, emails or
-- tokens) so the next run can say what changed.
--
-- Additive only: existing schedules keep every column and all send_history.
ALTER TABLE schedules ADD COLUMN compare_previous INTEGER NOT NULL DEFAULT 0;

CREATE TABLE IF NOT EXISTS exec_report_snapshots (
  id            TEXT PRIMARY KEY,
  schedule_id   TEXT NOT NULL,
  product       TEXT NOT NULL,
  generated_at  TEXT NOT NULL,
  days          INTEGER NOT NULL,
  metrics_json  TEXT NOT NULL,   -- { metricKey: number }
  risks_json    TEXT NOT NULL    -- [ stable risk codes ]
);

CREATE INDEX IF NOT EXISTS idx_exec_snapshots_schedule
  ON exec_report_snapshots (schedule_id, generated_at DESC);
