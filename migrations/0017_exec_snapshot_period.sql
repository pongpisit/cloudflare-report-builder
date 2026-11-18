-- The comparison names the period the previous report covered (e.g. "2026-11-16") instead of the day it was sent,
-- which was misleading when two reports were sent on the same day for different days.
-- Additive: existing snapshots keep every column; the period is simply unknown for them.
ALTER TABLE exec_report_snapshots ADD COLUMN period TEXT;
