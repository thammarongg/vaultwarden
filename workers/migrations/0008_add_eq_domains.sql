-- Migration: Add equivalent domains (eq_domains) functionality
--
-- Part 1: User settings fields for URI matching
-- - equivalent_domains: JSON string of Vec<Vec<String>> (custom groups)
-- - excluded_globals: JSON string of Vec<i32> (excluded global group IDs)
--
-- We keep defaults as "[]", and allow applying this migration multiple times
-- (duplicate column errors are handled gracefully by CI tooling).
--
-- Part 2: Global equivalent domains table
-- Stores the upstream "global domains" dataset (vaultwarden/Bitwarden compatible),
-- but kept OUT of the Worker bundle for size/perf reasons.
--
-- Data is seeded separately (see scripts) and may be refreshed over time.
-- Columns:
-- - type: the global group id (matches vaultwarden's `GlobalDomain.type`)
-- - sort_order: preserve upstream file order for stable client UX
-- - domains_json: JSON string of Vec<String> (domain list)

ALTER TABLE users ADD COLUMN equivalent_domains TEXT NOT NULL DEFAULT '[]';
ALTER TABLE users ADD COLUMN excluded_globals TEXT NOT NULL DEFAULT '[]';

CREATE TABLE IF NOT EXISTS global_equivalent_domains (
    type INTEGER PRIMARY KEY NOT NULL,
    sort_order INTEGER NOT NULL,
    domains_json TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_global_equivalent_domains_sort_order
    ON global_equivalent_domains(sort_order);

