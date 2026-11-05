# D1 migrations

sql/schema.sql is the baseline (vaultwarden SQLite schema + Workers-only tables/views).
Add incremental changes here as NNNN_description.sql, applied with
`wrangler d1 migrations apply vaultwarden-cf --remote`.
