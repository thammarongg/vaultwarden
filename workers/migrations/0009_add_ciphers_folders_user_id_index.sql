-- Add index to speed up common per-user cipher queries.
-- This reduces full table scans for:
-- - /api/sync (WHERE c.user_id = ?)
-- - /api/ciphers (WHERE c.user_id = ? AND deleted_at IS NULL ...)
-- - attachments usage queries that JOIN ciphers and filter by user_id
CREATE INDEX IF NOT EXISTS idx_ciphers_user_id ON ciphers(user_id);

-- Speed up per-user folder queries and FK cascades (e.g. /api/sync, folder listing).
CREATE INDEX IF NOT EXISTS idx_folders_user_id ON folders(user_id);

