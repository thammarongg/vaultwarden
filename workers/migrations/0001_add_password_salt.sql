-- Migration: Add password_salt column to users table
-- This column stores the salt for server-side PBKDF2 hashing
-- NULL for legacy users pending migration
--
-- Note: This migration is applied via GitHub Actions which handles
-- the "duplicate column" error gracefully for existing databases.

ALTER TABLE users ADD COLUMN password_salt TEXT;

