-- Migration: Add password_iterations column to users table
-- This column stores the per-user server-side PBKDF2 iteration count used for
-- hashing/storing the master password hash.
--
-- Existing databases (pre-migration) used 100_000 iterations for all users.
-- We set the default accordingly so existing rows remain verifiable, and the
-- application will upgrade users to the configured minimum during login.
--
-- Note: This migration is applied via GitHub Actions which handles
-- the "duplicate column" error gracefully for existing databases.

ALTER TABLE users ADD COLUMN password_iterations INTEGER NOT NULL DEFAULT 100000;


