-- Migration: Add Argon2 KDF fields to users table
-- These columns store the client-side Argon2 KDF parameters:
-- - kdf_memory: Memory parameter in MB (15-1024)
-- - kdf_parallelism: Parallelism parameter (1-16)
--
-- These are client-side encryption settings only.
-- The server does not execute Argon2 - it only stores these values
-- and returns them to clients during prelogin.
--
-- Note: This migration is applied via GitHub Actions which handles
-- the "duplicate column" error gracefully for existing databases.

ALTER TABLE users ADD COLUMN kdf_memory INTEGER;

ALTER TABLE users ADD COLUMN kdf_parallelism INTEGER;

