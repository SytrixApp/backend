-- Enforce AES-GCM nonce uniqueness per user at the database level.
-- Nonce reuse with the same AES-256-GCM key breaks confidentiality completely
-- (an attacker can XOR two ciphertexts to recover the plaintext XOR).
-- The application already checks for reuse, but a DB-level constraint is the
-- only way to prevent race conditions between concurrent requests.
--
-- Note: this index covers non-deleted items only. Soft-deleted items still occupy
-- a nonce slot — this is intentional, since allowing nonce reuse after deletion
-- would reintroduce the attack vector.
CREATE UNIQUE INDEX IF NOT EXISTS "vault_items_user_nonce_unique"
  ON "vault_items" ("user_id", "nonce");
