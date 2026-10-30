-- RuangKita V4 integrated staging migration.
-- Applied transactionally by migrator.go; BEGIN/COMMIT also support manual psql execution.
-- Existing 001 and 002 migrations must be the verified originals.
-- Media retention policy in current backend: ordinary media 24 hours;
-- voice notes and stickers 100 years (long-lived, not truly permanent).
-- The 24-hour DEFAULT applies only when INSERT omits expires_at.
-- The backend explicitly supplies expires_at for voice/sticker uploads.
BEGIN;

ALTER TABLE messages ADD COLUMN IF NOT EXISTS deleted_for_everyone BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE messages ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ;

CREATE TABLE IF NOT EXISTS hidden_messages (
  message_id BIGINT NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
  user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  PRIMARY KEY (message_id, user_id)
);
CREATE TABLE IF NOT EXISTS conversation_clears (
  user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  peer_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  cleared_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (user_id, peer_id)
);
CREATE TABLE IF NOT EXISTS message_reads (
  message_id BIGINT NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
  reader_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  read_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (message_id, reader_id)
);
CREATE INDEX IF NOT EXISTS message_reads_reader_idx ON message_reads(reader_id, read_at);
CREATE TABLE IF NOT EXISTS user_presence (
  user_id BIGINT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS contact_invites (
  token_hash CHAR(64) PRIMARY KEY,
  owner_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  used_by BIGINT REFERENCES users(id) ON DELETE SET NULL
);
CREATE INDEX IF NOT EXISTS contact_invites_owner_idx ON contact_invites(owner_id, expires_at);

CREATE TABLE IF NOT EXISTS media_files (
  id TEXT PRIMARY KEY,
  sender_id BIGINT NOT NULL REFERENCES users(id),
  receiver_id BIGINT NOT NULL REFERENCES users(id),
  original_name TEXT NOT NULL,
  mime_type TEXT NOT NULL,
  size_bytes BIGINT NOT NULL,
  view_once BOOLEAN NOT NULL DEFAULT FALSE,
  viewed_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at TIMESTAMPTZ NOT NULL DEFAULT NOW() + INTERVAL '24 hours'
);
ALTER TABLE media_files ADD COLUMN IF NOT EXISTS kind TEXT NOT NULL DEFAULT 'media';
ALTER TABLE media_files ADD COLUMN IF NOT EXISTS deleted_for_everyone BOOLEAN NOT NULL DEFAULT FALSE;
CREATE INDEX IF NOT EXISTS media_files_expires_idx ON media_files(expires_at);

CREATE TABLE IF NOT EXISTS sticker_library (
  id BIGSERIAL PRIMARY KEY,
  owner_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  media_id TEXT NOT NULL REFERENCES media_files(id) ON DELETE CASCADE,
  added_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (owner_id, media_id)
);
CREATE INDEX IF NOT EXISTS sticker_library_owner_idx ON sticker_library(owner_id);
CREATE TABLE IF NOT EXISTS hidden_media (
  media_id TEXT NOT NULL REFERENCES media_files(id) ON DELETE CASCADE,
  user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  PRIMARY KEY (media_id, user_id)
);

COMMIT;
