BEGIN;

-- Menyimpan referensi ke pesan teks yang dibalas.
-- NULL berarti pesan biasa, bukan balasan.
ALTER TABLE messages
ADD COLUMN IF NOT EXISTS reply_to_message_id BIGINT
REFERENCES messages(id)
ON DELETE SET NULL;

-- Mempercepat pencarian pesan yang menjadi referensi balasan.
CREATE INDEX IF NOT EXISTS idx_messages_reply_to
ON messages(reply_to_message_id)
WHERE reply_to_message_id IS NOT NULL;

COMMIT;
