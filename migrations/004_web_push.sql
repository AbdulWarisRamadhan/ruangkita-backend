BEGIN;

CREATE TABLE IF NOT EXISTS push_subscriptions (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    endpoint TEXT NOT NULL UNIQUE,
    p256dh TEXT NOT NULL,
    auth_secret TEXT NOT NULL,
    user_agent TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_success_at TIMESTAMPTZ,
    CHECK (length(endpoint) BETWEEN 10 AND 4096),
    CHECK (length(p256dh) BETWEEN 10 AND 1024),
    CHECK (length(auth_secret) BETWEEN 10 AND 1024)
);
CREATE INDEX IF NOT EXISTS idx_push_subscriptions_user_id ON push_subscriptions(user_id);

CREATE TABLE IF NOT EXISTS push_outbox (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    recipient_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    event_type TEXT NOT NULL,
    event_key TEXT NOT NULL,
    sender_id BIGINT REFERENCES users(id) ON DELETE SET NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    attempts INTEGER NOT NULL DEFAULT 0,
    available_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    lease_until TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ,
    last_error TEXT,
    UNIQUE (recipient_id, event_type, event_key),
    CHECK (event_type IN ('message', 'media', 'sticker')),
    CHECK (status IN ('pending', 'processing', 'sent', 'failed')),
    CHECK (attempts >= 0)
);
CREATE INDEX IF NOT EXISTS idx_push_outbox_claim ON push_outbox(available_at, id)
    WHERE status IN ('pending', 'processing');
CREATE INDEX IF NOT EXISTS idx_push_outbox_recipient ON push_outbox(recipient_id, created_at DESC);

-- Track delivery per browser so retry never resends to already accepted endpoints.
CREATE TABLE IF NOT EXISTS push_deliveries (
 outbox_id BIGINT NOT NULL REFERENCES push_outbox(id) ON DELETE CASCADE,
 subscription_id BIGINT NOT NULL REFERENCES push_subscriptions(id) ON DELETE CASCADE,
 status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','sent','failed')),
 last_error TEXT,
 PRIMARY KEY (outbox_id, subscription_id)
);
CREATE INDEX IF NOT EXISTS idx_push_deliveries_pending ON push_deliveries(outbox_id) WHERE status='pending';

-- AFTER INSERT triggers ensure notifications are queued atomically with the message/media.
-- IDs in messages are VARCHAR, unlike the BIGINT IDs in users.
CREATE OR REPLACE FUNCTION enqueue_text_push() RETURNS TRIGGER AS $$
BEGIN
  IF NEW.receiver_id ~ '^[0-9]{1,18}$' AND NEW.sender_id ~ '^[0-9]{1,18}$' THEN
    INSERT INTO push_outbox(recipient_id,event_type,event_key,sender_id)
    SELECT recipient.id, 'message', NEW.id::TEXT, sender.id
    FROM users recipient JOIN users sender ON sender.id=NEW.sender_id::BIGINT
    WHERE recipient.id=NEW.receiver_id::BIGINT AND recipient.id<>sender.id
    ON CONFLICT (recipient_id,event_type,event_key) DO NOTHING;
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;
DROP TRIGGER IF EXISTS trg_enqueue_text_push ON messages;
CREATE TRIGGER trg_enqueue_text_push AFTER INSERT ON messages
FOR EACH ROW EXECUTE FUNCTION enqueue_text_push();

CREATE OR REPLACE FUNCTION enqueue_media_push() RETURNS TRIGGER AS $$
BEGIN
  IF NEW.sender_id <> NEW.receiver_id THEN
    INSERT INTO push_outbox(recipient_id,event_type,event_key,sender_id)
    VALUES (NEW.receiver_id, CASE WHEN NEW.kind='sticker' THEN 'sticker' ELSE 'media' END, NEW.id, NEW.sender_id)
    ON CONFLICT (recipient_id,event_type,event_key) DO NOTHING;
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;
DROP TRIGGER IF EXISTS trg_enqueue_media_push ON media_files;
CREATE TRIGGER trg_enqueue_media_push AFTER INSERT ON media_files
FOR EACH ROW EXECUTE FUNCTION enqueue_media_push();
COMMIT;
