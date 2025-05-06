begin;
CREATE TABLE IF NOT EXISTS fcm_device (
    id SERIAL PRIMARY KEY,
    user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_identity UUID NOT NULL,
    fcm_token TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX idx_fcm_device_userid ON fcm_device(user_id);
CREATE INDEX idx_fcm_device_userid_device_id on fcm_device(user_id, device_identity);
commit;