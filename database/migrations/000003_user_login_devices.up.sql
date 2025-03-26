begin;
CREATE TABLE IF NOT EXISTS user_login_devices (
    id SERIAL PRIMARY KEY,
    user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_identity UUID NOT NULL,
    ip_address INET NOT NULL,
    user_agent TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    last_login_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX idx_device_identity ON user_login_devices(device_identity);

commit;