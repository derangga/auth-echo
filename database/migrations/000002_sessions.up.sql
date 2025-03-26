begin;
CREATE TABLE IF NOT EXISTS user_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    refresh_token VARCHAR(255) NOT NULL UNIQUE,
    token_family UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ DEFAULT NULL
);

CREATE INDEX idx_user_sessions_user ON user_sessions(user_id) WHERE revoked_at IS NULL;
CREATE INDEX idx_user_sessions_expiry ON user_sessions(expires_at) WHERE revoked_at IS NULL;
CREATE INDEX idx_refresh_token_expiry ON user_sessions(refresh_token) WHERE revoked_at IS NULL;
CREATE UNIQUE INDEX idx_active_token_family ON user_sessions(user_id, token_family) WHERE revoked_at IS NULL;
commit;