begin;

CREATE TYPE user_role AS ENUM (
  'admin',
  'user'
);

CREATE TABLE IF NOT EXISTS users(
  id SERIAL PRIMARY KEY,
  username VARCHAR(15) UNIQUE NOT NULL,
  email VARCHAR(100) UNIQUE NOT NULL,
  "name" VARCHAR(100),
  "password" VARCHAR(100),
  role user_role,
  created_at TIMESTAMPTZ default NOW(),
  updated_at TIMESTAMPTZ,
  deleted_at TIMESTAMPTZ
);

CREATE INDEX idx_users_username ON users(username);

commit;