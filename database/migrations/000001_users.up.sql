begin;

CREATE TYPE user_role AS ENUM (
  'admin',
  'user'
);

CREATE TABLE IF NOT EXISTS users(
  id serial PRIMARY KEY,
  username varchar(15) unique not null,
  email varchar(100) unique not null,
  "name" varchar(100),
  "password" varchar(100),
  role user_role,
  created_at timestamp,
  updated_at timestamp,
  deleted_at timestamp
);

CREATE INDEX ON "users" (username);

commit;