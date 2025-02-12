begin;

drop table if exists users;
drop type user_role;
drop index idx_users_username ON users;

commit;