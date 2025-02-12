begin;

drop table if exists sessions;
drop index idx_sessions_user ON sessions;
drop index idx_sessions_device ON sessions;

commit;