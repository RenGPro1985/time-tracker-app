-- Unpaid Client Holiday (uch) — 2026-11-24
-- Safe to re-run. Only touches a CHECK constraint on requests.type / leave_days.type
-- if one exists; if your tables have no such constraint, this does nothing.
-- New constraints are added NOT VALID so existing rows are never re-checked.
do $$
declare c record;
begin
  -- requests.type
  for c in
    select con.conname from pg_constraint con
    join pg_class t on t.oid = con.conrelid
    join pg_namespace n on n.oid = t.relnamespace
    where n.nspname = 'public' and t.relname = 'requests' and con.contype = 'c'
      and pg_get_constraintdef(con.oid) ilike '%type%'
      and pg_get_constraintdef(con.oid) not ilike '%uch%'
  loop
    execute format('alter table public.requests drop constraint %I', c.conname);
    alter table public.requests add constraint requests_type_check check (type in (
      'pto','pch','uch','planned_absence','sick_leave','half_day',
      'reimbursement','salary_advance','cash_advance')) not valid;
  end loop;

  -- leave_days.type
  for c in
    select con.conname from pg_constraint con
    join pg_class t on t.oid = con.conrelid
    join pg_namespace n on n.oid = t.relnamespace
    where n.nspname = 'public' and t.relname = 'leave_days' and con.contype = 'c'
      and pg_get_constraintdef(con.oid) ilike '%type%'
      and pg_get_constraintdef(con.oid) not ilike '%uch%'
  loop
    execute format('alter table public.leave_days drop constraint %I', c.conname);
    alter table public.leave_days add constraint leave_days_type_check check (type in (
      'pto','pch','uch','planned_absence','sick_leave','half_day')) not valid;
  end loop;
end $$;
