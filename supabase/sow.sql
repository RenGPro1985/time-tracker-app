-- Statements of Work issued from the portal (2026-11-22). Safe to re-run.
create sequence if not exists public.sow_seq;
create table if not exists public.sow_issued (
  id             uuid primary key default gen_random_uuid(),
  seq            bigint not null default nextval('public.sow_seq'),
  sow_no         text unique,
  staff_id       uuid not null references public.staff(id) on delete cascade,
  doc_id         uuid references public.portal_docs(id) on delete set null,
  snapshot       jsonb not null,           -- rate/client/shift/total at issue time (to detect "out of date")
  effective_date date,
  issued_at      timestamptz not null default now(),
  issued_by      uuid
);
create index if not exists sow_issued_staff_idx on public.sow_issued (staff_id, issued_at desc);
alter table public.sow_issued enable row level security;  -- server (service role) only; no client policies
