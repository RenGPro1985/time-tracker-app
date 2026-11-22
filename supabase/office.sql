-- Office Necessities: supply requests + broken-item reports (2026-11-23). Safe to re-run.
-- Server-only (RLS on, no client policies); all access goes through /api/office/*.
create table if not exists public.office_requests (
  id            uuid primary key default gen_random_uuid(),
  kind          text not null check (kind in ('supply','repair')),
  item          text not null,               -- key, e.g. 'dish_liquid' or 'other:<text>'
  label         text not null,               -- what people see, e.g. 'Dishwashing liquid'
  location      text,                        -- repairs: station / room
  urgency       text not null,               -- supply: low|out · repair: cant|fix|minor
  details       text,                        -- repairs: what's wrong
  notes         jsonb not null default '[]', -- supply: every request merged into this row [{by,urgency,qty,note,at}]
  requester_id  uuid not null references public.staff(id) on delete cascade,
  plus_ids      uuid[] not null default '{}',-- "me too"
  photo_path    text,
  status        text not null default 'requested' check (status in ('requested','ordered','fixing','done','replaced','declined','cancelled')),
  eta           date,
  cost          numeric,
  close_note    text,
  expense_id    uuid,
  created_at    timestamptz not null default now(),
  updated_at    timestamptz not null default now(),
  closed_at     timestamptz,
  closed_by     uuid
);
create index if not exists office_requests_open_idx on public.office_requests (kind, item, status);
alter table public.office_requests enable row level security;
