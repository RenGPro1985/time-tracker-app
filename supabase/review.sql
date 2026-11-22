-- Annual Service Review (2026-11-22). Safe to re-run.
-- Server-only tables (RLS on, no client policies): every read/write goes through
-- the Render server (/api/review/*), which enforces who can see what — peer
-- feedback stays anonymous to the person reviewed.

create table if not exists public.review_cycles (
  id            uuid primary key default gen_random_uuid(),
  year          int not null unique,
  self_open     date not null,            -- self + peer window opens
  self_due      date not null,            -- self + peer window closes (inclusive)
  admin_due     date not null,            -- admin scoring + 1-on-1s
  ack_due       date not null,            -- staff acknowledge / ask for reconsideration
  fee_effective date not null,            -- new contract fees take effect (first January cutoff)
  tenure_asof   date not null,            -- 6-month eligibility measured on this date
  fx            numeric not null default 60,
  bands         jsonb not null,           -- [{min,name,pct}]
  weights       jsonb not null,           -- {admin,peer,self,rel}
  created_at    timestamptz not null default now(),
  created_by    uuid
);

create table if not exists public.review_participants (
  cycle_id        uuid not null references public.review_cycles(id) on delete cascade,
  staff_id        uuid not null references public.staff(id) on delete cascade,
  review_type     text not null default 'annual' check (review_type in ('annual','dev')),
  peers           uuid[] not null default '{}',   -- who gives this person peer feedback
  admin_ratings   jsonb,
  admin_summary   text,
  one_on_one      boolean not null default false,
  reliability     numeric,                        -- frozen when the admin saves the score
  override_pct    numeric,
  override_reason text,
  final_score     numeric,
  band            text,
  increase_pct    numeric,
  current_rate    numeric,
  new_rate        numeric,
  finalized_at    timestamptz,
  released_at     timestamptz,
  ack_status      text check (ack_status in ('acknowledged','reconsideration')),
  ack_note        text,
  ack_at          timestamptz,
  admin_reply     text,
  applied_at      timestamptz,
  updated_at      timestamptz not null default now(),
  primary key (cycle_id, staff_id)
);

create table if not exists public.review_submissions (
  id           uuid primary key default gen_random_uuid(),
  cycle_id     uuid not null references public.review_cycles(id) on delete cascade,
  kind         text not null check (kind in ('self','peer')),
  reviewer_id  uuid not null references public.staff(id) on delete cascade,
  reviewee_id  uuid not null references public.staff(id) on delete cascade,
  ratings      jsonb not null default '{}',
  answers      jsonb not null default '{}',
  declined     boolean not null default false,  -- "haven't worked with them enough"
  status       text not null default 'draft' check (status in ('draft','submitted')),
  submitted_at timestamptz,
  updated_at   timestamptz not null default now(),
  unique (cycle_id, kind, reviewer_id, reviewee_id)
);
create index if not exists review_submissions_reviewee_idx on public.review_submissions (cycle_id, reviewee_id);

alter table public.review_cycles       enable row level security;
alter table public.review_participants enable row level security;
alter table public.review_submissions  enable row level security;
