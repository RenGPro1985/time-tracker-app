-- ============================================================
-- SMB TIME - Supabase database schema
-- Paste this whole file into Supabase > SQL Editor > New query > Run
-- Safe to re-run.
-- ============================================================

create extension if not exists "pgcrypto";

-- ---------- CLIENTS ----------
create table if not exists clients (
  id           uuid primary key default gen_random_uuid(),
  name         text not null unique,
  timezone     text not null default 'America/New_York',
  shift_start  time not null default '21:00',   -- PH time
  shift_end    time not null default '06:00',   -- PH time
  workdays     text not null default 'Mon-Fri',
  active       boolean not null default true,
  created_at   timestamptz not null default now()
);

-- ---------- STAFF (one row per login; id = Supabase auth user id) ----------
create table if not exists staff (
  id            uuid primary key references auth.users(id) on delete cascade,
  username      text not null unique,
  full_name     text not null,
  email         text not null unique,
  client_id     uuid references clients(id) on delete set null,
  role          text not null default 'staff' check (role in ('staff','admin')),
  active        boolean not null default true,
  hire_date     date,
  birth_date    date,
  monthly_rate    numeric(12,2) not null default 0,
  usd_hourly_rate  numeric(12,2) not null default 0,
  created_at      timestamptz not null default now()
);

-- safe to re-run on an existing database that predates these columns
alter table staff add column if not exists hire_date date;
alter table staff add column if not exists birth_date date;
alter table staff add column if not exists monthly_rate numeric(12,2) not null default 0;
alter table staff add column if not exists usd_hourly_rate numeric(12,2) not null default 0;

-- ---------- SHIFTS (LOGIN -> LOGOUT) ----------
create table if not exists shifts (
  id         uuid primary key default gen_random_uuid(),
  staff_id   uuid not null references staff(id) on delete cascade,
  login_at   timestamptz not null default now(),
  logout_at  timestamptz,
  note       text,
  created_at timestamptz not null default now()
);
create index if not exists shifts_staff_idx on shifts (staff_id, login_at desc);

-- ---------- ENTRIES (activity blocks inside a shift) ----------
create table if not exists entries (
  id         uuid primary key default gen_random_uuid(),
  shift_id   uuid not null references shifts(id) on delete cascade,
  staff_id   uuid not null references staff(id) on delete cascade,
  activity   text not null check (activity in
              ('Working','15min Break','30min Break','60min Break',
               'Personal Break','Bio Break','Meeting/Coaching')),
  started_at timestamptz not null default now(),
  ended_at   timestamptz,
  created_at timestamptz not null default now()
);
create index if not exists entries_staff_idx on entries (staff_id, started_at desc);
create index if not exists entries_shift_idx on entries (shift_id);

-- ---------- CORRECTION REQUESTS ----------
create table if not exists corrections (
  id           uuid primary key default gen_random_uuid(),
  staff_id     uuid not null references staff(id) on delete cascade,
  entry_id     uuid references entries(id) on delete set null,
  shift_id     uuid references shifts(id) on delete set null,
  target_date  date,
  message      text not null,
  status       text not null default 'pending' check (status in ('pending','approved','rejected')),
  admin_note   text,
  reviewed_by  uuid references staff(id),
  reviewed_at  timestamptz,
  created_at   timestamptz not null default now()
);

-- ---------- REQUESTS (PTO / salary advance / cash advance) ----------
create table if not exists requests (
  id           uuid primary key default gen_random_uuid(),
  staff_id     uuid not null references staff(id) on delete cascade,
  type         text not null check (type in ('pto','salary_advance','cash_advance')),
  start_date   date,
  end_date     date,
  amount       numeric(12,2),
  cutoffs      integer,
  reason       text,
  status       text not null default 'pending' check (status in ('pending','approved','rejected','paid')),
  reviewed_by  uuid references staff(id),
  reviewed_at  timestamptz,
  created_at   timestamptz not null default now()
);
create index if not exists requests_staff_idx on requests (staff_id, created_at desc);

-- safe to re-run on an existing database that predates these columns
alter table requests add column if not exists cutoffs integer;
alter table requests add column if not exists reason text;

-- ---------- ADVANCE DEDUCTIONS ----------
-- Auto-generated repayment schedule for approved salary/cash advances.
-- Staff pick how many cutoffs (pay periods) to repay over when they request
-- the advance. The first deduction always falls on the earliest payout
-- period after approval (the 15th or the last day of the month, whichever
-- comes first); each following deduction lands on the next payout after that.
create table if not exists advance_deductions (
  id           uuid primary key default gen_random_uuid(),
  request_id   uuid not null references requests(id) on delete cascade,
  staff_id     uuid not null references staff(id) on delete cascade,
  cutoff_date  date not null,
  amount       numeric(12,2) not null,
  status       text not null default 'scheduled' check (status in ('scheduled','deducted','waived')),
  created_at   timestamptz not null default now()
);
create index if not exists advance_deductions_staff_idx   on advance_deductions (staff_id, cutoff_date);
create index if not exists advance_deductions_request_idx on advance_deductions (request_id);

-- ---------- SETTINGS (break allowances etc.) ----------
create table if not exists settings (
  key   text primary key,
  value jsonb not null
);

insert into settings (key, value) values
 ('break_allowance_minutes', '{
    "15min Break": 15,
    "30min Break": 30,
    "60min Break": 60,
    "Personal Break": 30,
    "Bio Break": 0,
    "Meeting/Coaching": 0,
    "Working": 0
  }'::jsonb)
on conflict (key) do nothing;

-- 0 = unlimited / not tracked for overage.
-- Rule used by the app: an activity is billable EXCEPT "60min Break".
-- Minutes spent on 15min / 30min / Personal Break BEYOND the allowance
-- (per shift, totalled) are also counted NON-billable.

-- ============================================================
-- SECURITY
-- ============================================================
create or replace function is_admin()
returns boolean language sql security definer set search_path = public as $$
  select exists (select 1 from staff where id = auth.uid() and role = 'admin' and active);
$$;

alter table clients     enable row level security;
alter table staff       enable row level security;
alter table shifts      enable row level security;
alter table entries     enable row level security;
alter table corrections enable row level security;
alter table settings    enable row level security;
alter table requests            enable row level security;
alter table advance_deductions  enable row level security;

drop policy if exists p_clients_read  on clients;
drop policy if exists p_clients_admin on clients;
create policy p_clients_read  on clients for select to authenticated using (true);
create policy p_clients_admin on clients for all    to authenticated using (is_admin()) with check (is_admin());

drop policy if exists p_staff_self   on staff;
drop policy if exists p_staff_admin  on staff;
create policy p_staff_self  on staff for select to authenticated using (id = auth.uid() or is_admin());
create policy p_staff_admin on staff for all    to authenticated using (is_admin()) with check (is_admin());

drop policy if exists p_shifts_own   on shifts;
drop policy if exists p_shifts_admin on shifts;
create policy p_shifts_own   on shifts for all to authenticated
  using (staff_id = auth.uid()) with check (staff_id = auth.uid());
create policy p_shifts_admin on shifts for all to authenticated
  using (is_admin()) with check (is_admin());

drop policy if exists p_entries_own   on entries;
drop policy if exists p_entries_admin on entries;
create policy p_entries_own   on entries for all to authenticated
  using (staff_id = auth.uid()) with check (staff_id = auth.uid());
create policy p_entries_admin on entries for all to authenticated
  using (is_admin()) with check (is_admin());

drop policy if exists p_corr_own   on corrections;
drop policy if exists p_corr_admin on corrections;
create policy p_corr_own   on corrections for all to authenticated
  using (staff_id = auth.uid()) with check (staff_id = auth.uid());
create policy p_corr_admin on corrections for all to authenticated
  using (is_admin()) with check (is_admin());

drop policy if exists p_settings_read  on settings;
drop policy if exists p_settings_admin on settings;
create policy p_settings_read  on settings for select to authenticated using (true);
create policy p_settings_admin on settings for all    to authenticated using (is_admin()) with check (is_admin());

drop policy if exists p_requests_own_rw    on requests;
drop policy if exists p_requests_own_read  on requests;
drop policy if exists p_requests_admin     on requests;
-- staff can create and read their own requests, but only admins can change status
create policy p_requests_own_read on requests for select to authenticated
  using (staff_id = auth.uid() or is_admin());
create policy p_requests_own_insert on requests for insert to authenticated
  with check (staff_id = auth.uid());
create policy p_requests_admin on requests for update to authenticated
  using (is_admin()) with check (is_admin());
create policy p_requests_admin_del on requests for delete to authenticated
  using (is_admin());

drop policy if exists p_advdeduct_own_read on advance_deductions;
drop policy if exists p_advdeduct_admin    on advance_deductions;
create policy p_advdeduct_own_read on advance_deductions for select to authenticated
  using (staff_id = auth.uid() or is_admin());
create policy p_advdeduct_admin on advance_deductions for all to authenticated
  using (is_admin()) with check (is_admin());

-- ---------- TIMESHEET ADJUSTMENTS (admin-entered daily overrides) ----------
-- Lets an admin type a total-hours override for one staff member on one day
-- in the Timesheets "Daily hours grid" without touching that person's real
-- shift/entry records. The grid falls back to hours computed from actual
-- entries whenever no override row exists for that staff+date.
create table if not exists timesheet_adjustments (
  id         uuid primary key default gen_random_uuid(),
  staff_id   uuid not null references staff(id) on delete cascade,
  work_date  date not null,
  hours      numeric(6,2) not null check (hours >= 0),
  edited_by  uuid references staff(id),
  edited_at  timestamptz not null default now(),
  unique (staff_id, work_date)
);
create index if not exists timesheet_adj_staff_idx on timesheet_adjustments (staff_id, work_date);

alter table timesheet_adjustments enable row level security;
drop policy if exists p_tsadj_admin on timesheet_adjustments;
drop policy if exists p_tsadj_self_read on timesheet_adjustments;
create policy p_tsadj_admin on timesheet_adjustments for all to authenticated
  using (is_admin()) with check (is_admin());
create policy p_tsadj_self_read on timesheet_adjustments for select to authenticated
  using (staff_id = auth.uid() or is_admin());

-- ============================================================
-- STARTER DATA (edit the names later in the app)
-- ============================================================
insert into clients (name, timezone, shift_start, shift_end, workdays) values
 ('Sample Client A', 'America/New_York', '21:00', '06:00', 'Mon-Fri')
on conflict (name) do nothing;
