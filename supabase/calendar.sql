-- ============================================================
-- SMB VS PORTAL — Calendar (My Calendar / Live Status → Team Calendar)
-- Paste this whole file into Supabase → SQL Editor → Run.
-- Safe to re-run. Every table is server-only (RLS on, no policies):
-- the browser reads and writes the calendar through the Render server,
-- which also keeps the Google Calendar copy in sync.
-- ============================================================

-- Meetings, coaching sessions and client holidays.
-- attendee_ids empty = everyone (all active staff).
create table if not exists calendar_events (
  id             uuid primary key default gen_random_uuid(),
  type           text not null default 'meeting' check (type in ('meeting','coaching','holiday')),
  title          text not null,
  notes          text,
  start_at       timestamptz not null,
  end_at         timestamptz not null,
  all_day        boolean not null default false,
  attendee_ids   uuid[] not null default '{}',
  client_ids     uuid[] not null default '{}',
  meet_link      text,
  google_event_id text unique,
  source         text not null default 'portal' check (source in ('portal','google')),
  want_meet      boolean not null default true,
  reminders      integer[] not null default '{1440,60,15}',
  notify_slack   boolean not null default true,
  email_invites  boolean not null default true,
  created_by     uuid references staff(id) on delete set null,
  cancelled_at   timestamptz,
  created_at     timestamptz not null default now(),
  updated_at     timestamptz not null default now(),
  check (end_at > start_at)
);
create index if not exists calendar_events_start_idx on calendar_events (start_at);

-- Accept / decline per attendee.
create table if not exists calendar_rsvps (
  event_id   uuid not null references calendar_events(id) on delete cascade,
  staff_id   uuid not null references staff(id) on delete cascade,
  status     text not null check (status in ('accepted','declined')),
  updated_at timestamptz not null default now(),
  primary key (event_id, staff_id)
);

-- The one connected Google account (smb.ph.virtual.staffing@gmail.com).
create table if not exists google_calendar_link (
  id             integer primary key default 1 check (id = 1),
  account_email  text,
  refresh_token  text,
  calendar_id    text,
  connected_by   uuid references staff(id) on delete set null,
  connected_at   timestamptz,
  last_pull_at   timestamptz,
  last_sync_at   timestamptz,
  last_error     text
);

-- Approved PTO / PCH / Planned Absence / Sick Leave / Half Day → one all-day Google event per request.
-- key = request id, or "m:<staff>:<type>:<first date>" for leave days added without a request
create table if not exists calendar_leave_sync (
  leave_key       text primary key,
  google_event_id text not null,
  start_date      date not null,
  end_date        date not null,
  summary         text,
  updated_at      timestamptz not null default now()
);

alter table calendar_events      enable row level security;
alter table calendar_rsvps       enable row level security;
alter table google_calendar_link enable row level security;
alter table calendar_leave_sync  enable row level security;
-- (no policies on purpose: only the server's service-role key can touch these tables)
