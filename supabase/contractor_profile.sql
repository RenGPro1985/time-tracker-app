-- ============================================================
-- SMB VS PORTAL — Contractor Profile details + Birthday / Workiversary
-- Paste this whole file into Supabase → SQL Editor → Run. Safe to re-run.
--
--  1. staff.address / staff.contact_no (birth_date already exists)
--     Staff fill them in on My Profile through update_my_profile();
--     staff can only ever read their own staff row (p_staff_self), admins read all.
--  2. celebration_awards — one row per birthday / workiversary, 500 SMB tokens each.
--     unique (staff_id, kind, occasion_date) = a re-run can never pay twice.
--  3. rw_claim_state() — same as before, plus celebration tokens, so they show in
--     My Tokens ("Earning this week") and are claimed into BINGO like every other token.
--  4. calendar_celebration_sync — the yearly Google Calendar events (server-only).
-- ============================================================

-- 1. profile fields ------------------------------------------------------
alter table staff add column if not exists address            text;
alter table staff add column if not exists contact_no         text;
alter table staff add column if not exists profile_updated_at timestamptz;

create or replace function update_my_profile(p_birth_date date, p_address text, p_contact_no text)
returns jsonb language plpgsql security definer set search_path = public as $$
declare me_id uuid := auth.uid(); a text := nullif(btrim(coalesce(p_address,'')), ''); c text := nullif(btrim(coalesce(p_contact_no,'')), '');
begin
  if me_id is null then raise exception 'Please log in.'; end if;
  if p_birth_date is null then raise exception 'Date of birth is required.'; end if;
  if p_birth_date < date '1940-01-01' or p_birth_date > ((now() at time zone 'Asia/Manila')::date - interval '15 years') then
    raise exception 'Please check your date of birth.'; end if;
  if a is null then raise exception 'Address is required.'; end if;
  if length(a) > 300 then raise exception 'Address is too long (300 characters max).'; end if;
  if c is null then raise exception 'Contact number is required.'; end if;
  if c !~ '^\+?[0-9][0-9 ()-]{6,19}$' then raise exception 'Contact number should look like 0917 123 4567 or +63 917 123 4567.'; end if;
  update staff set birth_date = p_birth_date, address = a, contact_no = c, profile_updated_at = now()
   where id = me_id and active;
  if not found then raise exception 'This staff account is inactive.'; end if;
  return jsonb_build_object('ok', true);
end $$;
revoke all on function update_my_profile(date, text, text) from public, anon;
grant execute on function update_my_profile(date, text, text) to authenticated;

-- 2. celebration token awards -------------------------------------------
create table if not exists celebration_awards (
  id              uuid primary key default gen_random_uuid(),
  staff_id        uuid not null references staff(id) on delete cascade,
  kind            text not null check (kind in ('birthday','workiversary')),
  occasion_date   date not null,
  years           integer,                       -- workiversary only
  tokens          integer not null default 500 check (tokens >= 0),
  week_start      date not null,                 -- Monday of occasion_date (same weeks as reward_ledger)
  slack_posted_at timestamptz,
  created_at      timestamptz not null default now(),
  unique (staff_id, kind, occasion_date)
);
create index if not exists celebration_awards_staff_week on celebration_awards (staff_id, week_start);
alter table celebration_awards enable row level security;
drop policy if exists p_celebrate_read on celebration_awards;
create policy p_celebrate_read on celebration_awards for select to authenticated using (staff_id = auth.uid() or is_admin());
-- (no insert/update policy: only the Render server's service-role key writes awards)

-- 3. My Tokens: add celebration tokens to the weekly totals --------------
-- Identical to the live rw_claim_state except the three "+ celebration_awards" parts.
create or replace function public.rw_claim_state(p_staff uuid)
returns jsonb language plpgsql stable security definer set search_path to 'public' as $function$
declare
  live date := coalesce((select (value ->> 'claims_live_from')::date from settings where key = 'token_rules'), date '2026-11-02');
  lw date := rw_last_claimable_week(); cur_wk date := lw + 7;
  earned int; pend_wk int; claimed int; lnk record; last_c record; weeks jsonb; claims jsonb; cl_this boolean;
begin
  select coalesce(sum(tokens), 0) into earned from reward_ledger where staff_id = p_staff and week_start >= live and week_start <= lw;
  earned := earned + coalesce((select sum(tokens) from celebration_awards where staff_id = p_staff and week_start >= live and week_start <= lw), 0);
  select coalesce(sum(tokens), 0) into pend_wk from reward_ledger where staff_id = p_staff and week_start >= live and week_start > lw;
  pend_wk := pend_wk + coalesce((select sum(tokens) from celebration_awards where staff_id = p_staff and week_start >= live and week_start > lw), 0);
  select coalesce(sum(amount), 0) into claimed from reward_claims where staff_id = p_staff;
  select * into lnk from reward_bingo_links where staff_id = p_staff;
  cl_this := exists (select 1 from reward_claims where staff_id = p_staff and upto_week >= lw);
  select coalesce(jsonb_agg(jsonb_build_object('week_start', w, 'tokens', t) order by w desc), '[]'::jsonb) into weeks
  from (select week_start w, sum(tokens) t from (
          select week_start, tokens from reward_ledger where staff_id = p_staff and week_start >= live
          union all
          select week_start, tokens from celebration_awards where staff_id = p_staff and week_start >= live) u
        group by week_start order by week_start desc limit 8) z;
  select coalesce(jsonb_agg(jsonb_build_object('id', id, 'amount', amount, 'upto_week', upto_week, 'status', status, 'created_at', created_at,
    'credited_at', credited_at, 'player_name', player_name, 'balance_after', bingo_balance_after) order by created_at desc), '[]'::jsonb) into claims
  from (select * from reward_claims where staff_id = p_staff order by created_at desc limit 10) c;
  return jsonb_build_object(
    'live_from', live, 'last_claimable_week', lw, 'current_week', cur_wk, 'live', now() >= ((live + 7)::timestamp + time '07:00') at time zone 'Asia/Manila',
    'first_claim_at', ((live + 7)::timestamp + time '07:00') at time zone 'Asia/Manila',
    'next_unlock_at', ((cur_wk + 7)::timestamp + time '07:00') at time zone 'Asia/Manila',
    'earned_claimable', earned, 'claimed_total', claimed, 'available', greatest(earned - claimed, 0), 'carry_debt', greatest(claimed - earned, 0),
    'this_week', pend_wk, 'claimed_this_week', cl_this,
    'pending', exists (select 1 from reward_claims where staff_id = p_staff and status = 'pending'),
    'player_id', lnk.player_id, 'player_name', lnk.player_name, 'weeks', weeks, 'claims', claims);
end $function$;

-- 4. Google Calendar copies of the yearly events (server-only) ------------
create table if not exists calendar_celebration_sync (
  celebrate_key   text primary key,                -- 'bday:<staff id>' or 'wiv:<staff id>'
  google_event_id text not null,
  signature       text not null,                   -- summary|start|rrule — re-pushed when it changes
  updated_at      timestamptz not null default now()
);
alter table calendar_celebration_sync enable row level security;
-- (no policies on purpose)
