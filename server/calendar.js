// ============================================================
// SMB VS PORTAL — CALENDAR + GOOGLE CALENDAR SYNC
// Staff "My Calendar" tab and admin "Live Status → Team Calendar".
//
// One Google account (smb.ph.virtual.staffing@gmail.com) is connected once by an admin.
// The server keeps a secondary calendar on it ("SMB VS Team") in sync both ways:
//   portal → Google : meetings / coaching / holidays (with Meet links + email invites)
//                     and every APPROVED leave day (PTO, PCH, PA, SL, Half Day)
//   Google → portal : events added / moved / deleted directly in Google Calendar
// Staff never need a Google account — the portal reads the calendar from Supabase.
//
// Render env vars: GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET
//   (optional) GOOGLE_REDIRECT_URI — defaults to the URL registered in Google Cloud.
// Tables: supabase/calendar.sql (server-only, RLS on with no policies).
// ============================================================
import { createHmac, timingSafeEqual } from 'crypto';

const TEAM_CAL_NAME = 'SMB VS Team';
const TZ = 'Asia/Manila';
const DEFAULT_REDIRECT = 'https://time-tracker-app-95fe.onrender.com/api/google/oauth/callback';
const SCOPES = ['openid', 'email', 'https://www.googleapis.com/auth/calendar'];
const LEAVE_TYPES = ['pto', 'pch', 'planned_absence', 'sick_leave', 'half_day'];
const LEAVE_LABEL = { pto: 'PTO', pch: 'Paid Client Holiday', planned_absence: 'Planned Absence', sick_leave: 'Sick Leave', half_day: 'Half Day' };
const TYPE_LABEL = { meeting: 'Meeting', coaching: 'Coaching session', holiday: 'Client holiday' };
const isoDateRe = /^\d{4}-\d{2}-\d{2}$/;
const timeRe = /^([01]\d|2[0-3]):[0-5]\d$/;
const uuidRe = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

// ---- PHT date helpers ----
const phDateOf = v => new Date(new Date(v).getTime() + 8 * 3600000).toISOString().slice(0, 10);
const phMidnight = d => new Date(d + 'T00:00:00+08:00');
const addDays = (d, n) => { const x = new Date(d + 'T00:00:00Z'); x.setUTCDate(x.getUTCDate() + n); return x.toISOString().slice(0, 10); };
const fmtWhen = ev => {
  if (ev.all_day) {
    const a = phDateOf(ev.start_at), b = addDays(phDateOf(ev.end_at), -1);
    const f = d => new Intl.DateTimeFormat('en-US', { timeZone: 'UTC', weekday: 'short', month: 'short', day: 'numeric' }).format(new Date(d + 'T00:00:00Z'));
    return a === b ? f(a) + ' (all day)' : `${f(a)} – ${f(b)}`;
  }
  const s = new Intl.DateTimeFormat('en-US', { timeZone: TZ, weekday: 'short', month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit', hour12: true }).format(new Date(ev.start_at));
  const mins = Math.round((new Date(ev.end_at) - new Date(ev.start_at)) / 60000);
  return `${s} PHT (${mins} min)`;
};

export function registerCalendar(ctx) {
  const { app, admin, requireAdmin, requireActiveUser, sendDmOnce, dmBlocks, safeSlack, PORTAL_URL, SLACK_BOT_TOKEN, STATE_SECRET } = ctx;
  // .trim(): values pasted into Render can carry an invisible trailing newline → Google "invalid_client"
  const CLIENT_ID = String(process.env.GOOGLE_CLIENT_ID || '').trim();
  const CLIENT_SECRET = String(process.env.GOOGLE_CLIENT_SECRET || '').trim();
  const REDIRECT_URI = String(process.env.GOOGLE_REDIRECT_URI || DEFAULT_REDIRECT).trim();
  // only this Google account may be connected (override with GOOGLE_CALENDAR_ACCOUNT on Render)
  const ACCOUNT = String(process.env.GOOGLE_CALENDAR_ACCOUNT || 'smb.ph.virtual.staffing@gmail.com').trim().toLowerCase();
  const stats = { last: null, lastError: null, pushed: 0, pulled: 0, leave: 0, dms: 0 };

  // ---------------------------------------------------------------- Google plumbing
  let tokenCache = { token: null, exp: 0, rt: null };
  async function getLink() {
    const { data, error } = await admin.from('google_calendar_link').select('*').eq('id', 1).maybeSingle();
    if (error) throw error;
    return data && data.refresh_token && data.calendar_id ? data : null;
  }
  async function tokenRequest(params) {
    const r = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ client_id: CLIENT_ID, client_secret: CLIENT_SECRET, ...params })
    });
    const j = await r.json().catch(() => ({}));
    if (!r.ok) throw Object.assign(new Error(j.error_description || j.error || ('Google token error ' + r.status)), { google: j.error });
    return j;
  }
  async function accessToken(link, force = false) {
    if (!force && tokenCache.token && tokenCache.rt === link.refresh_token && Date.now() < tokenCache.exp - 60000) return tokenCache.token;
    try {
      const j = await tokenRequest({ grant_type: 'refresh_token', refresh_token: link.refresh_token });
      tokenCache = { token: j.access_token, exp: Date.now() + (j.expires_in || 3600) * 1000, rt: link.refresh_token };
      return j.access_token;
    } catch (e) {
      if (e.google === 'invalid_grant') {
        await admin.from('google_calendar_link').update({ last_error: 'Google access was removed or expired — click Connect Google again.' }).eq('id', 1);
      }
      throw e;
    }
  }
  async function gcal(link, method, path, { query, body } = {}) {
    const url = 'https://www.googleapis.com/calendar/v3' + path + (query ? '?' + new URLSearchParams(query) : '');
    let lastErr;
    for (let attempt = 0; attempt < 3; attempt++) {
      const token = await accessToken(link, attempt === 1 && lastErr?.status === 401);
      const r = await fetch(url, { method, headers: { Authorization: 'Bearer ' + token, ...(body ? { 'Content-Type': 'application/json' } : {}) }, body: body ? JSON.stringify(body) : undefined });
      if (r.status === 204) return {};
      const j = await r.json().catch(() => ({}));
      if (r.ok) return j;
      lastErr = Object.assign(new Error(j.error?.message || ('Google Calendar error ' + r.status)), { status: r.status });
      if (r.status === 401) continue;
      if (r.status === 429 || r.status >= 500 || (r.status === 403 && /rate/i.test(lastErr.message))) { await new Promise(res => setTimeout(res, 1000 * (attempt + 1))); continue; }
      break;
    }
    throw lastErr;
  }
  const calPath = link => '/calendars/' + encodeURIComponent(link.calendar_id);

  // signed OAuth state (survives a Render restart, expires in 15 min)
  const sign = s => createHmac('sha256', STATE_SECRET || CLIENT_SECRET || 'smb').update(s).digest('base64url');
  function makeState(adminId) { const p = Buffer.from(JSON.stringify({ a: adminId, e: Date.now() + 15 * 60000 })).toString('base64url'); return p + '.' + sign(p); }
  function readState(state) {
    const [p, sig] = String(state || '').split('.');
    if (!p || !sig) return null;
    const want = Buffer.from(sign(p)), got = Buffer.from(sig);
    if (want.length !== got.length || !timingSafeEqual(want, got)) return null;
    try { const o = JSON.parse(Buffer.from(p, 'base64url').toString()); return o.e > Date.now() ? o : null; } catch { return null; }
  }

  // ---------------------------------------------------------------- shared data helpers
  async function activeStaff() {
    const { data, error } = await admin.from('staff').select('id, full_name, email, role, active, client_id').eq('active', true).order('full_name');
    if (error) throw error;
    return data || [];
  }
  // attendee_ids empty = everyone
  async function attendeesOf(ev, staff) {
    staff = staff || await activeStaff();
    if (!ev.attendee_ids || !ev.attendee_ids.length) return staff;
    const set = new Set(ev.attendee_ids.map(String));
    return staff.filter(s => set.has(String(s.id)));
  }
  async function notifyInApp(staffIds, title, body, eventId) {
    const rows = [...new Set(staffIds.map(String))].map(id => ({ staff_id: id, title: String(title).slice(0, 200), body: String(body).slice(0, 500), related_type: 'calendar_event', related_id: eventId }));
    if (!rows.length) return;
    const { error } = await admin.from('in_app_notifications').insert(rows);
    if (error) console.error('Calendar in-app notification failed:', error.message);
  }
  async function adminIds() {
    const { data } = await admin.from('staff').select('id').eq('role', 'admin').eq('active', true);
    return (data || []).map(r => r.id);
  }
  function dmFor(ev, kind) {
    const head = { new: `📅 *New ${(TYPE_LABEL[ev.type] || 'event').toLowerCase()}*`, changed: '🔁 *Schedule changed*', cancelled: '❌ *Cancelled*' }[kind]
      || `⏰ *Starting ${kind >= 1440 ? 'tomorrow' : kind >= 60 ? 'in ' + Math.round(kind / 60) + ' hour' + (kind >= 120 ? 's' : '') : 'in ' + kind + ' minutes'}*`;
    const lines = [head, `*${safeSlack(ev.title, 200)}*`, fmtWhen(ev)];
    if (ev.meet_link && kind !== 'cancelled') lines.push(`🎥 <${ev.meet_link}|Join Google Meet>`);
    lines.push(`<${PORTAL_URL}|Open My Calendar in the portal>`);
    return { text: `${ev.title} — ${fmtWhen(ev)}`, blocks: dmBlocks(lines) };
  }
  // fire-and-forget Slack DMs (sendDmOnce makes every key send at most once)
  function dmMany(ev, people, kind, keyPart) {
    if (!SLACK_BOT_TOKEN || !ev.notify_slack || !people.length) return;
    (async () => {
      for (const s of people) {
        try { const r = await sendDmOnce({ eventKey: `dm:cal:${ev.id}:${keyPart}:${s.id}`, entityId: ev.id, staff: s, ...dmFor(ev, kind) }); if (r?.sent) stats.dms++; }
        catch (e) { console.error('Calendar DM failed:', e.message); }
      }
    })();
  }

  // ---------------------------------------------------------------- portal event → Google
  async function googleBody(ev, staff) {
    const people = await attendeesOf(ev, staff);
    const names = ev.attendee_ids?.length ? people.map(p => p.full_name).join(', ') : 'Everyone';
    const body = {
      summary: ev.type === 'coaching' && !/coach/i.test(ev.title) ? 'Coaching: ' + ev.title : ev.title,
      description: [ev.notes || '', `Attendees: ${names}`, `Scheduled in the SMB VS Portal: ${PORTAL_URL}`].filter(Boolean).join('\n\n'),
      extendedProperties: { private: { smbId: ev.id } },
      reminders: { useDefault: false, overrides: (ev.reminders || []).slice(0, 5).map(m => ({ method: 'popup', minutes: Math.min(40320, Number(m)) })) },
      attendees: ev.email_invites ? people.filter(p => p.email).map(p => ({ email: p.email, displayName: p.full_name })) : []
    };
    if (ev.all_day) { body.start = { date: phDateOf(ev.start_at) }; body.end = { date: phDateOf(ev.end_at) }; }
    else { body.start = { dateTime: new Date(ev.start_at).toISOString(), timeZone: TZ }; body.end = { dateTime: new Date(ev.end_at).toISOString(), timeZone: TZ }; }
    return body;
  }
  async function pushEvent(ev, staff) {
    const link = await getLink(); if (!link) return ev;
    const body = await googleBody(ev, staff);
    const sendUpdates = ev.email_invites ? 'all' : 'none';
    let res;
    if (ev.google_event_id) {
      try { res = await gcal(link, 'PATCH', calPath(link) + '/events/' + encodeURIComponent(ev.google_event_id), { query: { conferenceDataVersion: 1, sendUpdates }, body }); }
      catch (e) { if (e.status !== 404 && e.status !== 410) throw e; }
    }
    if (!res) {
      if (ev.want_meet && !ev.all_day) body.conferenceData = { createRequest: { requestId: ev.id, conferenceSolutionKey: { type: 'hangoutsMeet' } } };
      res = await gcal(link, 'POST', calPath(link) + '/events', { query: { conferenceDataVersion: 1, sendUpdates }, body });
    }
    const upd = { google_event_id: res.id, meet_link: res.hangoutLink || ev.meet_link || null };
    if (upd.google_event_id !== ev.google_event_id || upd.meet_link !== ev.meet_link) {
      await admin.from('calendar_events').update(upd).eq('id', ev.id);
      Object.assign(ev, upd);
    }
    stats.pushed++;
    return ev;
  }
  async function removeFromGoogle(ev) {
    const link = await getLink(); if (!link || !ev.google_event_id) return;
    try { await gcal(link, 'DELETE', calPath(link) + '/events/' + encodeURIComponent(ev.google_event_id), { query: { sendUpdates: ev.email_invites ? 'all' : 'none' } }); }
    catch (e) { if (e.status !== 404 && e.status !== 410) throw e; }
  }

  // ---------------------------------------------------------------- approved leave → Google
  function leaveGroups(rows) {
    const byKey = new Map();
    const manual = rows.filter(r => !r.request_id).sort((a, b) => (a.staff_id + a.type + a.date).localeCompare(b.staff_id + b.type + b.date));
    for (const r of rows.filter(r => r.request_id)) {
      const g = byKey.get(r.request_id) || { key: r.request_id, request_id: r.request_id, staff_id: r.staff_id, type: r.type, start: r.date, end: r.date };
      if (r.date < g.start) g.start = r.date; if (r.date > g.end) g.end = r.date;
      byKey.set(r.request_id, g);
    }
    let cur = null;
    for (const r of manual) {
      if (cur && cur.staff_id === r.staff_id && cur.type === r.type && addDays(cur.end, 1) === r.date) { cur.end = r.date; continue; }
      cur = { key: `m:${r.staff_id}:${r.type}:${r.date}`, request_id: null, staff_id: r.staff_id, type: r.type, start: r.date, end: r.date };
      byKey.set(cur.key, cur);
    }
    return [...byKey.values()];
  }
  async function syncLeave(link, budget) {
    const today = phDateOf(new Date()), from = addDays(today, -30), to = addDays(today, 365);
    const { data: days, error } = await admin.from('leave_days').select('request_id, staff_id, date, type').in('type', LEAVE_TYPES).gte('date', from).lte('date', to).limit(5000);
    if (error) throw error;
    const groups = leaveGroups(days || []);
    const { data: synced, error: se } = await admin.from('calendar_leave_sync').select('*').gte('end_date', from).limit(5000);
    if (se) throw se;
    const have = new Map((synced || []).map(r => [r.leave_key, r]));
    const names = new Map((await admin.from('staff').select('id, full_name').in('id', [...new Set(groups.map(g => g.staff_id))].slice(0, 500))).data?.map(s => [String(s.id), s.full_name]) || []);
    const want = new Set();
    for (const g of groups) {
      want.add(g.key);
      if (budget.n <= 0) break;
      const summary = `🏖️ ${LEAVE_LABEL[g.type] || 'Leave'} — ${names.get(String(g.staff_id)) || 'Staff'}`;
      const prev = have.get(g.key);
      if (prev && prev.start_date === g.start && prev.end_date === g.end && prev.summary === summary) continue;
      const body = { summary, start: { date: g.start }, end: { date: addDays(g.end, 1) }, transparency: 'transparent',
        extendedProperties: { private: { smbLeave: g.key } }, reminders: { useDefault: false, overrides: [] } };
      let gid = prev?.google_event_id, ok = false;
      if (gid) {
        try { await gcal(link, 'PATCH', calPath(link) + '/events/' + encodeURIComponent(gid), { body }); ok = true; }
        catch (e) { if (e.status !== 404 && e.status !== 410) throw e; }
      }
      if (!ok) gid = (await gcal(link, 'POST', calPath(link) + '/events', { body })).id;
      budget.n--; stats.leave++;
      await admin.from('calendar_leave_sync').upsert({ leave_key: g.key, google_event_id: gid, start_date: g.start, end_date: g.end, summary, updated_at: new Date().toISOString() });
    }
    // leave that was rejected / deleted / edited away → remove from Google
    for (const r of synced || []) {
      if (want.has(r.leave_key) || budget.n <= 0) continue;
      if (r.start_date > to) continue;
      try { await gcal(link, 'DELETE', calPath(link) + '/events/' + encodeURIComponent(r.google_event_id)); }
      catch (e) { if (e.status !== 404 && e.status !== 410) throw e; }
      budget.n--;
      await admin.from('calendar_leave_sync').delete().eq('leave_key', r.leave_key);
    }
  }

  // ---------------------------------------------------------------- birthdays + workiversaries → Google
  // One yearly recurring all-day event per active staff member (month + day only, never the year of birth).
  // Removed automatically when they're deactivated / terminated or the date is cleared.
  const isLeapY = y => (y % 4 === 0 && y % 100 !== 0) || y % 400 === 0;
  const occurs = (iso, y) => (String(iso).slice(5, 10) === '02-29' && !isLeapY(y)) ? `${y}-02-28` : `${y}-${String(iso).slice(5, 10)}`;
  const yearlyRule = iso => String(iso).slice(5, 10) === '02-29' ? 'RRULE:FREQ=YEARLY;BYMONTH=2;BYMONTHDAY=-1' : 'RRULE:FREQ=YEARLY';
  function celebrationWants(staff) {
    const out = [];
    for (const s of staff) {
      if (s.role === 'admin') continue;
      if (s.birth_date) {
        const y = Number(phDateOf(new Date()).slice(0, 4));
        out.push({ key: 'bday:' + s.id, summary: `🎂 Birthday — ${s.full_name}`, start: occurs(s.birth_date, y), rrule: yearlyRule(s.birth_date) });
      }
      if (s.hire_date) {
        const first = occurs(s.hire_date, Number(s.hire_date.slice(0, 4)) + 1);
        out.push({ key: 'wiv:' + s.id, summary: `🎉 Workiversary — ${s.full_name} (hired ${s.hire_date.slice(0, 4)})`, start: first, rrule: yearlyRule(s.hire_date) });
      }
    }
    return out;
  }
  async function syncCelebrations(link, budget) {
    const { data: staff, error } = await admin.from('staff').select('id, full_name, role, birth_date, hire_date').eq('active', true);
    if (error) throw error;
    const { data: synced, error: se } = await admin.from('calendar_celebration_sync').select('*');
    if (se) { if (/calendar_celebration_sync/.test(se.message)) return; throw se; } // SQL not run yet
    const have = new Map((synced || []).map(r => [r.celebrate_key, r]));
    const want = new Set();
    for (const w of celebrationWants(staff || [])) {
      want.add(w.key);
      const sig = `${w.summary}|${w.start}|${w.rrule}`;
      const prev = have.get(w.key);
      if (prev && prev.signature === sig) continue;
      if (budget.n <= 0) break;
      const body = { summary: w.summary, start: { date: w.start }, end: { date: addDays(w.start, 1) }, recurrence: [w.rrule], transparency: 'transparent',
        extendedProperties: { private: { smbCelebrate: w.key } }, reminders: { useDefault: false, overrides: [] } };
      let gid = prev?.google_event_id, ok = false;
      if (gid) {
        try { await gcal(link, 'PUT', calPath(link) + '/events/' + encodeURIComponent(gid), { body }); ok = true; }
        catch (e) { if (e.status !== 404 && e.status !== 410) throw e; }
      }
      if (!ok) gid = (await gcal(link, 'POST', calPath(link) + '/events', { body })).id;
      budget.n--;
      await admin.from('calendar_celebration_sync').upsert({ celebrate_key: w.key, google_event_id: gid, signature: sig, updated_at: new Date().toISOString() });
    }
    for (const r of synced || []) {
      if (want.has(r.celebrate_key) || budget.n <= 0) continue;
      try { await gcal(link, 'DELETE', calPath(link) + '/events/' + encodeURIComponent(r.google_event_id)); }
      catch (e) { if (e.status !== 404 && e.status !== 410) throw e; }
      budget.n--;
      await admin.from('calendar_celebration_sync').delete().eq('celebrate_key', r.celebrate_key);
    }
  }
  // portal feed: birthday / workiversary occurrences between from..to (month + day only)
  function celebrationsBetween(staff, from, to) {
    const out = [];
    const y0 = Number(from.slice(0, 4)), y1 = Number(to.slice(0, 4));
    for (const s of staff) {
      if (s.role === 'admin') continue;
      for (let y = y0; y <= y1; y++) {
        if (s.birth_date) { const d = occurs(s.birth_date, y); if (d >= from && d <= to) out.push({ key: `bday:${s.id}:${d}`, type: 'birthday', staff_id: s.id, date: d }); }
        if (s.hire_date && y > Number(s.hire_date.slice(0, 4))) {
          const d = occurs(s.hire_date, y);
          if (d >= from && d <= to) out.push({ key: `wiv:${s.id}:${d}`, type: 'workiversary', staff_id: s.id, date: d, years: y - Number(s.hire_date.slice(0, 4)) });
        }
      }
    }
    return out;
  }

  // ---------------------------------------------------------------- Google → portal
  function gTimes(item) {
    if (item.start?.date) return { all_day: true, start_at: phMidnight(item.start.date).toISOString(), end_at: phMidnight(item.end?.date || addDays(item.start.date, 1)).toISOString() };
    return { all_day: false, start_at: new Date(item.start.dateTime).toISOString(), end_at: new Date(item.end?.dateTime || item.start.dateTime).toISOString() };
  }
  const sameTime = (a, b) => new Date(a).getTime() === new Date(b).getTime();
  async function pullFromGoogle(link) {
    const startedAt = new Date();
    const since = link.last_pull_at ? new Date(new Date(link.last_pull_at).getTime() - 120000) : new Date(Date.now() - 20 * 86400000);
    let pageToken = null, pages = 0;
    do {
      const query = { updatedMin: since.toISOString(), showDeleted: 'true', singleEvents: 'true', maxResults: '250' };
      if (pageToken) query.pageToken = pageToken;
      const j = await gcal(link, 'GET', calPath(link) + '/events', { query });
      for (const item of j.items || []) {
        const priv = item.extendedProperties?.private || {};
        if (priv.smbLeave || priv.smbCelebrate) continue;
        const cancelled = item.status === 'cancelled';
        let row = null;
        if (priv.smbId && uuidRe.test(priv.smbId)) row = (await admin.from('calendar_events').select('*').eq('id', priv.smbId).maybeSingle()).data;
        if (!row) row = (await admin.from('calendar_events').select('*').eq('google_event_id', item.id).maybeSingle()).data;
        if (cancelled) {
          if (row && !row.cancelled_at) {
            await admin.from('calendar_events').update({ cancelled_at: new Date().toISOString(), updated_at: new Date().toISOString() }).eq('id', row.id);
            if (row.source === 'portal' && new Date(row.end_at) > new Date()) {
              const people = await attendeesOf(row);
              await notifyInApp(people.map(p => p.id), '❌ Cancelled: ' + row.title, fmtWhen(row), row.id);
            }
            stats.pulled++;
          }
          continue;
        }
        if (!item.start) continue;
        const t = gTimes(item);
        if (row) {
          const title = row.type === 'coaching' ? String(item.summary || '').replace(/^Coaching:\s*/i, '') || row.title : (item.summary || row.title);
          const changedTime = !sameTime(row.start_at, t.start_at) || !sameTime(row.end_at, t.end_at) || row.all_day !== t.all_day;
          if (changedTime || title !== row.title || row.cancelled_at || (item.hangoutLink && item.hangoutLink !== row.meet_link)) {
            const upd = { title, ...t, meet_link: item.hangoutLink || row.meet_link, cancelled_at: null, updated_at: new Date().toISOString() };
            await admin.from('calendar_events').update(upd).eq('id', row.id);
            if (changedTime && row.source === 'portal' && new Date(t.end_at) > new Date()) {
              const ev = { ...row, ...upd };
              const people = await attendeesOf(ev);
              await notifyInApp(people.map(p => p.id), '🔁 Schedule changed: ' + title, fmtWhen(ev), row.id);
              dmMany(ev, people, 'changed', 'chg:' + new Date(t.start_at).getTime());
            }
            stats.pulled++;
          }
        } else {
          // added directly in Google Calendar → visible to everyone in the portal, no Slack pings
          await admin.from('calendar_events').insert({
            type: 'meeting', title: String(item.summary || '(no title)').slice(0, 300), notes: item.description ? String(item.description).slice(0, 2000) : null,
            ...t, attendee_ids: [], google_event_id: item.id, source: 'google', meet_link: item.hangoutLink || null,
            want_meet: false, reminders: [], notify_slack: false, email_invites: false
          });
          stats.pulled++;
        }
      }
      pageToken = j.nextPageToken; pages++;
    } while (pageToken && pages < 8);
    await admin.from('google_calendar_link').update({ last_pull_at: startedAt.toISOString() }).eq('id', 1);
  }

  // ---------------------------------------------------------------- the sweep
  let running = false;
  async function calendarSweep() {
    if (running) return { skipped: 'running' };
    running = true;
    try {
      const link = CLIENT_ID && CLIENT_SECRET ? await getLink().catch(() => null) : null;
      if (link) {
        try {
          const budget = { n: 40 };
          // portal events made before Google was connected (or whose push failed)
          const { data: unsynced } = await admin.from('calendar_events').select('*').is('google_event_id', null).is('cancelled_at', null).eq('source', 'portal').gt('end_at', new Date(Date.now() - 86400000).toISOString()).limit(20);
          if (unsynced?.length) { const staff = await activeStaff(); for (const ev of unsynced) { if (budget.n-- <= 0) break; await pushEvent(ev, staff); } }
          await syncLeave(link, budget);
          await syncCelebrations(link, budget);
          await pullFromGoogle(link);
          await admin.from('google_calendar_link').update({ last_sync_at: new Date().toISOString(), last_error: null }).eq('id', 1);
        } catch (e) {
          console.error('Google Calendar sync failed:', e.message);
          stats.lastError = e.message;
          await admin.from('google_calendar_link').update({ last_error: String(e.message).slice(0, 500) }).eq('id', 1);
        }
      }
      await sendReminders();
      stats.last = new Date().toISOString();
      return { ok: true, connected: !!link, ...stats };
    } finally { running = false; }
  }
  // Slack reminder DMs at each event's reminder offsets (1 day / 1 hour / 15 min by default)
  async function sendReminders() {
    if (!SLACK_BOT_TOKEN) return;
    const now = Date.now();
    const { data: evs, error } = await admin.from('calendar_events').select('*').is('cancelled_at', null).eq('notify_slack', true)
      .gt('start_at', new Date(now).toISOString()).lt('start_at', new Date(now + 25 * 3600000).toISOString()).limit(200);
    if (error) { console.error('Calendar reminders:', error.message); return; }
    if (!evs?.length) return;
    const staff = await activeStaff();
    for (const ev of evs) {
      const start = new Date(ev.start_at).getTime();
      // only the most recent reminder that is due (no burst of 1-day + 1-hour when created late)
      const due = (ev.reminders || []).map(Number).filter(m => m > 0 && now >= start - m * 60000).sort((a, b) => a - b)[0];
      if (!due) continue;
      if (now - (start - due * 60000) > Math.max(20, due / 4) * 60000) continue; // too late for this one
      if (new Date(ev.created_at).getTime() > start - due * 60000) continue; // created after it was due → the "new event" DM covers it
      const { data: rs } = await admin.from('calendar_rsvps').select('staff_id, status').eq('event_id', ev.id);
      const declined = new Set((rs || []).filter(r => r.status === 'declined').map(r => String(r.staff_id)));
      const people = (await attendeesOf(ev, staff)).filter(p => !declined.has(String(p.id)));
      dmMany(ev, people, due, `rem:${start}:${due}`);
    }
  }

  // ---------------------------------------------------------------- routes: Google connect
  app.post('/api/google/connect', async (req, res) => {
    try {
      const a = await requireAdmin(req, res); if (!a) return;
      if (!CLIENT_ID || !CLIENT_SECRET) return res.status(409).json({ error: 'GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET are not set on Render yet.' });
      const url = 'https://accounts.google.com/o/oauth2/v2/auth?' + new URLSearchParams({
        client_id: CLIENT_ID, redirect_uri: REDIRECT_URI, response_type: 'code', scope: SCOPES.join(' '),
        access_type: 'offline', prompt: 'select_account consent', include_granted_scopes: 'true', state: makeState(a.id),
        ...(ACCOUNT ? { login_hint: ACCOUNT } : {})
      });
      res.json({ ok: true, url });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });
  app.get('/api/google/oauth/callback', async (req, res) => {
    const back = (msg, ok) => res.redirect(PORTAL_URL.replace(/#.*$/, '') + '#calendar-' + (ok ? 'connected' : 'error=' + encodeURIComponent(String(msg).slice(0, 200))));
    try {
      if (req.query.error) return back(req.query.error, false);
      const st = readState(req.query.state);
      if (!st) return back('The connect link expired — click Connect Google again.', false);
      const tok = await tokenRequest({ grant_type: 'authorization_code', code: String(req.query.code || ''), redirect_uri: REDIRECT_URI });
      if (!tok.refresh_token) return back('Google did not return offline access — remove the app at myaccount.google.com/permissions and connect again.', false);
      const who = await fetch('https://openidconnect.googleapis.com/v1/userinfo', { headers: { Authorization: 'Bearer ' + tok.access_token } }).then(r => r.json()).catch(() => ({}));
      if (ACCOUNT && String(who.email || '').toLowerCase() !== ACCOUNT) {
        fetch('https://oauth2.googleapis.com/revoke?token=' + encodeURIComponent(tok.refresh_token), { method: 'POST' }).catch(() => {});
        return back(`You picked ${who.email || 'a different Google account'}. Click Connect Google again and choose ${ACCOUNT} (use "Use another account" if it is not listed).`, false);
      }
      const link = { refresh_token: tok.refresh_token, calendar_id: 'primary' };
      tokenCache = { token: tok.access_token, exp: Date.now() + (tok.expires_in || 3600) * 1000, rt: tok.refresh_token };
      // reuse the "SMB VS Team" calendar if it already exists on this account, else create it
      const { data: old } = await admin.from('google_calendar_link').select('*').eq('id', 1).maybeSingle();
      let calId = null;
      const list = await gcal(link, 'GET', '/users/me/calendarList', { query: { minAccessRole: 'owner', maxResults: '250' } });
      const found = (list.items || []).find(c => c.id === old?.calendar_id) || (list.items || []).find(c => c.summary === TEAM_CAL_NAME);
      if (found) calId = found.id;
      else calId = (await gcal(link, 'POST', '/calendars', { body: { summary: TEAM_CAL_NAME, description: 'Meetings, coaching and time off — synced with the SMB VS Portal.', timeZone: TZ } })).id;
      const sameCal = old?.calendar_id === calId;
      const { error } = await admin.from('google_calendar_link').upsert({
        id: 1, account_email: who.email || null, refresh_token: tok.refresh_token, calendar_id: calId, connected_by: st.a,
        connected_at: new Date().toISOString(), last_error: null, ...(sameCal ? {} : { last_pull_at: null })
      });
      if (error) throw error;
      if (!sameCal) { // a different calendar → re-push everything to it
        await admin.from('calendar_leave_sync').delete().neq('leave_key', '');
        await admin.from('calendar_events').update({ google_event_id: null }).eq('source', 'portal').gt('end_at', new Date().toISOString());
      }
      setTimeout(() => calendarSweep().catch(() => {}), 500);
      back('', true);
    } catch (e) { console.error('Google connect failed:', e); back(e.message || 'Connect failed', false); }
  });
  app.post('/api/google/disconnect', async (req, res) => {
    try {
      const a = await requireAdmin(req, res); if (!a) return;
      const { data: old } = await admin.from('google_calendar_link').select('refresh_token').eq('id', 1).maybeSingle();
      if (old?.refresh_token) fetch('https://oauth2.googleapis.com/revoke?token=' + encodeURIComponent(old.refresh_token), { method: 'POST' }).catch(() => {});
      await admin.from('google_calendar_link').update({ refresh_token: null, last_error: null }).eq('id', 1);
      tokenCache = { token: null, exp: 0, rt: null };
      res.json({ ok: true });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });
  app.post('/api/calendar/sync', async (req, res) => {
    try { const a = await requireAdmin(req, res); if (!a) return; res.json(await calendarSweep()); }
    catch (e) { res.status(500).json({ error: e.message }); }
  });

  // ---------------------------------------------------------------- routes: calendar data
  app.get('/api/calendar/feed', async (req, res) => {
    try {
      const u = await requireActiveUser(req, res); if (!u) return;
      const { data: meRow } = await admin.from('staff').select('id, full_name, role, client_id').eq('id', u.row.id).single();
      const isAdmin = meRow?.role === 'admin', myId = String(meRow.id);
      const from = String(req.query.from || ''), to = String(req.query.to || '');
      if (!isoDateRe.test(from) || !isoDateRe.test(to) || to < from || (new Date(to) - new Date(from)) > 120 * 86400000) return res.status(400).json({ error: 'from/to must be dates up to 120 days apart.' });
      const fromTs = phMidnight(from).toISOString(), toTs = phMidnight(addDays(to, 1)).toISOString();
      const [evQ, staffQ, clientsQ, leaveQ, pendQ, linkQ] = await Promise.all([
        admin.from('calendar_events').select('*').is('cancelled_at', null).lt('start_at', toTs).gt('end_at', fromTs).order('start_at').limit(1500),
        admin.from('staff').select('id, full_name, client_id, role, birth_date, hire_date').eq('active', true).order('full_name'),
        admin.from('clients').select('id, name, timezone'),
        admin.from('leave_days').select('request_id, staff_id, date, type').in('type', LEAVE_TYPES).gte('date', from).lte('date', to).limit(5000),
        (() => { let q = admin.from('requests').select('id, staff_id, type, start_date, end_date, reason, status, created_at').eq('status', 'pending').in('type', LEAVE_TYPES).lte('start_date', to).gte('end_date', from).limit(500); if (!isAdmin) q = q.eq('staff_id', myId); return q; })(),
        admin.from('google_calendar_link').select('account_email, refresh_token, last_sync_at, last_error').eq('id', 1).maybeSingle()
      ]);
      for (const q of [evQ, staffQ, clientsQ, leaveQ, pendQ]) if (q.error) throw q.error;
      const evs = evQ.data || [];
      const rsvpQ = evs.length ? await admin.from('calendar_rsvps').select('event_id, staff_id, status').in('event_id', evs.map(e => e.id)) : { data: [] };
      const rs = {};
      for (const r of rsvpQ.data || []) (rs[r.event_id] = rs[r.event_id] || {})[r.staff_id] = r.status;
      const events = evs.map(e => {
        const mine = !e.attendee_ids?.length || e.attendee_ids.map(String).includes(myId);
        const out = { id: e.id, type: e.type, title: e.title, start_at: e.start_at, end_at: e.end_at, all_day: e.all_day, attendee_ids: e.attendee_ids || [], client_ids: e.client_ids || [],
          source: e.source, rsvp: rs[e.id] || {}, notes: (isAdmin || mine) ? e.notes : null, meet_link: (isAdmin || mine) ? e.meet_link : null };
        if (isAdmin) Object.assign(out, { reminders: e.reminders, notify_slack: e.notify_slack, email_invites: e.email_invites, want_meet: e.want_meet, synced: !!e.google_event_id });
        return out;
      });
      const leave = leaveGroups(leaveQ.data || []).map(g => ({ key: g.key, request_id: g.request_id, staff_id: g.staff_id, start: g.start, end: g.end, status: 'approved',
        type: (!isAdmin && g.type === 'sick_leave' && String(g.staff_id) !== myId) ? 'out' : g.type }));
      for (const p of pendQ.data || []) leave.push({ key: 'p:' + p.id, request_id: p.id, staff_id: p.staff_id, start: p.start_date, end: p.end_date || p.start_date, status: 'pending', type: p.type, reason: isAdmin || String(p.staff_id) === myId ? p.reason : null });
      const link = linkQ.data;
      const celebrations = celebrationsBetween(staffQ.data || [], from, to);
      res.json({ ok: true, me: { id: myId, role: meRow.role, name: meRow.full_name, client_id: meRow.client_id }, events, leave, celebrations,
        staff: (staffQ.data || []).map(s => ({ id: s.id, name: s.full_name, client_id: s.client_id, role: s.role })),
        clients: clientsQ.data || [],
        google: { configured: !!(CLIENT_ID && CLIENT_SECRET), connected: !!link?.refresh_token, email: link?.account_email || null, last_sync_at: isAdmin ? link?.last_sync_at : undefined, last_error: isAdmin ? link?.last_error : undefined } });
    } catch (e) { console.error('Calendar feed failed:', e); res.status(500).json({ error: e.message || 'Could not load the calendar.' }); }
  });

  function parseEventBody(b) {
    const type = ['meeting', 'coaching', 'holiday'].includes(b?.type) ? b.type : null;
    const title = String(b?.title || '').trim().slice(0, 300);
    if (!type) return { error: 'Pick a type.' };
    if (!title) return { error: 'Title is required.' };
    const date = String(b?.date || '');
    if (!isoDateRe.test(date)) return { error: 'Pick a date.' };
    const all_day = type === 'holiday' || !!b?.all_day;
    let start_at, end_at;
    if (all_day) {
      const endDate = isoDateRe.test(String(b?.end_date || '')) ? String(b.end_date) : date;
      if (endDate < date) return { error: 'End date is before the start date.' };
      start_at = phMidnight(date).toISOString(); end_at = phMidnight(addDays(endDate, 1)).toISOString();
    } else {
      const start = String(b?.start || '');
      if (!timeRe.test(start)) return { error: 'Pick a start time.' };
      const dur = Math.round(Number(b?.duration_min || 30));
      if (!(dur >= 5 && dur <= 720)) return { error: 'Duration must be 5–720 minutes.' };
      start_at = new Date(`${date}T${start}:00+08:00`).toISOString(); end_at = new Date(new Date(start_at).getTime() + dur * 60000).toISOString();
    }
    const ids = arr => (Array.isArray(arr) ? arr : []).map(String).filter(x => uuidRe.test(x)).slice(0, 300);
    const attendee_ids = type === 'holiday' ? [] : ids(b?.attendee_ids);
    if (type === 'coaching' && !attendee_ids.length) return { error: 'Pick who the coaching session is with.' };
    const reminders = [...new Set((Array.isArray(b?.reminders) ? b.reminders : []).map(Number).filter(m => [10080, 1440, 60, 30, 15, 5].includes(m)))].sort((a, z) => z - a);
    return { row: { type, title, notes: String(b?.notes || '').trim().slice(0, 2000) || null, start_at, end_at, all_day, attendee_ids, client_ids: type === 'holiday' ? ids(b?.client_ids) : [],
      want_meet: !all_day && b?.meet !== false, reminders: type === 'holiday' ? [] : reminders, notify_slack: type === 'holiday' ? false : b?.notify_slack !== false, email_invites: type === 'holiday' ? false : b?.email_invites !== false } };
  }

  app.post('/api/calendar/events', async (req, res) => {
    try {
      const a = await requireAdmin(req, res); if (!a) return;
      const p = parseEventBody(req.body); if (p.error) return res.status(400).json({ error: p.error });
      const { data: ev, error } = await admin.from('calendar_events').insert({ ...p.row, created_by: a.id, source: 'portal' }).select().single();
      if (error) throw error;
      const staff = await activeStaff();
      let gErr = null;
      try { await pushEvent(ev, staff); } catch (e) { gErr = e.message; console.error('Calendar push failed:', e.message); }
      if (ev.type !== 'holiday') {
        const people = (await attendeesOf(ev, staff)).filter(s => String(s.id) !== String(a.id));
        await notifyInApp(people.map(p => p.id), `📅 New ${(TYPE_LABEL[ev.type] || 'event').toLowerCase()}: ${ev.title}`, fmtWhen(ev), ev.id);
        dmMany(ev, people, 'new', 'new');
      }
      res.json({ ok: true, event: ev, google_error: gErr });
    } catch (e) { console.error('Create event failed:', e); res.status(500).json({ error: e.message || 'Could not save.' }); }
  });

  app.put('/api/calendar/events/:id', async (req, res) => {
    try {
      const a = await requireAdmin(req, res); if (!a) return;
      if (!uuidRe.test(req.params.id)) return res.status(400).json({ error: 'Bad id.' });
      const { data: old } = await admin.from('calendar_events').select('*').eq('id', req.params.id).maybeSingle();
      if (!old || old.cancelled_at) return res.status(404).json({ error: 'Event not found.' });
      const p = parseEventBody(req.body); if (p.error) return res.status(400).json({ error: p.error });
      const { data: ev, error } = await admin.from('calendar_events').update({ ...p.row, updated_at: new Date().toISOString() }).eq('id', old.id).select().single();
      if (error) throw error;
      const staff = await activeStaff();
      let gErr = null;
      try { await pushEvent(ev, staff); } catch (e) { gErr = e.message; }
      const timeChanged = !sameTime(old.start_at, ev.start_at) || !sameTime(old.end_at, ev.end_at);
      if (ev.type !== 'holiday') {
        const before = new Set((await attendeesOf(old, staff)).map(s => String(s.id)));
        const people = (await attendeesOf(ev, staff)).filter(s => String(s.id) !== String(a.id));
        const added = people.filter(s => !before.has(String(s.id))), kept = people.filter(s => before.has(String(s.id)));
        if (added.length) { await notifyInApp(added.map(s => s.id), `📅 New ${(TYPE_LABEL[ev.type] || 'event').toLowerCase()}: ${ev.title}`, fmtWhen(ev), ev.id); dmMany(ev, added, 'new', 'new'); }
        if (timeChanged && kept.length) {
          await notifyInApp(kept.map(s => s.id), '🔁 Schedule changed: ' + ev.title, fmtWhen(ev), ev.id);
          dmMany(ev, kept, 'changed', 'chg:' + new Date(ev.start_at).getTime());
          await admin.from('calendar_rsvps').delete().eq('event_id', ev.id); // new time → ask again
        }
      }
      res.json({ ok: true, event: ev, google_error: gErr });
    } catch (e) { console.error('Update event failed:', e); res.status(500).json({ error: e.message || 'Could not save.' }); }
  });

  app.delete('/api/calendar/events/:id', async (req, res) => {
    try {
      const a = await requireAdmin(req, res); if (!a) return;
      if (!uuidRe.test(req.params.id)) return res.status(400).json({ error: 'Bad id.' });
      const { data: ev } = await admin.from('calendar_events').select('*').eq('id', req.params.id).maybeSingle();
      if (!ev || ev.cancelled_at) return res.status(404).json({ error: 'Event not found.' });
      await admin.from('calendar_events').update({ cancelled_at: new Date().toISOString(), updated_at: new Date().toISOString() }).eq('id', ev.id);
      let gErr = null;
      try { await removeFromGoogle(ev); } catch (e) { gErr = e.message; }
      if (ev.type !== 'holiday' && new Date(ev.end_at) > new Date()) {
        const people = (await attendeesOf(ev)).filter(s => String(s.id) !== String(a.id));
        await notifyInApp(people.map(s => s.id), '❌ Cancelled: ' + ev.title, fmtWhen(ev), ev.id);
        dmMany(ev, people, 'cancelled', 'x');
      }
      res.json({ ok: true, google_error: gErr });
    } catch (e) { console.error('Cancel event failed:', e); res.status(500).json({ error: e.message || 'Could not cancel.' }); }
  });

  app.post('/api/calendar/events/:id/rsvp', async (req, res) => {
    try {
      const u = await requireActiveUser(req, res); if (!u) return;
      const status = req.body?.status === 'declined' ? 'declined' : req.body?.status === 'accepted' ? 'accepted' : null;
      if (!status || !uuidRe.test(req.params.id)) return res.status(400).json({ error: 'Bad request.' });
      const { data: ev } = await admin.from('calendar_events').select('*').eq('id', req.params.id).maybeSingle();
      if (!ev || ev.cancelled_at || ev.type === 'holiday') return res.status(404).json({ error: 'Event not found.' });
      const myId = String(u.row.id);
      if (ev.attendee_ids?.length && !ev.attendee_ids.map(String).includes(myId)) return res.status(403).json({ error: 'You are not invited to this event.' });
      const { data: prev } = await admin.from('calendar_rsvps').select('status').eq('event_id', ev.id).eq('staff_id', myId).maybeSingle();
      const { error } = await admin.from('calendar_rsvps').upsert({ event_id: ev.id, staff_id: myId, status, updated_at: new Date().toISOString() });
      if (error) throw error;
      if (prev?.status !== status) {
        const admins = (await adminIds()).filter(id => String(id) !== myId);
        await notifyInApp(admins, `${status === 'accepted' ? '✅' : '🚫'} ${u.row.full_name} ${status} ${ev.title}`, fmtWhen(ev), ev.id);
      }
      res.json({ ok: true });
    } catch (e) { console.error('RSVP failed:', e); res.status(500).json({ error: e.message || 'Could not save.' }); }
  });

  setInterval(() => calendarSweep().catch(e => console.error('Calendar sweep:', e.message)), 5 * 60 * 1000);
  setTimeout(() => calendarSweep().catch(() => {}), 20000);
  return { calendarSweep };
}
