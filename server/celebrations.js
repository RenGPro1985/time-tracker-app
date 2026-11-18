// ============================================================
// SMB VS PORTAL — Birthdays, Workiversaries, auto-hide on termination
//
// Runs inside the existing 5-minute sweep (and the hourly pinger on /api/notify/sweep),
// so nothing extra has to be scheduled. Everything is idempotent:
//   • terminated staff → staff.active = false the day AFTER their Term / Resignation date
//     (roster "Active staff", Live Status, kudos and future payroll periods all key off active;
//      the payroll period containing their last day still includes them via termination_date)
//   • birthday / workiversary → 500 SMB tokens (celebration_awards, unique per occasion)
//     then one Slack post in #general (slack_notification_log event key, sent once)
// Tables: supabase/contractor_profile.sql
// ============================================================

const TOKENS = 500;
const TZ = 'Asia/Manila';
// [2026-11-17 fix] catch-up: re-check the last 7 PH days every sweep, so a date the server missed
// (asleep, restarted, hire date / DOB entered late, a failed Slack post) is still awarded + greeted (belated).
// Safe: unique (staff_id, kind, occasion_date) + the Slack event key mean nothing is ever paid or posted twice.
const CATCHUP_DAYS = 7;
const STUCK_MS = 3 * 60 * 1000; // a sweep that hangs longer than this no longer blocks every later sweep

const phToday = (now = new Date()) => new Date(now.getTime() + 8 * 3600000).toISOString().slice(0, 10);
const isLeap = y => (y % 4 === 0 && y % 100 !== 0) || y % 400 === 0;
// Monday of the week (reward_ledger weeks start Monday)
export function addDaysIso(iso, n) { const d = new Date(iso + 'T00:00:00Z'); d.setUTCDate(d.getUTCDate() + n); return d.toISOString().slice(0, 10); }
export function mondayOf(iso) { const d = new Date(iso + 'T00:00:00Z'); const dow = (d.getUTCDay() + 6) % 7; d.setUTCDate(d.getUTCDate() - dow); return d.toISOString().slice(0, 10); }
// The date a yearly MM-DD falls on in `year` (Feb 29 → Feb 28 in non-leap years)
export function occursOn(isoDate, year) {
  const md = String(isoDate).slice(5, 10);
  if (md === '02-29' && !isLeap(year)) return `${year}-02-28`;
  return `${year}-${md}`;
}
export function yearsSince(isoDate, today) {
  const y = Number(today.slice(0, 4)) - Number(String(isoDate).slice(0, 4));
  return occursOn(isoDate, Number(today.slice(0, 4))) <= today ? y : y - 1;
}
// Pure: what should be celebrated on `today` for this staff member
export function occasionsFor(s, today) {
  const year = Number(today.slice(0, 4)), out = [];
  if (s.birth_date && occursOn(s.birth_date, year) === today) out.push({ kind: 'birthday' });
  if (s.hire_date && s.hire_date < today && occursOn(s.hire_date, year) === today) {
    const years = yearsSince(s.hire_date, today);
    if (years >= 1) out.push({ kind: 'workiversary', years });
  }
  return out;
}
// Pure: staff whose last day has passed
export const isPastTerm = (s, today) => !!s.termination_date && s.termination_date < today;

const hash = s => { let h = 0; for (const c of String(s)) h = (h * 31 + c.charCodeAt(0)) | 0; return Math.abs(h); };
const BDAY = [
  n => `🎂 *HAPPY BIRTHDAY, ${n}!* 🎉\nThank you for every overnight shift you show up for. We hope this year brings you as much joy as you bring the team. Enjoy your day, Bayani! 🥳`,
  n => `🎉 *Happy Birthday, ${n}!* 🎂\nAnother year wiser, still the heart of the night shift. Wishing you good health, big blessings and a well-deserved rest. 💛`,
  n => `🥳 *It's ${n}'s birthday today!* 🎂\nPlease join us in greeting our Bayani! Thank you for your hard work and good vibes. Have the best day! 🎈`,
  n => `🎈 *Maligayang Kaarawan, ${n}!* 🎂\nSalamat sa sipag at malasakit mo sa team. May your wishes all come true this year! 🙏`,
  n => `🎂 *Happy Birthday, ${n}!* ✨\nWe're lucky to have you on the team. Celebrate big today — you've earned it! 🎉`
];
const WIV = [
  (n, y, d) => `🏆 *HAPPY WORKIVERSARY, ${n}!* 🎉\n*${y} year${y > 1 ? 's' : ''}* with SMB VS today (since ${d}). Thank you for your dedication and for always having the team's back. Here's to many more! 💪`,
  (n, y, d) => `🎉 *Happy ${y}-year Workiversary, ${n}!* 🏆\nSince ${d}, you've been showing up for our clients night after night. Salamat, Bayani! 🙌`,
  (n, y, d) => `🥇 *${y} year${y > 1 ? 's' : ''} and counting — Happy Workiversary, ${n}!* 🎉\nThank you for your loyalty and hard work since ${d}. We're proud to have you on the team! 💛`,
  (n, y, d) => `🏆 *Happy Workiversary, ${n}!* 🎊\nToday marks *${y} year${y > 1 ? 's' : ''}* with SMB Virtual Staffing (since ${d}). Cheers to your growth and to many more years together! 🥂`
];
const niceDate = iso => new Intl.DateTimeFormat('en-US', { timeZone: 'UTC', month: 'short', day: '2-digit', year: 'numeric' }).format(new Date(iso + 'T00:00:00Z'));

// When celebration tokens can be claimed into BINGO: the Monday 07:00 PHT after the occasion's week (same as rw_claim_state)
export function claimOpensAt(occasionIso) { return new Date(addDaysIso(mondayOf(occasionIso), 7) + 'T07:00:00+08:00'); }
const niceDay = iso => new Intl.DateTimeFormat('en-US', { timeZone: 'UTC', weekday: 'short', month: 'short', day: 'numeric' }).format(new Date(iso + 'T00:00:00Z'));

export function celebrationMessage(kind, name, mention, today, extra = {}) {
  const who = mention || name;
  const occasion = extra.occasion || today;
  const pick = (list, salt) => list[hash(salt + occasion) % list.length];
  const body = kind === 'birthday'
    ? pick(BDAY, name)(who)
    : pick(WIV, name)(who, extra.years, niceDate(extra.hire_date));
  const late = occasion < today;
  const belated = late ? `_(Belated greeting for ${niceDay(occasion)} — sorry we're late!)_\n` : '';
  const text0 = late ? body.replace(' today (since', ' (since').replace('Today marks', 'This week marks').replace("birthday today!", 'birthday!').replace('Enjoy your day', 'Hope you had a great day') : body;
  const opens = claimOpensAt(occasion);
  const when = Date.now() >= opens.getTime()
    ? 'Claim them into BINGO now in *My Tokens*.'
    : `They're in *My Tokens* and can be claimed into BINGO from *${niceDay(addDaysIso(mondayOf(occasion), 7))}, 7 AM PHT*.`;
  const text = `${belated}${text0}\n🎁 *+${TOKENS} SMB tokens* for you! ${when}`;
  return {
    text: (kind === 'birthday' ? 'Happy Birthday, ' : 'Happy Workiversary, ') + name + '!',
    blocks: [
      { type: 'section', text: { type: 'mrkdwn', text } },
      { type: 'context', elements: [{ type: 'mrkdwn', text: '— From all of us at SMB Virtual Staffing' }] }
    ]
  };
}

export function registerCelebrations(ctx) {
  const { app, admin, requireAdmin, sendSlackOnce, safeSlack, slackUserIdFor, SLACK_BOT_TOKEN, SLACK_GENERAL_WEBHOOK_URL } = ctx;
  const stats = { last: null, lastError: null, lastErrorAt: null, deactivated: 0, awarded: 0, posted: 0, checked: 0, skippedRunning: 0 };
  let running = false, runningSince = 0;
  const noteError = (where, e) => { const m = `${where}: ${e && e.message || e}`; console.error('Celebrations', m); stats.lastError = m; stats.lastErrorAt = new Date().toISOString(); };

  async function mentionFor(s) {
    if (!SLACK_BOT_TOKEN || !s.email) return null;
    try { const id = await slackUserIdFor(s.email); return id ? `<@${id}>` : null; } catch { return null; }
  }

  async function autoDeactivate(today) {
    const { data, error } = await admin.from('staff').select('id, full_name, termination_date')
      .eq('active', true).or('role.is.null,role.neq.admin').not('termination_date', 'is', null).lt('termination_date', today);
    if (error) throw error;
    for (const s of data || []) {
      const { error: e } = await admin.from('staff').update({ active: false }).eq('id', s.id).eq('active', true);
      if (e) { console.error('Auto-deactivate failed for', s.full_name, e.message); continue; }
      stats.deactivated++;
      console.log(`Auto-deactivated ${s.full_name} (last day ${s.termination_date})`);
    }
  }

  async function celebrate(today) {
    // [2026-11-17 fix] .or(role is null / not admin): .neq('role','admin') alone silently drops staff whose role is blank
    const { data: staff, error } = await admin.from('staff')
      .select('id, full_name, email, role, active, birth_date, hire_date, termination_date').eq('active', true).or('role.is.null,role.neq.admin');
    if (error) throw error;
    stats.checked = (staff || []).length;
    const days = []; for (let i = CATCHUP_DAYS; i >= 0; i--) days.push(addDaysIso(today, -i));
    for (const s of staff || []) {
      for (const day of days) {
        if (s.termination_date && s.termination_date < day) continue;
        for (const o of occasionsFor(s, day)) {
          try { await award(s, o, day, today); } catch (e) { noteError(`${o.kind} ${s.full_name} ${day}`, e); }
        }
      }
    }
  }

  async function award(s, o, day, today) {
    // 1) tokens first — unique (staff_id, kind, occasion_date) makes this safe to repeat
    const { error: insErr } = await admin.from('celebration_awards').insert({
      staff_id: s.id, kind: o.kind, occasion_date: day, years: o.years || null, tokens: TOKENS, week_start: mondayOf(day)
    });
    if (insErr && insErr.code !== '23505') throw insErr;
    if (!insErr) { stats.awarded++; console.log(`Celebration award: ${o.kind} ${s.full_name} ${day}`); }
    // 2) Slack once (a failed post is retried on the next sweep for up to CATCHUP_DAYS)
    if (!SLACK_GENERAL_WEBHOOK_URL) throw new Error('SLACK_GENERAL_WEBHOOK_URL is not set on Render');
    const payload = celebrationMessage(o.kind, safeSlack(s.full_name, 80), await mentionFor(s), today, { years: o.years, hire_date: s.hire_date, occasion: day });
    const r = await sendSlackOnce({ eventKey: `celebrate:${o.kind}:${s.id}:${day}`, destination: 'general', eventType: o.kind, entityId: s.id, webhook: SLACK_GENERAL_WEBHOOK_URL, payload });
    if (r.sent) {
      stats.posted++;
      await admin.from('celebration_awards').update({ slack_posted_at: new Date().toISOString() }).eq('staff_id', s.id).eq('kind', o.kind).eq('occasion_date', day);
    }
  }

  async function sweep() {
    if (running && Date.now() - runningSince < STUCK_MS) { stats.skippedRunning++; return { skipped: 'running' }; }
    running = true; runningSince = Date.now();
    try {
      const today = phToday();
      // [2026-11-17 fix] separate try blocks: a failure in auto-hide no longer stops birthdays/workiversaries
      try { await autoDeactivate(today); } catch (e) { noteError('auto-deactivate', e); }
      await celebrate(today);
      stats.last = new Date().toISOString();
      return { ok: true, ...stats };
    } catch (e) {
      noteError('sweep', e);
      return { ok: false, error: e.message };
    } finally { running = false; }
  }

  // admin: status + this month's upcoming list (also used to sanity-check after deploy)
  app.get('/api/celebrations/status', async (req, res) => {
    try {
      if (!(await requireAdmin(req, res))) return;
      const today = phToday();
      const { data: awards } = await admin.from('celebration_awards').select('staff_id, kind, occasion_date, years, tokens, slack_posted_at').gte('occasion_date', today.slice(0, 7) + '-01').order('occasion_date');
      res.json({ ok: true, today, tz: TZ, tokens: TOKENS, webhook: !!SLACK_GENERAL_WEBHOOK_URL, ...stats, awards: awards || [] });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  return { sweep, stats };
}
