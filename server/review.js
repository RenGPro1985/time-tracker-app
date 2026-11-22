// ============================================================
// SMB VS PORTAL — Annual Service Review (2026-11-22, Rendy)
// Tables: review_cycles, review_participants, review_submissions (supabase/review.sql).
// Phases come from the cycle dates (PHT), so the cycle "just works" once created:
//   before self_open → setup · self_open..self_due → open (self + peer forms)
//   after self_due → scoring (admin) · results show to each contractor once released.
// Peer feedback is anonymous: the person reviewed only ever gets averages and
// shuffled comments; reviewer ids never leave the server for peer content.
// Scores are computed in the browser (same formula the admin sees) and stored.
// ============================================================
const CRIT_ALL = ['quality', 'comm', 'own', 'team', 'client', 'growth'];
const CRIT_PEER = ['quality', 'comm', 'own', 'team'];
const DEF_BANDS = [{ min: 4.5, name: 'Outstanding', pct: 10 }, { min: 3.75, name: 'Exceeds', pct: 5 }, { min: 3, name: 'Meets', pct: 3 }, { min: 0, name: 'Developing', pct: 0 }];
const DEF_WEIGHTS = { admin: 0.5, peer: 0.2, self: 0.1, rel: 0.2 };

export function registerReview(ctx) {
  const { app, admin, requireAdmin, requireActiveUser, sendDmOnce, dmBlocks, PORTAL_URL } = ctx;
  const today = () => new Date().toLocaleDateString('en-CA', { timeZone: 'Asia/Manila' });
  const phaseOf = c => { const t = today(); return t < c.self_open ? 'setup' : t <= c.self_due ? 'open' : 'scoring'; };
  const shuffle = a => { const x = a.slice(); for (let i = x.length - 1; i > 0; i--) { const j = Math.floor(Math.random() * (i + 1)); [x[i], x[j]] = [x[j], x[i]]; } return x; };
  const avg = a => a.length ? a.reduce((s, v) => s + v, 0) / a.length : null;
  const r2 = n => n == null ? null : Math.round(n * 100) / 100;
  const fail = (res, e, code = 500) => { console.error('review:', e); res.status(e.status || code).json({ error: e.message || 'Review request failed.' }); };
  const bad = msg => Object.assign(new Error(msg), { status: 400 });
  const cleanRatings = (r, keys) => Object.fromEntries(keys.filter(k => [1, 2, 3, 4, 5].includes(Number(r?.[k]))).map(k => [k, Number(r[k])]));
  const cleanText = (o, keys) => Object.fromEntries(keys.map(k => [k, String(o?.[k] ?? '').slice(0, 4000)]));

  async function currentCycle() {
    const { data, error } = await admin.from('review_cycles').select('*').order('year', { ascending: false }).limit(1);
    if (error) throw error;
    return data?.[0] || null;
  }
  // Peer averages + shuffled comments for one reviewee (anonymous shape)
  function peerSummary(subs, revieweeId) {
    const p = subs.filter(s => s.kind === 'peer' && s.reviewee_id === revieweeId && s.status === 'submitted' && !s.declined);
    const per = Object.fromEntries(CRIT_PEER.map(k => [k, r2(avg(p.map(s => s.ratings?.[k]).filter(Number.isFinite)))]));
    const overall = r2(avg(p.map(s => avg(CRIT_PEER.map(k => s.ratings?.[k]).filter(Number.isFinite))).filter(v => v != null)));
    const strengths = shuffle(p.map(s => (s.answers?.strength || '').trim()).filter(Boolean));
    const improve = shuffle(p.map(s => (s.answers?.improve || '').trim()).filter(Boolean));
    return { count: p.length, per, overall, strengths, improve };
  }

  // ---------------- staff ----------------
  app.get('/api/review/me', async (req, res) => {
    try {
      const caller = await requireActiveUser(req, res); if (!caller) return;
      const me = caller.user.id, c = await currentCycle();
      if (!c) return res.json({ ok: true, cycle: null });
      const phase = phaseOf(c);
      const { data: part } = await admin.from('review_participants').select('*').eq('cycle_id', c.id).eq('staff_id', me).maybeSingle();
      const { data: all } = await admin.from('review_participants').select('staff_id, peers').eq('cycle_id', c.id);
      const assigned = (all || []).filter(p => (p.peers || []).includes(me)).map(p => p.staff_id);
      const { data: mine } = await admin.from('review_submissions').select('*').eq('cycle_id', c.id).eq('reviewer_id', me);
      const ids = [...new Set(assigned)];
      const { data: people } = ids.length ? await admin.from('staff').select('id, full_name, client_id').in('id', ids) : { data: [] };
      const out = {
        ok: true, phase, today: today(),
        cycle: { year: c.year, self_open: c.self_open, self_due: c.self_due, admin_due: c.admin_due, ack_due: c.ack_due, fee_effective: c.fee_effective, bands: c.bands, weights: c.weights },
        participant: !!part, review_type: part?.review_type || null,
        self: (mine || []).find(s => s.kind === 'self') || null,
        peers: (people || []).map(p => ({ id: p.id, full_name: p.full_name, sub: (mine || []).find(s => s.kind === 'peer' && s.reviewee_id === p.id) || null }))
      };
      if (part?.released_at) {
        const { data: subs } = await admin.from('review_submissions').select('kind, reviewee_id, ratings, answers, status, declined').eq('cycle_id', c.id).eq('reviewee_id', me);
        const ps = peerSummary(subs || [], me);
        out.result = {
          final_score: part.final_score, band: part.band, increase_pct: part.increase_pct, current_rate: part.current_rate, new_rate: part.new_rate,
          admin_ratings: part.admin_ratings, admin_summary: part.admin_summary, released_at: part.released_at,
          peer: { count: ps.count, per: ps.per, strengths: ps.strengths, improve: ps.improve },
          self: ((subs || []).find(s => s.kind === 'self') || {}).ratings || null,
          ack_status: part.ack_status, ack_note: part.ack_note, ack_at: part.ack_at, admin_reply: part.admin_reply
        };
      }
      res.json(out);
    } catch (e) { fail(res, e); }
  });

  app.post('/api/review/submit', async (req, res) => {
    try {
      const caller = await requireActiveUser(req, res); if (!caller) return;
      const me = caller.user.id, c = await currentCycle();
      if (!c) throw bad('No review cycle yet.');
      if (phaseOf(c) !== 'open') throw bad(`The review window is ${c.self_open} to ${c.self_due}.`);
      const { kind, reviewee_id, ratings, answers, final, declined } = req.body || {};
      if (!['self', 'peer'].includes(kind)) throw bad('Unknown review type.');
      const target = kind === 'self' ? me : reviewee_id;
      if (kind === 'self') {
        const { data: part } = await admin.from('review_participants').select('staff_id').eq('cycle_id', c.id).eq('staff_id', me).maybeSingle();
        if (!part) throw bad('You are not part of this review cycle.');
      } else {
        const { data: part } = await admin.from('review_participants').select('peers').eq('cycle_id', c.id).eq('staff_id', target).maybeSingle();
        if (!part || !(part.peers || []).includes(me)) throw bad('You were not asked to give feedback on this person.');
      }
      const { data: prev } = await admin.from('review_submissions').select('status').eq('cycle_id', c.id).eq('kind', kind).eq('reviewer_id', me).eq('reviewee_id', target).maybeSingle();
      if (prev?.status === 'submitted') throw bad('Already submitted.');
      const keys = kind === 'self' ? CRIT_ALL : CRIT_PEER;
      const r = cleanRatings(ratings, keys);
      const a = cleanText(answers, kind === 'self' ? ['wins', 'improve', 'goals'] : ['strength', 'improve']);
      const isDecl = kind === 'peer' && !!declined;
      if (final && !isDecl && Object.keys(r).length !== keys.length) throw bad('Please rate every item before submitting.');
      const row = { cycle_id: c.id, kind, reviewer_id: me, reviewee_id: target, ratings: isDecl ? {} : r, answers: isDecl ? {} : a, declined: isDecl,
        status: final ? 'submitted' : 'draft', submitted_at: final ? new Date().toISOString() : null, updated_at: new Date().toISOString() };
      const { error } = await admin.from('review_submissions').upsert(row, { onConflict: 'cycle_id,kind,reviewer_id,reviewee_id' });
      if (error) throw error;
      res.json({ ok: true });
    } catch (e) { fail(res, e); }
  });

  app.post('/api/review/ack', async (req, res) => {
    try {
      const caller = await requireActiveUser(req, res); if (!caller) return;
      const me = caller.user.id, c = await currentCycle();
      if (!c) throw bad('No review cycle.');
      const { action, note } = req.body || {};
      if (!['acknowledged', 'reconsideration'].includes(action)) throw bad('Unknown action.');
      if (action === 'reconsideration' && !String(note || '').trim()) throw bad('Please tell us why you are asking for reconsideration.');
      const { data: part } = await admin.from('review_participants').select('released_at, ack_status').eq('cycle_id', c.id).eq('staff_id', me).maybeSingle();
      if (!part?.released_at) throw bad('Your review has not been released yet.');
      if (part.ack_status === 'acknowledged') throw bad('Already acknowledged.');
      const { error } = await admin.from('review_participants').update({ ack_status: action, ack_note: String(note || '').slice(0, 4000) || null, ack_at: new Date().toISOString(), updated_at: new Date().toISOString() }).eq('cycle_id', c.id).eq('staff_id', me);
      if (error) throw error;
      res.json({ ok: true });
    } catch (e) { fail(res, e); }
  });

  // ---------------- admin ----------------
  app.get('/api/review/admin', async (req, res) => {
    try {
      const caller = await requireAdmin(req, res); if (!caller) return;
      const c = await currentCycle();
      if (!c) return res.json({ ok: true, cycle: null });
      const [{ data: parts }, { data: subs }] = await Promise.all([
        admin.from('review_participants').select('*').eq('cycle_id', c.id),
        admin.from('review_submissions').select('kind, reviewer_id, reviewee_id, ratings, answers, status, declined, submitted_at').eq('cycle_id', c.id)
      ]);
      const S = subs || [];
      const participants = (parts || []).map(p => {
        const self = S.find(s => s.kind === 'self' && s.reviewee_id === p.staff_id) || null;
        const ps = peerSummary(S, p.staff_id);
        const declinedN = S.filter(s => s.kind === 'peer' && s.reviewee_id === p.staff_id && s.status === 'submitted' && s.declined).length;
        return { ...p, self: self ? { status: self.status, ratings: self.status === 'submitted' ? self.ratings : null, answers: self.status === 'submitted' ? self.answers : null } : null, peer: { ...ps, declined: declinedN } };
      });
      // progress per reviewer (counts only — never which feedback is whose)
      const progress = {};
      for (const p of parts || []) {
        progress[p.staff_id] = progress[p.staff_id] || { self: null, peer_assigned: 0, peer_done: 0 };
        for (const r of p.peers || []) { progress[r] = progress[r] || { self: null, peer_assigned: 0, peer_done: 0 }; progress[r].peer_assigned++; }
      }
      for (const s of S) {
        if (!progress[s.reviewer_id]) continue;
        if (s.kind === 'self') progress[s.reviewer_id].self = s.status;
        else if (s.status === 'submitted') progress[s.reviewer_id].peer_done++;
      }
      res.json({ ok: true, phase: phaseOf(c), today: today(), cycle: c, participants, progress });
    } catch (e) { fail(res, e); }
  });

  // create the cycle (or update its dates/bands while nobody has submitted)
  app.post('/api/review/admin/cycle', async (req, res) => {
    try {
      const caller = await requireAdmin(req, res); if (!caller) return;
      const b = req.body || {};
      const d = k => { if (!/^\d{4}-\d{2}-\d{2}$/.test(b[k] || '')) throw bad(`${k} must be a date.`); return b[k]; };
      const row = { year: Number(b.year), self_open: d('self_open'), self_due: d('self_due'), admin_due: d('admin_due'), ack_due: d('ack_due'),
        fee_effective: d('fee_effective'), tenure_asof: d('tenure_asof'), fx: Number(b.fx || 60) || 60,
        bands: Array.isArray(b.bands) && b.bands.length ? b.bands : DEF_BANDS, weights: b.weights || DEF_WEIGHTS };
      if (!(row.year > 2020)) throw bad('Year is required.');
      if (!(row.self_open <= row.self_due && row.self_due <= row.admin_due && row.admin_due <= row.ack_due)) throw bad('Dates must run in order: open ≤ due ≤ admin ≤ acknowledge.');
      const { data: ex } = await admin.from('review_cycles').select('id').eq('year', row.year).maybeSingle();
      let cycle;
      if (ex) { const { data, error } = await admin.from('review_cycles').update(row).eq('id', ex.id).select().single(); if (error) throw error; cycle = data; }
      else { const { data, error } = await admin.from('review_cycles').insert({ ...row, created_by: caller.id }).select().single(); if (error) throw error; cycle = data; }
      // participants: insert missing (never removes or overwrites existing rows)
      const list = Array.isArray(b.participants) ? b.participants : [];
      if (list.length) {
        const { data: have } = await admin.from('review_participants').select('staff_id').eq('cycle_id', cycle.id);
        const has = new Set((have || []).map(x => x.staff_id));
        const add = list.filter(p => p.staff_id && !has.has(p.staff_id)).map(p => ({ cycle_id: cycle.id, staff_id: p.staff_id, review_type: p.review_type === 'dev' ? 'dev' : 'annual', peers: (p.peers || []).filter(x => x && x !== p.staff_id).slice(0, 5) }));
        if (add.length) { const { error } = await admin.from('review_participants').insert(add); if (error) throw error; }
      }
      res.json({ ok: true, cycle });
    } catch (e) { fail(res, e); }
  });

  // edit one participant's peers / review type, or remove them from the cycle
  app.post('/api/review/admin/participant', async (req, res) => {
    try {
      const caller = await requireAdmin(req, res); if (!caller) return;
      const c = await currentCycle(); if (!c) throw bad('No review cycle.');
      const { staff_id, peers, review_type, remove } = req.body || {};
      if (remove) { const { error } = await admin.from('review_participants').delete().eq('cycle_id', c.id).eq('staff_id', staff_id); if (error) throw error; return res.json({ ok: true }); }
      const upd = { updated_at: new Date().toISOString() };
      if (Array.isArray(peers)) upd.peers = peers.filter(x => x && x !== staff_id).slice(0, 5);
      if (review_type) upd.review_type = review_type === 'dev' ? 'dev' : 'annual';
      const { data: ex } = await admin.from('review_participants').select('staff_id').eq('cycle_id', c.id).eq('staff_id', staff_id).maybeSingle();
      const q = ex ? admin.from('review_participants').update(upd).eq('cycle_id', c.id).eq('staff_id', staff_id)
        : admin.from('review_participants').insert({ cycle_id: c.id, staff_id, review_type: upd.review_type || 'annual', peers: upd.peers || [] });
      const { error } = await q; if (error) throw error;
      res.json({ ok: true });
    } catch (e) { fail(res, e); }
  });

  // admin saves ratings + computed score (finalize locks it for release)
  app.post('/api/review/admin/score', async (req, res) => {
    try {
      const caller = await requireAdmin(req, res); if (!caller) return;
      const c = await currentCycle(); if (!c) throw bad('No review cycle.');
      const b = req.body || {};
      const { data: part } = await admin.from('review_participants').select('released_at').eq('cycle_id', c.id).eq('staff_id', b.staff_id).maybeSingle();
      if (!part) throw bad('Not in this cycle.');
      if (part.released_at && !b.allow_after_release) throw bad('Already released to the contractor.');
      const ov = b.override_pct === '' || b.override_pct == null ? null : Number(b.override_pct);
      if (ov != null && (!Number.isFinite(ov) || ov < 0)) throw bad('Override must be 0% or more (fees never go down).');
      if (ov != null && !String(b.override_reason || '').trim()) throw bad('An override needs a reason.');
      const upd = {
        admin_ratings: cleanRatings(b.admin_ratings, CRIT_ALL), admin_summary: String(b.admin_summary || '').slice(0, 6000), one_on_one: !!b.one_on_one,
        reliability: b.reliability == null ? null : Number(b.reliability), override_pct: ov, override_reason: ov == null ? null : String(b.override_reason).slice(0, 1000),
        final_score: b.final_score == null ? null : Number(b.final_score), band: b.band || null, increase_pct: b.increase_pct == null ? null : Number(b.increase_pct),
        current_rate: b.current_rate == null ? null : Number(b.current_rate), new_rate: b.new_rate == null ? null : Number(b.new_rate),
        finalized_at: b.finalize ? new Date().toISOString() : null, updated_at: new Date().toISOString()
      };
      if (b.finalize && Object.keys(upd.admin_ratings).length !== CRIT_ALL.length) throw bad('Rate all six items before finalizing.');
      const { error } = await admin.from('review_participants').update(upd).eq('cycle_id', c.id).eq('staff_id', b.staff_id);
      if (error) throw error;
      res.json({ ok: true });
    } catch (e) { fail(res, e); }
  });

  app.post('/api/review/admin/release', async (req, res) => {
    try {
      const caller = await requireAdmin(req, res); if (!caller) return;
      const c = await currentCycle(); if (!c) throw bad('No review cycle.');
      const ids = Array.isArray(req.body?.staff_ids) ? req.body.staff_ids : [];
      const { data: parts } = await admin.from('review_participants').select('staff_id, finalized_at, released_at').eq('cycle_id', c.id).in('staff_id', ids);
      const ready = (parts || []).filter(p => p.finalized_at && !p.released_at).map(p => p.staff_id);
      if (!ready.length) return res.json({ ok: true, released: 0 });
      const now = new Date().toISOString();
      const { error } = await admin.from('review_participants').update({ released_at: now, updated_at: now }).eq('cycle_id', c.id).in('staff_id', ready);
      if (error) throw error;
      const { data: people } = await admin.from('staff').select('id, full_name, email').in('id', ready);
      for (const s of people || []) {
        try {
          await sendDmOnce({ eventKey: `review-release:${c.year}:${s.id}`, entityId: s.id, staff: s,
            text: `Your ${c.year} Annual Service Review is ready`,
            blocks: dmBlocks([`🌱 *Your ${c.year} Annual Service Review is ready*`, `Please read it and tap *I acknowledge* (or ask for reconsideration) by *${c.ack_due}*.`], `<${PORTAL_URL}|Open the SMB Portal> → Annual Performance`) });
        } catch (_) {}
      }
      res.json({ ok: true, released: ready.length });
    } catch (e) { fail(res, e); }
  });

  app.post('/api/review/admin/reply', async (req, res) => {
    try {
      const caller = await requireAdmin(req, res); if (!caller) return;
      const c = await currentCycle(); if (!c) throw bad('No review cycle.');
      const { staff_id, reply } = req.body || {};
      const { error } = await admin.from('review_participants').update({ admin_reply: String(reply || '').slice(0, 4000), updated_at: new Date().toISOString() }).eq('cycle_id', c.id).eq('staff_id', staff_id);
      if (error) throw error;
      res.json({ ok: true });
    } catch (e) { fail(res, e); }
  });

  // Slack DM to everyone with an unfinished self review or peer feedback
  app.post('/api/review/admin/remind', async (req, res) => {
    try {
      const caller = await requireAdmin(req, res); if (!caller) return;
      const c = await currentCycle(); if (!c) throw bad('No review cycle.');
      if (phaseOf(c) !== 'open') throw bad('Reminders only go out while the window is open.');
      const [{ data: parts }, { data: subs }] = await Promise.all([
        admin.from('review_participants').select('staff_id, peers').eq('cycle_id', c.id),
        admin.from('review_submissions').select('kind, reviewer_id, reviewee_id, status').eq('cycle_id', c.id)
      ]);
      const todo = {};
      for (const p of parts || []) {
        const selfDone = (subs || []).some(s => s.kind === 'self' && s.reviewer_id === p.staff_id && s.status === 'submitted');
        if (!selfDone) (todo[p.staff_id] = todo[p.staff_id] || { self: true, peers: 0 }).self = true;
        for (const r of p.peers || []) {
          const done = (subs || []).some(s => s.kind === 'peer' && s.reviewer_id === r && s.reviewee_id === p.staff_id && s.status === 'submitted');
          if (!done) (todo[r] = todo[r] || { self: false, peers: 0 }).peers++;
        }
      }
      const ids = Object.keys(todo);
      const { data: people } = ids.length ? await admin.from('staff').select('id, full_name, email, active').in('id', ids) : { data: [] };
      let sent = 0;
      for (const s of (people || []).filter(x => x.active)) {
        const t = todo[s.id], parts2 = [];
        if (t.self) parts2.push('your *self review*'); if (t.peers) parts2.push(`*peer feedback* for ${t.peers} teammate${t.peers === 1 ? '' : 's'}`);
        try {
          const r = await sendDmOnce({ eventKey: `review-remind:${c.year}:${today()}:${s.id}`, entityId: s.id, staff: s, text: 'Annual Service Review reminder',
            blocks: dmBlocks([`🌱 *Annual Service Review — reminder*`, `Still to do: ${parts2.join(' and ')}. Due *${c.self_due}*.`], `<${PORTAL_URL}|Open the SMB Portal> → Annual Performance`) });
          if (r?.sent) sent++;
        } catch (_) {}
      }
      res.json({ ok: true, people: ids.length, sent });
    } catch (e) { fail(res, e); }
  });

  // Apply new contract fees to the roster (only on/after fee_effective; once per person)
  app.post('/api/review/admin/apply', async (req, res) => {
    try {
      const caller = await requireAdmin(req, res); if (!caller) return;
      const c = await currentCycle(); if (!c) throw bad('No review cycle.');
      if (today() < c.fee_effective) throw bad(`New fees can be applied from ${c.fee_effective}.`);
      const { data: parts } = await admin.from('review_participants').select('staff_id, new_rate, current_rate, released_at, applied_at').eq('cycle_id', c.id);
      const todo = (parts || []).filter(p => p.released_at && !p.applied_at && Number(p.new_rate) > Number(p.current_rate || 0));
      let n = 0;
      for (const p of todo) {
        const { data: st } = await admin.from('staff').select('monthly_rate').eq('id', p.staff_id).single();
        if (Number(st?.monthly_rate) >= Number(p.new_rate)) continue; // never lower, never double-apply
        const { error } = await admin.from('staff').update({ monthly_rate: Number(p.new_rate) }).eq('id', p.staff_id);
        if (error) throw error;
        await admin.from('review_participants').update({ applied_at: new Date().toISOString() }).eq('cycle_id', c.id).eq('staff_id', p.staff_id);
        n++;
      }
      res.json({ ok: true, applied: n });
    } catch (e) { fail(res, e); }
  });

  return { phaseOf };
}
