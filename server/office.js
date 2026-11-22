// ============================================================
// SMB VS PORTAL — Office Necessities (2026-11-23, Rendy)
// Staff ask for supplies (dishwashing liquid, hand soap…) and report broken items
// (chairs, PCs…). Supply requests for the same item MERGE into one open row
// (people are added as "me too"), so admin never sees duplicates. "Can't work"
// repairs DM the admins at once; closing an item DMs everyone who asked and can
// log the cost to SMBVS Expense. Table: office_requests (supabase/office.sql).
// ============================================================
import { randomUUID } from 'crypto';

const OPEN = ['requested', 'ordered', 'fixing'];
const URG_RANK = { low: 1, out: 2, minor: 1, fix: 2, cant: 3 };

export function registerOffice(ctx) {
  const { app, admin, requireAdmin, requireActiveUser, sendDmOnce, dmBlocks, PORTAL_URL, upload, BUCKET } = ctx;
  const bad = m => Object.assign(new Error(m), { status: 400 });
  const fail = (res, e) => { console.error('office:', e); res.status(e.status || 500).json({ error: e.message || 'Office request failed.' }); };
  const short = n => { const p = String(n || '').trim().split(/\s+/); return p.length > 1 ? `${p[0]} ${p[p.length - 1][0]}.` : (p[0] || '—'); };
  const clean = (v, n = 500) => String(v ?? '').trim().slice(0, n);
  const nowIso = () => new Date().toISOString();
  const phDay = () => new Date().toLocaleDateString('en-CA', { timeZone: 'Asia/Manila' });

  async function staffMap(ids) {
    const u = [...new Set(ids.filter(Boolean))];
    if (!u.length) return {};
    const { data } = await admin.from('staff').select('id, full_name, email, active').in('id', u);
    return Object.fromEntries((data || []).map(s => [s.id, s]));
  }
  async function dmAdmins(key, lines) {
    const { data: admins } = await admin.from('staff').select('id, full_name, email').eq('role', 'admin').eq('active', true);
    for (const a of admins || []) { try { await sendDmOnce({ eventKey: `${key}:${a.id}`, entityId: a.id, staff: a, text: lines[0].replace(/\*/g, ''), blocks: dmBlocks(lines, `<${PORTAL_URL}|Open the SMB Portal> → Requests → Office Necessities`) }); } catch (_) {} }
  }

  // ---------- staff ----------
  // Everyone sees the open board (so nobody asks twice) + their own history.
  app.get('/api/office/board', async (req, res) => {
    try {
      const caller = await requireActiveUser(req, res); if (!caller) return;
      const me = caller.user.id;
      const { data: open } = await admin.from('office_requests').select('*').in('status', OPEN).order('created_at', { ascending: false });
      const { data: mine } = await admin.from('office_requests').select('*').or(`requester_id.eq.${me},plus_ids.cs.{${me}}`).order('created_at', { ascending: false }).limit(50);
      const S = await staffMap([...(open || []), ...(mine || [])].map(r => r.requester_id));
      const view = r => ({ id: r.id, kind: r.kind, item: r.item, label: r.label, location: r.location, urgency: r.urgency, status: r.status, eta: r.eta,
        created_at: r.created_at, closed_at: r.closed_at, close_note: r.close_note, by: short(S[r.requester_id]?.full_name), plus: (r.plus_ids || []).length,
        mine: r.requester_id === me, joined: (r.plus_ids || []).includes(me), details: r.requester_id === me ? r.details : undefined,
        my_note: r.requester_id === me ? ((r.notes || [])[0]?.note || '') : undefined });
      res.json({ ok: true, open: (open || []).map(view), mine: (mine || []).map(view) });
    } catch (e) { fail(res, e); }
  });

  app.post('/api/office/request', async (req, res) => {
    try {
      const caller = await requireActiveUser(req, res); if (!caller) return;
      const me = caller.user.id, who = caller.row.full_name;
      const b = req.body || {};
      const kind = b.kind === 'repair' ? 'repair' : 'supply';
      let item = clean(b.item, 60), label = clean(b.label, 80);
      if (!item || !label) throw bad('Pick an item.');
      if (item === 'other') { if (!clean(b.other_text, 80)) throw bad('Type what you need.'); label = clean(b.other_text, 80); item = 'other:' + label.toLowerCase().replace(/[^a-z0-9]+/g, '-'); }
      const urgency = kind === 'supply' ? (b.urgency === 'out' ? 'out' : 'low') : (['cant', 'fix', 'minor'].includes(b.urgency) ? b.urgency : 'fix');
      const entry = { by: me, urgency, qty: clean(b.qty, 60), note: clean(b.note, 500), at: nowIso() };

      if (kind === 'supply' && !b.force_new) {
        const { data: ex } = await admin.from('office_requests').select('*').eq('kind', 'supply').eq('item', item).in('status', OPEN).order('created_at', { ascending: true }).limit(1);
        const row = ex?.[0];
        if (row) {
          const plus = row.requester_id === me || (row.plus_ids || []).includes(me) ? row.plus_ids : [...(row.plus_ids || []), me];
          const upd = { plus_ids: plus, notes: [...(row.notes || []), entry], updated_at: nowIso() };
          if ((URG_RANK[urgency] || 0) > (URG_RANK[row.urgency] || 0)) upd.urgency = urgency;
          const { error } = await admin.from('office_requests').update(upd).eq('id', row.id); if (error) throw error;
          return res.json({ ok: true, merged: true, id: row.id });
        }
      }
      const ins = { kind, item, label, urgency, requester_id: me, notes: [entry], location: kind === 'repair' ? clean(b.location, 120) : null,
        details: kind === 'repair' ? clean(b.details, 1500) : null };
      if (kind === 'repair' && !ins.details) throw bad("Tell us what's wrong.");
      const { data: row, error } = await admin.from('office_requests').insert(ins).select().single(); if (error) throw error;
      if (kind === 'repair' && urgency === 'cant') {
        await dmAdmins(`office-cant:${row.id}`, [`🚨 *Can't work: ${label}${ins.location ? ' — ' + ins.location : ''}*`, `Reported by ${who}: ${ins.details}`]);
      }
      res.json({ ok: true, merged: false, id: row.id });
    } catch (e) { fail(res, e); }
  });

  // optional photo for a repair the caller reported
  app.post('/api/office/photo', upload.single('file'), async (req, res) => {
    try {
      const caller = await requireActiveUser(req, res); if (!caller) return;
      const id = req.body?.id;
      if (!req.file) throw bad('No photo.');
      if (!/^image\//.test(req.file.mimetype || '')) throw bad('Photos only (JPG, PNG, HEIC).');
      if (req.file.size > 10 * 1024 * 1024) throw bad('Photo is over 10 MB.');
      const { data: row } = await admin.from('office_requests').select('requester_id').eq('id', id).maybeSingle();
      if (!row || row.requester_id !== caller.user.id) throw bad('Not your report.');
      const ext = (req.file.originalname.split('.').pop() || 'jpg').toLowerCase().replace(/[^a-z0-9]/g, '').slice(0, 5) || 'jpg';
      const path = `office/${id}/${Date.now()}-${randomUUID()}.${ext}`;
      const { error: upErr } = await admin.storage.from(BUCKET).upload(path, req.file.buffer, { contentType: req.file.mimetype, upsert: false });
      if (upErr) throw upErr;
      await admin.from('office_requests').update({ photo_path: path, updated_at: nowIso() }).eq('id', id);
      res.json({ ok: true });
    } catch (e) { fail(res, e); }
  });

  app.post('/api/office/metoo', async (req, res) => {
    try {
      const caller = await requireActiveUser(req, res); if (!caller) return;
      const me = caller.user.id;
      const { data: row } = await admin.from('office_requests').select('requester_id, plus_ids, status').eq('id', req.body?.id).maybeSingle();
      if (!row || !OPEN.includes(row.status)) throw bad('That item is already closed.');
      if (row.requester_id === me || (row.plus_ids || []).includes(me)) return res.json({ ok: true, already: true });
      const { error } = await admin.from('office_requests').update({ plus_ids: [...(row.plus_ids || []), me], updated_at: nowIso() }).eq('id', req.body.id); if (error) throw error;
      res.json({ ok: true });
    } catch (e) { fail(res, e); }
  });

  // requester cancels (only while nobody else joined and it's still "requested")
  app.post('/api/office/cancel', async (req, res) => {
    try {
      const caller = await requireActiveUser(req, res); if (!caller) return;
      const me = caller.user.id;
      const { data: row } = await admin.from('office_requests').select('requester_id, plus_ids, status').eq('id', req.body?.id).maybeSingle();
      if (!row) throw bad('Not found.');
      if (row.requester_id !== me) {
        if ((row.plus_ids || []).includes(me)) { await admin.from('office_requests').update({ plus_ids: row.plus_ids.filter(x => x !== me), updated_at: nowIso() }).eq('id', req.body.id); return res.json({ ok: true, left: true }); }
        throw bad('Not your request.');
      }
      if (row.status !== 'requested') throw bad('Already being handled — message Sir Rendy instead.');
      if ((row.plus_ids || []).length) throw bad('Others need this too, so it stays open.');
      await admin.from('office_requests').update({ status: 'cancelled', closed_at: nowIso(), updated_at: nowIso() }).eq('id', req.body.id);
      res.json({ ok: true });
    } catch (e) { fail(res, e); }
  });

  // ---------- admin ----------
  app.get('/api/office/admin', async (req, res) => {
    try {
      const caller = await requireAdmin(req, res); if (!caller) return;
      const since = new Date(Date.now() - 62 * 864e5).toISOString();
      const { data: open } = await admin.from('office_requests').select('*').in('status', OPEN);
      const { data: closed } = await admin.from('office_requests').select('*').not('status', 'in', `(${OPEN.join(',')})`).gte('closed_at', since).order('closed_at', { ascending: false });
      const rows = [...(open || []), ...(closed || [])];
      const S = await staffMap(rows.flatMap(r => [r.requester_id, ...(r.plus_ids || [])]));
      const out = await Promise.all(rows.map(async r => {
        let photo_url = null;
        if (r.photo_path) { const { data } = await admin.storage.from(BUCKET).createSignedUrl(r.photo_path, 3600); photo_url = data?.signedUrl || null; }
        return { ...r, photo_url, requester: S[r.requester_id]?.full_name || '—', plus: (r.plus_ids || []).map(id => S[id]?.full_name || '—'),
          notes: (r.notes || []).map(n => ({ ...n, by_name: S[n.by]?.full_name || '—' })) };
      }));
      res.json({ ok: true, rows: out, today: phDay() });
    } catch (e) { fail(res, e); }
  });

  app.post('/api/office/admin/status', async (req, res) => {
    try {
      const caller = await requireAdmin(req, res); if (!caller) return;
      const b = req.body || {};
      const allowed = ['requested', 'ordered', 'fixing', 'done', 'replaced', 'declined'];
      if (!allowed.includes(b.status)) throw bad('Unknown status.');
      const { data: row } = await admin.from('office_requests').select('*').eq('id', b.id).maybeSingle();
      if (!row) throw bad('Not found.');
      const closing = ['done', 'replaced', 'declined'].includes(b.status);
      const cost = b.cost === '' || b.cost == null ? null : Number(b.cost);
      if (cost != null && (!Number.isFinite(cost) || cost < 0)) throw bad('Cost must be a number.');
      const upd = { status: b.status, updated_at: nowIso() };
      if (b.status === 'ordered') upd.eta = /^\d{4}-\d{2}-\d{2}$/.test(b.eta || '') ? b.eta : null;
      if (cost != null) upd.cost = cost;
      if (closing) Object.assign(upd, { closed_at: nowIso(), closed_by: caller.id, close_note: clean(b.close_note, 500) || null });
      // optional: log the cost to SMBVS Expense (once)
      if (closing && b.log_expense && cost > 0 && !row.expense_id) {
        const { data: ex, error: exErr } = await admin.from('smbvs_expenses').insert({ spent_on: phDay(), category: row.kind === 'supply' ? 'supplies' : 'other',
          description: `${row.kind === 'supply' ? 'Office supplies' : 'Repair'}: ${row.label}${row.location ? ' — ' + row.location : ''}`, amount: cost, receipt_path: null }).select('id').single();
        if (exErr) throw Object.assign(new Error('Saved nothing — could not log the expense: ' + exErr.message), { status: 500 });
        upd.expense_id = ex.id;
      }
      const { error } = await admin.from('office_requests').update(upd).eq('id', b.id); if (error) throw error;
      // tell everyone who asked
      if (closing || b.status === 'ordered' || b.status === 'fixing') {
        const S = await staffMap([row.requester_id, ...(row.plus_ids || [])]);
        const verb = { done: row.kind === 'supply' ? 'restocked ✅' : 'fixed ✅', replaced: 'replaced ✅', declined: 'closed', ordered: `ordered${upd.eta ? ' — arriving ' + upd.eta : ''} 🛒`, fixing: 'being fixed 🛠️' }[b.status];
        for (const s of Object.values(S).filter(x => x.active)) {
          try { await sendDmOnce({ eventKey: `office-${b.status}:${row.id}:${s.id}`, entityId: s.id, staff: s, text: `${row.label}: ${verb}`,
            blocks: dmBlocks([`🧴 *${row.label}${row.location ? ' — ' + row.location : ''}* is ${verb}`, ...(upd.close_note ? [upd.close_note] : [])], `<${PORTAL_URL}|SMB Portal> → Request → Office Necessities`) }); } catch (_) {}
        }
      }
      res.json({ ok: true, expense_logged: !!upd.expense_id });
    } catch (e) { fail(res, e); }
  });
}
