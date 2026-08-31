// ============================================================
// SMB TIME - small helper server (deploy this folder on Render)
// It does only the things the browser is NOT allowed to do:
//   1. turn a username into an email so staff can log in with a username
//   2. create staff accounts (email invite OR instant temporary password)
//   2b. create many staff at once from a pasted list
//   3. deactivate / delete staff
//   4. send a password reset email
// ============================================================
import express from 'express';
import cors from 'cors';
import { createClient } from '@supabase/supabase-js';

const {
  SUPABASE_URL,
  SUPABASE_SERVICE_ROLE_KEY,
  ALLOWED_ORIGIN = '*',
  APP_URL = '',
  PORT = 10000
} = process.env;

if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) {
  console.error('Missing SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY environment variables.');
}

// service-role client = full access. NEVER expose this key in the browser.
const admin = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
  auth: { autoRefreshToken: false, persistSession: false }
});

const app = express();
app.use(express.json());
app.use(cors({ origin: ALLOWED_ORIGIN === '*' ? true : ALLOWED_ORIGIN.split(',').map(s => s.trim()) }));

app.get('/', (_req, res) => res.send('SMB Time server is running.'));
app.get('/health', (_req, res) => res.json({ ok: true }));


// --- helper: readable temporary password --------------------------------
function tempPassword(){
  const letters = 'ABCDEFGHJKLMNPQRSTUVWXYZ';     // no I or O
  const digits  = '23456789';                      // no 0 or 1
  const pick = (set, n) => Array.from({length:n}, () => set[Math.floor(Math.random()*set.length)]).join('');
  return 'SMB-' + pick(letters,4) + '-' + pick(digits,4);
}

// --- helper: create one staff member ------------------------------------
// mode 'password' works even when email sending is broken or rate-limited.
async function createOneStaff(body, mode){
  const full_name = String(body?.full_name || '').trim();
  const username  = String(body?.username || '').trim().toLowerCase();
  const email     = String(body?.email || '').trim().toLowerCase();
  const client_id = body?.client_id || null;
  const role      = body?.role === 'admin' ? 'admin' : 'staff';
  const hire_date = body?.hire_date || null;
  const birth_date = body?.birth_date || null;
  const monthly_rate = body?.monthly_rate != null && body.monthly_rate !== '' ? Number(body.monthly_rate) : 0;
  if (!full_name || !username || !email) return { error: 'Name, username and email are required.' };

  const { data: dupe } = await admin.from('staff').select('id')
    .or(`username.eq.${username},email.eq.${email}`).maybeSingle();
  if (dupe) return { error: 'That username or email already exists.' };

  let userId, temp = null;
  if (mode === 'password') {
    temp = tempPassword();
    const { data, error } = await admin.auth.admin.createUser({
      email, password: temp, email_confirm: true, user_metadata: { full_name, username }
    });
    if (error) return { error: 'Could not create login: ' + error.message };
    userId = data.user.id;
  } else {
    const { data, error } = await admin.auth.admin.inviteUserByEmail(email, {
      redirectTo: APP_URL || undefined, data: { full_name, username }
    });
    if (error) return { error: 'Could not send invite: ' + error.message };
    userId = data.user.id;
  }

  const { error: insErr } = await admin.from('staff')
    .insert({ id: userId, full_name, username, email, client_id, role, hire_date, birth_date, monthly_rate });
  if (insErr) {
    await admin.auth.admin.deleteUser(userId); // roll back so nothing is half-created
    return { error: 'Could not save staff row: ' + insErr.message };
  }
  return { ok: true, id: userId, temp_password: temp };
}

// --- helper: make sure the caller is a logged-in admin -------------------
async function requireAdmin(req, res) {
  const token = (req.headers.authorization || '').replace('Bearer ', '').trim();
  if (!token) { res.status(401).json({ error: 'Not logged in.' }); return null; }
  const { data: u, error } = await admin.auth.getUser(token);
  if (error || !u?.user) { res.status(401).json({ error: 'Session expired, please log in again.' }); return null; }
  const { data: row } = await admin.from('staff').select('id, role, active').eq('id', u.user.id).single();
  if (!row || row.role !== 'admin' || !row.active) { res.status(403).json({ error: 'Admins only.' }); return null; }
  return row;
}

// --- 1. username -> email (used by the login screen) --------------------
app.post('/api/resolve-username', async (req, res) => {
  const username = String(req.body?.username || '').trim().toLowerCase();
  if (!username) return res.status(400).json({ error: 'Username required.' });
  const { data } = await admin.from('staff').select('email, active').eq('username', username).maybeSingle();
  if (!data || !data.active) return res.status(404).json({ error: 'Username not found.' });
  res.json({ email: data.email });
});

// --- 2. create ONE staff account ----------------------------------------
// body.mode: 'password' (instant, no email) or 'invite' (emails a setup link)
app.post('/api/staff', async (req, res) => {
  if (!(await requireAdmin(req, res))) return;
  const mode = req.body?.mode === 'invite' ? 'invite' : 'password';
  const r = await createOneStaff(req.body, mode);
  if (r.error) return res.status(400).json({ error: r.error });
  res.json(r);
});

// --- 2b. create MANY staff at once --------------------------------------
// body.rows = [{full_name, username, email, client_id, role}, ...]
// Always uses temporary passwords, so it never depends on email delivery.
app.post('/api/staff/bulk', async (req, res) => {
  if (!(await requireAdmin(req, res))) return;
  const rows = Array.isArray(req.body?.rows) ? req.body.rows : [];
  if (!rows.length) return res.status(400).json({ error: 'No rows sent.' });
  if (rows.length > 100) return res.status(400).json({ error: 'Maximum 100 people at a time.' });
  const results = [];
  for (const row of rows) {
    const r = await createOneStaff(row, 'password');
    results.push({
      full_name: row.full_name, username: row.username, email: row.email,
      ok: !!r.ok, temp_password: r.temp_password || '', error: r.error || ''
    });
  }
  res.json({ results });
});

// --- 3a. deactivate (keeps their history) --------------------------------
app.post('/api/staff/:id/deactivate', async (req, res) => {
  if (!(await requireAdmin(req, res))) return;
  const { error } = await admin.from('staff').update({ active: false }).eq('id', req.params.id);
  if (error) return res.status(400).json({ error: error.message });
  res.json({ ok: true });
});

app.post('/api/staff/:id/reactivate', async (req, res) => {
  if (!(await requireAdmin(req, res))) return;
  const { error } = await admin.from('staff').update({ active: true }).eq('id', req.params.id);
  if (error) return res.status(400).json({ error: error.message });
  res.json({ ok: true });
});

// --- 3b. delete for good (also deletes their time records) ---------------
app.delete('/api/staff/:id', async (req, res) => {
  if (!(await requireAdmin(req, res))) return;
  const { error } = await admin.auth.admin.deleteUser(req.params.id); // staff row cascades
  if (error) return res.status(400).json({ error: error.message });
  res.json({ ok: true });
});

// --- 4. password reset email --------------------------------------------
app.post('/api/staff/:id/reset-password', async (req, res) => {
  if (!(await requireAdmin(req, res))) return;
  const { data: row } = await admin.from('staff').select('email').eq('id', req.params.id).single();
  if (!row) return res.status(404).json({ error: 'Staff not found.' });
  const { error } = await admin.auth.resetPasswordForEmail(row.email, { redirectTo: APP_URL || undefined });
  if (error) return res.status(400).json({ error: error.message });
  res.json({ ok: true });
});

// --- 4b. set a NEW temporary password (no email needed) ------------------
app.post('/api/staff/:id/temp-password', async (req, res) => {
  if (!(await requireAdmin(req, res))) return;
  const temp = tempPassword();
  const { error } = await admin.auth.admin.updateUserById(req.params.id, { password: temp, email_confirm: true });
  if (error) return res.status(400).json({ error: error.message });
  res.json({ ok: true, temp_password: temp });
});

app.listen(PORT, () => console.log('SMB Time server listening on ' + PORT));
