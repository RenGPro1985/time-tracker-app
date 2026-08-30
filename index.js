// ============================================================
// SMB TIME - small helper server (deploy this folder on Render)
// It does only the things the browser is NOT allowed to do:
//   1. turn a username into an email so staff can log in with a username
//   2. create staff accounts + send them a setup email
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

// --- 2. create a staff account + send setup email -----------------------
app.post('/api/staff', async (req, res) => {
  if (!(await requireAdmin(req, res))) return;
  const full_name = String(req.body?.full_name || '').trim();
  const username  = String(req.body?.username || '').trim().toLowerCase();
  const email     = String(req.body?.email || '').trim().toLowerCase();
  const client_id = req.body?.client_id || null;
  const role      = req.body?.role === 'admin' ? 'admin' : 'staff';
  if (!full_name || !username || !email) return res.status(400).json({ error: 'Name, username and email are required.' });

  const { data: dupe } = await admin.from('staff').select('id').or(`username.eq.${username},email.eq.${email}`).maybeSingle();
  if (dupe) return res.status(409).json({ error: 'That username or email already exists.' });

  // invite = creates the auth user and emails them a "set your password" link
  const { data: invited, error: inviteErr } = await admin.auth.admin.inviteUserByEmail(email, {
    redirectTo: APP_URL || undefined,
    data: { full_name, username }
  });
  if (inviteErr) return res.status(400).json({ error: 'Could not send invite: ' + inviteErr.message });

  const { error: insErr } = await admin.from('staff')
    .insert({ id: invited.user.id, full_name, username, email, client_id, role });
  if (insErr) {
    await admin.auth.admin.deleteUser(invited.user.id); // roll back so nothing is half-created
    return res.status(400).json({ error: 'Could not save staff row: ' + insErr.message });
  }
  res.json({ ok: true, id: invited.user.id });
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

app.listen(PORT, () => console.log('SMB Time server listening on ' + PORT));
