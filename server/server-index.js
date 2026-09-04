// ============================================================
// SMB TIME - small helper server (deploy this folder on Render)
// It keeps privileged Supabase operations and Slack webhook secrets off the browser.
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
  SLACK_GENERAL_WEBHOOK_URL = '',
  SLACK_PAYROLL_WEBHOOK_URL = '',
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

// Keep notification traffic bounded if a browser tab or account is abused. This in-memory
// limiter is per Render instance; delivery-log idempotency remains the authoritative
// duplicate guard across instances/restarts.
const notificationRate=new Map();
function notificationRateLimit(req,res,next){
  const token=(req.headers.authorization||'').slice(-32);
  const key=(req.ip||'unknown')+':'+token;
  const now=Date.now(),windowMs=60*1000,max=120;
  let bucket=notificationRate.get(key);
  if(!bucket||now-bucket.started>=windowMs){bucket={started:now,count:0};notificationRate.set(key,bucket);}
  bucket.count++;
  if(notificationRate.size>1000){
    for(const [k,v] of notificationRate) if(now-v.started>windowMs*2) notificationRate.delete(k);
  }
  if(bucket.count>max) return res.status(429).json({error:'Too many notification checks. Please wait a minute.'});
  next();
}
app.use('/api/slack',notificationRateLimit);


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
  // The Staff form collects these; they used to be dropped on the floor here, so every new
  // hire landed with no hire date, no birthday and a 0 monthly rate until someone re-typed
  // them in the staff table. USD Rate is an optional manually entered hourly rate.
  const hire_date      = body?.hire_date  || null;
  const birth_date     = body?.birth_date || null;
  const monthly_rate   = body?.monthly_rate != null && body.monthly_rate !== '' ? Number(body.monthly_rate) : 0;
  const usd_hourly_rate = body?.usd_hourly_rate != null && body.usd_hourly_rate !== '' ? Number(body.usd_hourly_rate) : 0;
  if (!full_name || !username || !email) return { error: 'Name, username and email are required.' };
  if (!/^[a-z0-9._-]+$/.test(username)) return { error: 'Username can only contain letters, numbers, dots, dashes and underscores.' };
  if (!/^[^\s,@]+@[^\s,@]+\.[^\s,@]+$/.test(email)) return { error: 'That email address does not look valid.' };

  // Two plain equality checks instead of an interpolated .or() filter: a value containing a
  // comma or parenthesis used to be parsed as extra PostgREST filter syntax.
  const { data: dupeUser } = await admin.from('staff').select('id').eq('username', username).maybeSingle();
  const { data: dupeMail } = await admin.from('staff').select('id').eq('email', email).maybeSingle();
  if (dupeUser || dupeMail) return { error: 'That username or email already exists.' };

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
    .insert({ id: userId, full_name, username, email, client_id, role, hire_date, birth_date, monthly_rate, usd_hourly_rate });
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
  const { data: row } = await admin.from('staff').select('id, full_name, role, active').eq('id', u.user.id).single();
  if (!row || row.role !== 'admin' || !row.active) { res.status(403).json({ error: 'Admins only.' }); return null; }
  return row;
}


// --- helper: active logged-in staff (used by Slack routes) ----------------
async function requireActiveUser(req, res) {
  const token = (req.headers.authorization || '').replace('Bearer ', '').trim();
  if (!token) { res.status(401).json({ error: 'Not logged in.' }); return null; }
  const { data: u, error } = await admin.auth.getUser(token);
  if (error || !u?.user) { res.status(401).json({ error: 'Session expired, please log in again.' }); return null; }
  const { data: row, error: rowErr } = await admin.from('staff')
    .select('id, full_name, client_id, active').eq('id', u.user.id).single();
  if (rowErr || !row || !row.active) { res.status(403).json({ error: 'This staff account is inactive.' }); return null; }
  return { user: u.user, row };
}

const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
const uuidRe = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const BREAK_ACTIVITIES = ['15min Break','30min Break','60min Break','Personal Break','Bio Break'];
function safeSlack(value, max=500){
  /* Values are inserted inside mrkdwn fields. Escape link/mention syntax and neutralize
     formatting characters so a staff-entered reason cannot create mentions or formatting. */
  return String(value ?? '').slice(0,max)
    .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/@/g,'＠')
    .replace(/\*/g,'＊').replace(/_/g,'＿').replace(/~/g,'～').replace(/`/g,'｀');
}
function phtDateTime(value){
  return new Intl.DateTimeFormat('en-US',{timeZone:'Asia/Manila',month:'short',day:'numeric',year:'numeric',hour:'numeric',minute:'2-digit',hour12:true}).format(new Date(value))+' PHT';
}
function phtDate(value){
  return new Intl.DateTimeFormat('en-US',{timeZone:'Asia/Manila',month:'short',day:'numeric',year:'numeric'}).format(new Date(value));
}
function peso(value){
  return new Intl.NumberFormat('en-PH',{style:'currency',currency:'PHP',minimumFractionDigits:2}).format(Number(value||0));
}
function inclusiveDays(start,end){
  return Math.max(1,Math.round((Date.parse(end+'T00:00:00Z')-Date.parse(start+'T00:00:00Z'))/86400000)+1);
}
function slackPayload(title, fields, context, reason='', reasonLabel='Reason / note'){
  const blocks=[
    {type:'header',text:{type:'plain_text',text:title,emoji:true}},
    {type:'section',fields:fields.map(([label,value])=>({type:'mrkdwn',text:`*${safeSlack(label,80)}:*\n${safeSlack(value)}`}))}
  ];
  if(reason) blocks.push({type:'section',text:{type:'mrkdwn',text:`*${safeSlack(reasonLabel,80)}:*\n${safeSlack(reason,1200)}`}});
  if(context) blocks.push({type:'context',elements:[{type:'mrkdwn',text:safeSlack(context,500)}]});
  const fallback=fields.map(([k,v])=>`${k}: ${v}`).join(' | ');
  return {text:safeSlack(`${title} — ${fallback}`,2500),blocks};
}
async function clientName(clientId){
  if(!clientId) return 'Unassigned';
  const {data}=await admin.from('clients').select('name').eq('id',clientId).maybeSingle();
  return data?.name || 'Unassigned';
}
async function postSlackWebhook(url,payload){
  if(!url) throw new Error('Slack webhook is not configured on Render.');
  let lastError;
  for(let attempt=1;attempt<=3;attempt++){
    try{
      const response=await fetch(url,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});
      const text=await response.text();
      if(response.ok && text.trim()==='ok') return;
      lastError=new Error(`Slack returned ${response.status}${text?`: ${text.slice(0,160)}`:''}`);
      if(response.status===429){
        const wait=Math.max(1200,Number(response.headers.get('retry-after')||1)*1000);
        await sleep(wait); continue;
      }
      if(response.status<500) break;
    }catch(e){lastError=e;}
    if(attempt<3) await sleep(1200*attempt);
  }
  throw lastError || new Error('Slack notification failed.');
}
async function claimNotification(eventKey,destination,eventType,entityId){
  const now=new Date().toISOString();
  const row={event_key:eventKey,destination,event_type:eventType,entity_id:String(entityId),status:'sending',attempts:1,claimed_at:now,updated_at:now};
  const {error}=await admin.from('slack_notification_log').insert(row);
  if(!error) return {claimed:true};
  if(error.code!=='23505') throw error;
  const {data:existing,error:readErr}=await admin.from('slack_notification_log').select('*').eq('event_key',eventKey).single();
  if(readErr) throw readErr;
  if(existing.status==='sent') return {claimed:false,duplicate:true};
  const stale=existing.status==='sending' && (Date.now()-new Date(existing.claimed_at).getTime()>5*60*1000);
  if(existing.status!=='failed'&&!stale) return {claimed:false,processing:true};
  let q=admin.from('slack_notification_log').update({status:'sending',attempts:Number(existing.attempts||0)+1,claimed_at:now,last_error:null,updated_at:now})
    .eq('event_key',eventKey).eq('status',existing.status);
  if(stale) q=q.eq('claimed_at',existing.claimed_at);
  const {data:claimed,error:claimErr}=await q.select('event_key');
  if(claimErr) throw claimErr;
  return {claimed:!!claimed?.length,processing:!claimed?.length};
}
async function sendSlackOnce({eventKey,destination,eventType,entityId,webhook,payload}){
  if(!webhook) throw new Error(`The ${destination} Slack webhook is not configured on Render.`);
  const claim=await claimNotification(eventKey,destination,eventType,entityId);
  if(!claim.claimed) return {sent:false,...claim};
  try{
    await postSlackWebhook(webhook,payload);
    const now=new Date().toISOString();
    await admin.from('slack_notification_log').update({status:'sent',sent_at:now,last_error:null,updated_at:now}).eq('event_key',eventKey);
    return {sent:true};
  }catch(e){
    await admin.from('slack_notification_log').update({status:'failed',last_error:String(e.message||e).slice(0,1000),updated_at:new Date().toISOString()}).eq('event_key',eventKey);
    throw e;
  }
}
function unionMinutes(entries,nowMs=Date.now()){
  const intervals=entries.map(e=>[new Date(e.started_at).getTime(),e.ended_at?new Date(e.ended_at).getTime():nowMs])
    .filter(([s,t])=>Number.isFinite(s)&&Number.isFinite(t)&&t>s).sort((a,b)=>a[0]-b[0]);
  const merged=[];
  for(const iv of intervals){const last=merged[merged.length-1];if(last&&iv[0]<=last[1])last[1]=Math.max(last[1],iv[1]);else merged.push(iv.slice());}
  return merged.reduce((sum,[s,t])=>sum+(t-s),0)/60000;
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

// --- 4b. set a new password (admin can type one, or leave blank for a random temp one) ---
app.post('/api/staff/:id/temp-password', async (req, res) => {
  if (!(await requireAdmin(req, res))) return;
  const custom = (req.body && req.body.password) ? String(req.body.password) : '';
  if (custom && custom.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters.' });
  const temp = custom || tempPassword();
  const { error } = await admin.auth.admin.updateUserById(req.params.id, { password: temp, email_confirm: true });
  if (error) return res.status(400).json({ error: error.message });
  res.json({ ok: true, temp_password: temp });
});


// --- 5. Slack: manual activity selection -> SMB general ------------------
app.post('/api/slack/activity', async (req, res) => {
  try{
    const caller=await requireActiveUser(req,res); if(!caller) return;
    const entryId=String(req.body?.entry_id||'');
    if(!uuidRe.test(entryId)) return res.status(400).json({error:'Valid entry_id required.'});
    const {data:entry,error}=await admin.from('entries').select('id, staff_id, activity, started_at').eq('id',entryId).single();
    if(error||!entry) return res.status(404).json({error:'Activity entry not found.'});
    if(entry.staff_id!==caller.user.id) return res.status(403).json({error:'You can only notify your own activity.'});
    const client=await clientName(caller.row.client_id);
    const payload=slackPayload('🕒 SMB Time Activity',[
      ['Staff',caller.row.full_name],['Client',client],['Activity',entry.activity],['Started',phtDateTime(entry.started_at)]
    ],'Posted automatically by SMB Time');
    const result=await sendSlackOnce({eventKey:`activity:${entry.id}`,destination:'SMB general',eventType:'activity',entityId:entry.id,webhook:SLACK_GENERAL_WEBHOOK_URL,payload});
    res.json({ok:true,...result});
  }catch(e){console.error('Slack activity notification failed:',e);res.status(502).json({error:e.message||'Slack notification failed.'});}
});

// --- 6. Slack: PTO/advance request -> payroll-and-sheet ------------------
app.post('/api/slack/request', async (req, res) => {
  try{
    const caller=await requireActiveUser(req,res); if(!caller) return;
    const requestId=String(req.body?.request_id||'');
    if(!uuidRe.test(requestId)) return res.status(400).json({error:'Valid request_id required.'});
    const {data:r,error}=await admin.from('requests').select('*').eq('id',requestId).single();
    if(error||!r) return res.status(404).json({error:'Request not found.'});
    if(r.staff_id!==caller.user.id) return res.status(403).json({error:'You can only notify your own request.'});
    const typeLabel={pto:'Paid Time Off',salary_advance:'Salary Advance',cash_advance:'Cash Advance'}[r.type];
    if(!typeLabel) return res.status(400).json({error:'Unsupported request type.'});
    const client=await clientName(caller.row.client_id);
    const fields=[['Staff',caller.row.full_name],['Client',client],['Request',typeLabel]];
    if(r.type==='pto'){
      fields.push(['Dates',`${phtDate(r.start_date+'T00:00:00+08:00')} – ${phtDate(r.end_date+'T00:00:00+08:00')}`],['Requested',`${inclusiveDays(r.start_date,r.end_date)} calendar day(s)`]);
    }else{
      fields.push(['Amount',peso(r.amount)],['Repayment',`${Number(r.cutoffs||0)} cutoff(s)`]);
    }
    fields.push(['Submitted',phtDateTime(r.created_at)]);
    const payload=slackPayload(`🧾 New ${typeLabel} Request`,fields,'Status: Pending admin review',r.reason||'');
    const result=await sendSlackOnce({eventKey:`request:${r.id}`,destination:'payroll-and-sheet',eventType:'request',entityId:r.id,webhook:SLACK_PAYROLL_WEBHOOK_URL,payload});
    res.json({ok:true,...result});
  }catch(e){console.error('Slack request notification failed:',e);res.status(502).json({error:e.message||'Slack notification failed.'});}
});

// --- 7. Slack: rejected PTO/advance request -> payroll-and-sheet ----------
app.post('/api/slack/request-rejected', async (req, res) => {
  try{
    const adminRow=await requireAdmin(req,res); if(!adminRow) return;
    const requestId=String(req.body?.request_id||'');
    if(!uuidRe.test(requestId)) return res.status(400).json({error:'Valid request_id required.'});
    const {data:r,error}=await admin.from('requests').select('*').eq('id',requestId).single();
    if(error||!r) return res.status(404).json({error:'Request not found.'});
    if(r.status!=='rejected'||!String(r.rejection_reason||'').trim()){
      return res.status(409).json({error:'The request must be rejected with a reason before notifying payroll.'});
    }
    const typeLabel={pto:'Paid Time Off',salary_advance:'Salary Advance',cash_advance:'Cash Advance'}[r.type];
    if(!typeLabel) return res.status(400).json({error:'Unsupported request type.'});
    const {data:staff,error:staffErr}=await admin.from('staff')
      .select('id, full_name, client_id').eq('id',r.staff_id).single();
    if(staffErr||!staff) return res.status(404).json({error:'Request staff account not found.'});
    const client=await clientName(staff.client_id);
    const fields=[['Staff',staff.full_name],['Client',client],['Request',typeLabel]];
    if(r.type==='pto'){
      fields.push(['Dates',`${phtDate(r.start_date+'T00:00:00+08:00')} – ${phtDate(r.end_date+'T00:00:00+08:00')}`],['Requested',`${inclusiveDays(r.start_date,r.end_date)} calendar day(s)`]);
    }else{
      fields.push(['Amount',peso(r.amount)],['Repayment',`${Number(r.cutoffs||0)} cutoff(s)`]);
    }
    fields.push(['Rejected by',adminRow.full_name||'Admin'],['Reviewed',phtDateTime(r.reviewed_at||new Date())]);
    const payload=slackPayload(`❌ ${typeLabel} Request Rejected`,fields,'Status: Rejected',r.rejection_reason,'Rejection reason');
    const result=await sendSlackOnce({eventKey:`request-rejected:${r.id}`,destination:'payroll-and-sheet',eventType:'request',entityId:r.id,webhook:SLACK_PAYROLL_WEBHOOK_URL,payload});
    res.json({ok:true,...result});
  }catch(e){console.error('Slack rejection notification failed:',e);res.status(502).json({error:e.message||'Slack notification failed.'});}
});

// --- 8. Slack: first overbreak per shift/activity -> payroll-and-sheet ----
app.post('/api/slack/overbreaks', async (req, res) => {
  try{
    const caller=await requireActiveUser(req,res); if(!caller) return;
    const shiftId=String(req.body?.shift_id||'');
    if(!uuidRe.test(shiftId)) return res.status(400).json({error:'Valid shift_id required.'});
    const {data:shift,error:shiftErr}=await admin.from('shifts').select('id, staff_id, login_at, logout_at').eq('id',shiftId).single();
    if(shiftErr||!shift) return res.status(404).json({error:'Shift not found.'});
    if(shift.staff_id!==caller.user.id) return res.status(403).json({error:'You can only check your own shift.'});
    const [{data:setting,error:setErr},{data:entries,error:entryErr}]=await Promise.all([
      admin.from('settings').select('value').eq('key','break_allowance_minutes').maybeSingle(),
      admin.from('entries').select('activity, started_at, ended_at').eq('shift_id',shiftId).in('activity',BREAK_ACTIVITIES)
    ]);
    if(setErr||entryErr) throw setErr||entryErr;
    const allowances=setting?.value||{};
    const client=await clientName(caller.row.client_id);
    const crossed=[];
    for(const activity of BREAK_ACTIVITIES){
      const cap=Number(allowances[activity]||0);
      if(cap<=0) continue; // current app semantics: zero means unlimited/no deduction
      const used=unionMinutes((entries||[]).filter(e=>e.activity===activity));
      if(used<=cap) continue;
      const usedRounded=Math.ceil(used),overRounded=Math.max(1,Math.ceil(used-cap));
      const payload=slackPayload('⚠️ SMB Time Overbreak Alert',[
        ['Staff',caller.row.full_name],['Client',client],['Activity',activity],['Allowance',`${cap} min`],['Used',`${usedRounded} min`],['Over by',`${overRounded} min`]
      ],`Shift: ${phtDate(shift.login_at)} PHT · First alert for this activity in this shift`);
      const result=await sendSlackOnce({eventKey:`overbreak:${shift.id}:${activity}`,destination:'payroll-and-sheet',eventType:'overbreak',entityId:shift.id,webhook:SLACK_PAYROLL_WEBHOOK_URL,payload});
      crossed.push({activity,...result});
      if(result.sent) await sleep(1200); // Slack incoming webhooks may drop bursts faster than ~1/sec
    }
    res.json({ok:true,crossed});
  }catch(e){console.error('Slack overbreak notification failed:',e);res.status(502).json({error:e.message||'Slack notification failed.'});}
});

// --- 9. Slack: auto force-logout after 10h shift cap -> payroll-and-sheet --
app.post('/api/slack/force-logout', async (req, res) => {
  try{
    const caller=await requireActiveUser(req,res); if(!caller) return;
    const shiftId=String(req.body?.shift_id||'');
    if(!uuidRe.test(shiftId)) return res.status(400).json({error:'Valid shift_id required.'});
    const {data:shift,error}=await admin.from('shifts').select('id, staff_id, login_at, logout_at').eq('id',shiftId).single();
    if(error||!shift) return res.status(404).json({error:'Shift not found.'});
    if(shift.staff_id!==caller.user.id) return res.status(403).json({error:'You can only notify your own shift.'});
    if(!shift.logout_at) return res.status(409).json({error:'Shift is not closed yet.'});
    const client=await clientName(caller.row.client_id);
    const durationMin=Math.round((new Date(shift.logout_at)-new Date(shift.login_at))/60000);
    const payload=slackPayload('⏰ SMB Time Auto Force-Logout (10h cap)',[
      ['Staff',caller.row.full_name],['Client',client],['Shift start',phtDateTime(shift.login_at)],['Auto logout',phtDateTime(shift.logout_at)],['Total shift time',`${Math.floor(durationMin/60)}h ${durationMin%60}m`]
    ],'Staff exceeded 10 hours on shift without selecting Overtime — auto logged out by SMB Time.');
    const result=await sendSlackOnce({eventKey:`force-logout:${shift.id}`,destination:'payroll-and-sheet',eventType:'force-logout',entityId:shift.id,webhook:SLACK_PAYROLL_WEBHOOK_URL,payload});
    res.json({ok:true,...result});
  }catch(e){console.error('Slack force-logout notification failed:',e);res.status(502).json({error:e.message||'Slack notification failed.'});}
});

app.listen(PORT, () => console.log('SMB Time server listening on ' + PORT));
