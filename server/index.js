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
import multer from 'multer';
import { randomUUID } from 'crypto';

const {
  SUPABASE_URL,
  SUPABASE_SERVICE_ROLE_KEY,
  ALLOWED_ORIGIN = '*',
  APP_URL = '',
  SLACK_GENERAL_WEBHOOK_URL = '',
  SLACK_PAYROLL_WEBHOOK_URL = '',
  PORT = 10000
} = process.env;

const OVERBREAK_GRACE_MIN = 1;   // tolerated overbreak, never flagged
const OVERBREAK_FLAG_MIN  = 2;   // Slack alert only when over the allowance by MORE than this

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
/* Per-instance break policy (2026-09-22): the allowance caps each USE of a break type on
   its own, not the sum of every use in the shift. 15min/30min/60min Break additionally have
   a hard cap on how many separate instances are allowed per shift; any instance beyond that
   gets ZERO allowance (100% of it counts as overbreak), not just the minutes past the cap.
   mergeGapMin: two same-activity entries closer together than this are treated as ONE
   instance (their time is added together, then capped once) — this closes the loophole of
   splitting one break into several short back-to-back punches. Personal/Bio Break have no
   merge rule and no instance-count limit (per-instance cap only, tracked but not capped on
   count). See skills/users/u0bcs577h9q/SKILL.md for the Slack thread that specified this. */
const BREAK_INSTANCE_RULES = {
  '15min Break': { mergeGapMin: 60, maxInstances: 2 },
  '30min Break': { mergeGapMin: 60, maxInstances: 1 },
  '60min Break': { mergeGapMin: 0,  maxInstances: 1 }, // 60min Break is already always 100% non-billable regardless of cap; this only drives alerting/flagging, not pay.
};
/* Groups an activity's raw intervals for one shift into "instances" per BREAK_INSTANCE_RULES,
   merging entries that are less than mergeGapMin apart. Returns instances in chronological
   order, each as {minutes} (union of any sub-intervals in that instance). */
const TINY_BREAK_SEC = 30; // b25 (Rendy 2026-10-24): 15/30/60min Break records shorter than this are accidental taps
function groupBreakInstances(entries, activity, nowMs=Date.now()){
  const rule=BREAK_INSTANCE_RULES[activity]||{};
  const mergeGapMs=(rule.mergeGapMin||0)*60000;
  const ivs=(entries||[]).filter(e=>e.activity===activity)
    .map(e=>[new Date(e.started_at).getTime(), e.ended_at?new Date(e.ended_at).getTime():nowMs])
    .filter(([s,t])=>Number.isFinite(s)&&Number.isFinite(t)&&t>s)
    .filter(([s,t])=>!(BREAK_INSTANCE_RULES[activity]&&(t-s)<TINY_BREAK_SEC*1000)) // b25: accidental taps never count as an instance (matches index.html)
    .sort((a,b)=>a[0]-b[0]);
  const groups=[];
  ivs.forEach(iv=>{
    const g=groups[groups.length-1];
    const gap=g?iv[0]-g[g.length-1][1]:Infinity;
    if(g && (gap<=0||gap<mergeGapMs)) g.push(iv); else groups.push([iv]);
  });
  return groups.map(g=>({ minutes: unionMinutesMs(g) }));
}
function overbreakCandidates(entries, activity, cap){
  const rule=BREAK_INSTANCE_RULES[activity]||{};
  return groupBreakInstances(entries,activity).flatMap((instance,idx)=>{
    const withinLimit=!rule.maxInstances||(idx+1)<=rule.maxInstances;
    if(cap<=0&&withinLimit) return []; // zero means unlimited for allowed instances
    const allowance=withinLimit?cap:0; // excess instances have zero allowance, even if cap is zero
    const over=instance.minutes-allowance;
    if(over<=OVERBREAK_FLAG_MIN) return [];
    return [{instance:idx+1,used:instance.minutes,allowance,over,withinLimit}];
  });
}
function unionMinutesMs(ivsMs){
  const merged=[];
  ivsMs.slice().sort((a,b)=>a[0]-b[0]).forEach(iv=>{const last=merged[merged.length-1];if(last&&iv[0]<=last[1])last[1]=Math.max(last[1],iv[1]);else merged.push(iv.slice());});
  return merged.reduce((sum,[s,t])=>sum+(t-s),0)/60000;
}
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
    const typeLabel={pto:'Paid Time Off',salary_advance:'Salary Advance',cash_advance:'Cash Advance',half_day:'Half Day'}[r.type];
    if(!typeLabel) return res.status(400).json({error:'Unsupported request type.'});
    const client=await clientName(caller.row.client_id);
    const fields=[['Staff',caller.row.full_name],['Client',client],['Request',typeLabel]];
    if(r.type==='half_day'){
      fields.push(['Shift date',phtDate(r.start_date+'T12:00:00+08:00')]);
      if(r.half_part) fields.push(['Half',r.half_part==='first'?'1st half':'2nd half']);
      if(r.late_filing) fields.push(['Filing','⏰ Late filing (more than 24h after the shift)']);
    }else if(r.type==='pto'){
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
    const typeLabel={pto:'Paid Time Off',salary_advance:'Salary Advance',cash_advance:'Cash Advance',half_day:'Half Day'}[r.type];
    if(!typeLabel) return res.status(400).json({error:'Unsupported request type.'});
    const {data:staff,error:staffErr}=await admin.from('staff')
      .select('id, full_name, client_id').eq('id',r.staff_id).single();
    if(staffErr||!staff) return res.status(404).json({error:'Request staff account not found.'});
    const client=await clientName(staff.client_id);
    const fields=[['Staff',staff.full_name],['Client',client],['Request',typeLabel]];
    if(r.type==='half_day'){
      fields.push(['Shift date',phtDate(r.start_date+'T12:00:00+08:00')]);
    }else if(r.type==='pto'){
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

// --- 8. Slack: per-instance overbreak alerts -> SMB general --------------
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
      const rule=BREAK_INSTANCE_RULES[activity]||{};
      for(const candidate of overbreakCandidates(entries||[],activity,cap)){
        const {instance,used,allowance:instanceCap,over,withinLimit}=candidate;
        const usedRounded=Math.ceil(used),overRounded=Math.max(1,Math.ceil(over));
        const label=withinLimit?`Instance ${instance} of ${rule.maxInstances||'∞'} allowed this shift`:`Instance ${instance} exceeds the ${rule.maxInstances} allowed this shift — zero allowance, fully non-billable`;
        const payload=slackPayload('⚠️ SMB Time Overbreak Alert',[
          ['Staff',caller.row.full_name],['Client',client],['Activity',activity],['Allowance',`${instanceCap} min${OVERBREAK_GRACE_MIN?` (+${OVERBREAK_GRACE_MIN} min grace)`:''}`],['Used',`${usedRounded} min`],['Over by',`${overRounded} min`]
        ],`Shift: ${phtDate(shift.login_at)} PHT · ${label} · Checked per-instance, not summed across the shift · Flagged only past ${OVERBREAK_FLAG_MIN} min over`);
        const result=await sendSlackOnce({eventKey:`overbreak:${shift.id}:${activity}:${instance-1}`,destination:'SMB general',eventType:'overbreak',entityId:shift.id,webhook:SLACK_GENERAL_WEBHOOK_URL,payload});
        crossed.push({activity,instance,...result});
        if(result.sent) await sleep(1200); // Slack incoming webhooks may drop bursts faster than ~1/sec
      }
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


// --- 10. Slack: staff log-in / log-out notices -> SMB general (added 2026-10-22) --
// Times come from the SERVER-saved shift row (never the browser clock). One post per
// event: login:<shift_id>, logout:<shift_id> (delivery log dedupes across refreshes).
// Only staff-initiated (manual) log-outs post here; auto 10h + admin/system log-outs
// keep their existing alerts.
const SHIFT_TZ_CLIENT = 'America/New_York';      // all clients are US Eastern
const SHIFT_TZ_REF_DATE = '2026-10-01';          // saved client shift times = US summer-time (EDT) values
const SHIFT_DST_AUTO_FROM = '2026-10-01';        // same switch-on date as the portal (index.html)
const EARLY_LOGIN_GRACE_MIN_SRV = 60;
function tzOffsetMin(tz, at){
  const p={};new Intl.DateTimeFormat('en-US',{timeZone:tz,hourCycle:'h23',year:'numeric',month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit',second:'2-digit'})
    .formatToParts(at).forEach(x=>p[x.type]=x.value);
  const asUtc=Date.UTC(+p.year,+p.month-1,+p.day,+p.hour,+p.minute,+p.second);
  return Math.round((asUtc-at.getTime())/60000);
}
// Auto-DST: when US clocks fall back (Nov), the same US start time is 1h later in PHT.
function dstShiftMin(at){
  return tzOffsetMin(SHIFT_TZ_CLIENT,new Date(SHIFT_TZ_REF_DATE+'T12:00:00Z'))-tzOffsetMin(SHIFT_TZ_CLIENT,at);
}
function phIsoDate(at){return new Intl.DateTimeFormat('en-CA',{timeZone:'Asia/Manila',year:'numeric',month:'2-digit',day:'2-digit'}).format(at);}
function addIsoDays(iso,n){const d=new Date(iso+'T00:00:00Z');d.setUTCDate(d.getUTCDate()+n);return d.toISOString().slice(0,10);}
function srvShiftWindow(client,dateIso){
  if(!client||!client.shift_start||!client.shift_end) return null;
  const pad=t=>String(t).length===5?t+':00':String(t);
  let start=new Date(dateIso+'T'+pad(client.shift_start)+'+08:00');
  let end=new Date(dateIso+'T'+pad(client.shift_end)+'+08:00');
  if(end<=start) end=new Date(end.getTime()+86400000);
  const shiftMs=(dateIso<SHIFT_DST_AUTO_FROM?0:dstShiftMin(start))*60000;  // dates before the switch-on stay exactly as before
  return {start:new Date(start.getTime()+shiftMs),end:new Date(end.getTime()+shiftMs)};
}
function nearestShiftWindow(client,at){
  const d=phIsoDate(at);
  const c=[addIsoDays(d,-1),d,addIsoDays(d,1)].map(x=>srvShiftWindow(client,x)).filter(Boolean);
  if(!c.length) return null;
  return c.reduce((a,b)=>Math.abs(at-a.start)<=Math.abs(at-b.start)?a:b);
}
function phtClock(value){
  return new Intl.DateTimeFormat('en-US',{timeZone:'Asia/Manila',hour:'numeric',minute:'2-digit',hour12:true}).format(new Date(value));
}
function durText(min){min=Math.max(0,Math.round(min));const h=Math.floor(min/60),m=min%60;return h?`${h}h ${m}m`:`${m}m`;}
function noticePayload(lines,fallback){
  return {text:safeSlack(fallback,2500),blocks:lines.filter(Boolean).map(t=>({type:'section',text:{type:'mrkdwn',text:t}}))};
}
/* Shift-date window: a log-in inside the 60-min early grace before TOMORROW's window belongs to
   tomorrow; a log-in after 12MN that falls inside LAST NIGHT's window belongs to last night's
   shift (half day / late log-in); otherwise today's window. Same rule as the portal. [2026-10-23] */
function anchoredShiftWindow(client,at){
  const d=phIsoDate(at);
  const nxt=srvShiftWindow(client,addIsoDays(d,1));
  if(nxt&&at>=new Date(nxt.start.getTime()-EARLY_LOGIN_GRACE_MIN_SRV*60000)) return {...nxt,date:addIsoDays(d,1)};
  const prv=srvShiftWindow(client,addIsoDays(d,-1));
  if(prv&&at>=new Date(prv.start.getTime()-EARLY_LOGIN_GRACE_MIN_SRV*60000)&&at<prv.end) return {...prv,date:addIsoDays(d,-1)};
  const cur=srvShiftWindow(client,d);
  return cur?{...cur,date:d}:null;
}
// Build everything a login/logout notice needs for one shift (route + backfill sweep share this).
async function shiftNoticeData(shift,staffRow){
  let client=null;
  if(staffRow.client_id){
    const {data:c}=await admin.from('clients').select('id, name, shift_start, shift_end').eq('id',staffRow.client_id).maybeSingle();
    client=c||null;
  }
  const win=client?anchoredShiftWindow(client,new Date(shift.login_at)):null;
  // Other shifts of this staff in the same shift-day (window start - 60 min grace .. window end), or last 12h if no client
  const from=win?new Date(win.start.getTime()-EARLY_LOGIN_GRACE_MIN_SRV*60000):new Date(new Date(shift.login_at).getTime()-12*3600000);
  const to=win?win.end:new Date(new Date(shift.login_at).getTime()+12*3600000);
  const {data:sameDay,error:sdErr}=await admin.from('shifts').select('id, login_at, logout_at')
    .eq('staff_id',shift.staff_id).gte('login_at',from.toISOString()).lte('login_at',to.toISOString()).order('login_at',{ascending:true});
  if(sdErr) throw sdErr;
  let halfDay=null;
  if(win){
    const {data:hd}=await admin.from('requests').select('id, status, half_part').eq('staff_id',shift.staff_id).eq('type','half_day').eq('start_date',win.date).neq('status','rejected').limit(1);
    halfDay=(hd&&hd[0])||null;
  }
  return {shift,client,win,sameDay:sameDay||[],halfDay,
    name:safeSlack(staffRow.full_name||'Staff',120),clientName:safeSlack(client?.name||'No client',120),
    NAME:safeSlack(String(staffRow.full_name||'Staff').toUpperCase(),120),CLIENT:safeSlack(String(client?.name||'No client').toUpperCase(),120)};
}
function loginNoticePayload(ctx,{late=false}={}){
  const {shift,win,sameDay,halfDay,name,clientName,NAME,CLIENT}=ctx;
  const login=new Date(shift.login_at);
  const earlier=sameDay.filter(s=>s.id!==shift.id&&new Date(s.login_at)<login);
  const lateNote=late?`📨 _Late notice — the portal did not send this at log-in._`:'';
  if(earlier.length){
    return noticePayload([`↩️ _${name} (${clientName}) logged back in · ${phtClock(login)} PHT_`,lateNote],`${name} (${clientName}) logged back in · ${phtClock(login)} PHT`);
  }
  const lateMin=win?Math.floor((login-win.start)/60000):0;
  const shiftTxt=win?` · Shift ${phtClock(win.start)}–${phtClock(win.end)} PHT`:'';
  const tag=halfDay
    ? `🌓 _Half Day${halfDay.half_part==='first'?' (1st half)':halfDay.half_part==='second'?' (2nd half)':''} filed${halfDay.status==='pending'?' · waiting for Sir Rendy':''}._`
    : (lateMin>=1?`⏰ _Late ${lateMin} min si *${name}* of *${clientName}*, I hope you are okay and that your day gets better._`:'');
  return noticePayload([
    `🎉 *${NAME}* of *${CLIENT}* HAS LOGGED IN for today's awesome shift!\n🕘 Log-in time: *${phtClock(login)} PHT*${shiftTxt}`,
    tag, lateNote
  ],`${name} of ${clientName} HAS LOGGED IN for today's awesome shift! Log-in time: ${phtClock(login)} PHT`+(halfDay?' · Half Day':lateMin>=1?` · Late ${lateMin} min`:''));
}
async function shiftNoticeContext(req,res){
  const caller=await requireActiveUser(req,res); if(!caller) return null;
  const shiftId=String(req.body?.shift_id||'');
  if(!uuidRe.test(shiftId)){res.status(400).json({error:'Valid shift_id required.'});return null;}
  const {data:shift,error}=await admin.from('shifts').select('id, staff_id, login_at, logout_at, logout_reason').eq('id',shiftId).single();
  if(error||!shift){res.status(404).json({error:'Shift not found.'});return null;}
  if(shift.staff_id!==caller.user.id){res.status(403).json({error:'You can only notify your own shift.'});return null;}
  return {caller,...(await shiftNoticeData(shift,caller.row))};
}

app.post('/api/slack/login', async (req, res) => {
  try{
    const ctx=await shiftNoticeContext(req,res); if(!ctx) return;
    const payload=loginNoticePayload(ctx);
    const result=await sendSlackOnce({eventKey:`login:${ctx.shift.id}`,destination:'SMB general',eventType:'activity',entityId:ctx.shift.id,webhook:SLACK_GENERAL_WEBHOOK_URL,payload});
    res.json({ok:true,...result});
  }catch(e){console.error('Slack login notification failed:',e);res.status(502).json({error:e.message||'Slack notification failed.'});}
});

/* Missed log-in notices backfill [Rendy, 2026-10-23]. If a staff member's browser never sent
   the log-in notice (old open tab, closed too fast, network), the server posts it within ~5 min,
   marked as a late notice. Only shifts logged in during the last 14h, at least 3 min ago, with
   NO login:<shift> row in the delivery log at all (a failed post is not retried here), and never
   for shifts an admin added by hand. */
const LOGIN_NOTICE_FLOOR = '2026-10-22T21:40:00Z'; // log-in notices went live Oct 23 05:40 PHT
let loginSweepRunning=false;
async function loginNoticeSweep(){
  if(loginSweepRunning||!SLACK_GENERAL_WEBHOOK_URL) return;
  loginSweepRunning=true;
  try{
    const fromMs=Math.max(Date.now()-14*3600000,new Date(LOGIN_NOTICE_FLOOR).getTime());
    let {data:shifts,error}=await admin.from('shifts').select('id, staff_id, login_at, logout_at, logout_reason, added_by')
      .gte('login_at',new Date(fromMs).toISOString()).lte('login_at',new Date(Date.now()-3*60000).toISOString()).limit(500);
    if(error&&/added_by/.test(error.message||'')){
      ({data:shifts,error}=await admin.from('shifts').select('id, staff_id, login_at, logout_at, logout_reason')
        .gte('login_at',new Date(fromMs).toISOString()).lte('login_at',new Date(Date.now()-3*60000).toISOString()).limit(500));
    }
    if(error) throw error;
    const list=(shifts||[]).filter(sh=>!sh.added_by);
    if(!list.length) return;
    const keys=list.map(sh=>`login:${sh.id}`);
    const {data:logs,error:le}=await admin.from('slack_notification_log').select('event_key').in('event_key',keys);
    if(le) throw le;
    const have=new Set((logs||[]).map(x=>x.event_key));
    const missing=list.filter(sh=>!have.has(`login:${sh.id}`));
    if(!missing.length) return;
    const {data:staff,error:se}=await admin.from('staff').select('id, full_name, client_id, role, active').in('id',[...new Set(missing.map(x=>x.staff_id))]);
    if(se) throw se;
    for(const sh of missing.sort((a,b)=>a.login_at<b.login_at?-1:1)){
      const st=(staff||[]).find(x=>x.id===sh.staff_id); if(!st||!st.active||st.role==='admin') continue;
      try{
        const ctx=await shiftNoticeData(sh,st);
        await sendSlackOnce({eventKey:`login:${sh.id}`,destination:'SMB general',eventType:'activity',entityId:sh.id,webhook:SLACK_GENERAL_WEBHOOK_URL,payload:loginNoticePayload(ctx,{late:true})});
        await sleep(400);
      }catch(e){console.error('Login notice backfill failed for',sh.id,e.message);}
    }
  }catch(e){console.error('Login notice sweep failed:',e.message);}
  finally{loginSweepRunning=false;}
}
setInterval(loginNoticeSweep,5*60*1000);
setTimeout(loginNoticeSweep,30000);

/* Login speed test → SMB General [Rendy, 2026-10-23]. The browser measures the staff member's
   connection right after LOGIN; this posts it once per shift (slack_notification_log key
   speedtest:<shift>). Only for the caller's own open shift, within 15 min of its login. */
function stNum(v, max){ const n=Number(v); return Number.isFinite(n)&&n>=0&&n<=max ? Math.round(n*10)/10 : null; }
app.post('/api/slack/speedtest', async (req, res) => {
  try{
    const ctx=await shiftNoticeContext(req,res); if(!ctx) return;
    const {shift,name,clientName}=ctx;
    if(shift.logout_at) return res.status(409).json({error:'Shift already ended.'});
    if(Date.now()-new Date(shift.login_at).getTime()>15*60000) return res.status(409).json({error:'Speed test window (15 min after login) has passed.'});
    const down=stNum(req.body?.down,10000), up=stNum(req.body?.up,10000), ping=stNum(req.body?.ping,10000), jitter=stNum(req.body?.jitter,10000);
    if(down==null||up==null||ping==null) return res.status(400).json({error:'Invalid speed test result.'});
    const isp=safeSlack(req.body?.isp||'',80), city=safeSlack(req.body?.city||'',60);
    const when=phtClock(new Date())+' PHT';
    const line=`📶 *Speed Test: ${name}* (${clientName})\n⬇️ ${down} Mbps  ·  ⬆️ ${up} Mbps  ·  Ping ${ping} ms${jitter!=null?`  ·  Jitter ${jitter} ms`:''}`;
    const ctxTxt=[isp,city,when].filter(Boolean).join(' · ');
    const payload={text:safeSlack(`Speed Test: ${ctx.caller.row.full_name||'Staff'} (${clientName}) · ${down}↓ / ${up}↑ Mbps · ${ping} ms ping`,2500),
      blocks:[{type:'section',text:{type:'mrkdwn',text:line}},{type:'context',elements:[{type:'mrkdwn',text:ctxTxt}]}]};
    const result=await sendSlackOnce({eventKey:`speedtest:${shift.id}`,destination:'SMB general',eventType:'activity',entityId:shift.id,webhook:SLACK_GENERAL_WEBHOOK_URL,payload});
    res.json({ok:true,...result});
  }catch(e){console.error('Slack speed test notification failed:',e);res.status(502).json({error:e.message||'Slack notification failed.'});}
});

app.post('/api/slack/logout', async (req, res) => {
  try{
    const ctx=await shiftNoticeContext(req,res); if(!ctx) return;
    const {shift,win,sameDay,name,clientName,NAME,CLIENT}=ctx;
    if(!shift.logout_at) return res.status(409).json({error:'Shift is not closed yet.'});
    if(shift.logout_reason&&shift.logout_reason!=='manual') return res.json({ok:true,sent:false,skipped:'not a manual log-out'});
    const out=new Date(shift.logout_at);
    const leftMin=win?Math.floor((win.end-out)/60000):0;
    let payload;
    if(win&&leftMin>=1){
      payload=noticePayload([
        `🚪 *${NAME}* of *${CLIENT}* HAS LOGGED OUT.\n🕘 Log-out time: *${phtClock(out)} PHT* · Shift ends ${phtClock(win.end)} PHT`,
        `⚠️ *${durText(leftMin)} before shift end* — can someone reach out to ${name}?`
      ],`${name} of ${clientName} HAS LOGGED OUT at ${phtClock(out)} PHT — ${durText(leftMin)} before shift end`);
    }else{
      const total=sameDay.filter(s=>s.logout_at).reduce((m,s)=>m+Math.max(0,(new Date(s.logout_at)-new Date(s.login_at))/60000),0);
      payload=noticePayload([
        `👋 *${NAME}* of *${CLIENT}* has logged out. Shift done — salamat!\n🕘 Log-out time: *${phtClock(out)} PHT* · Total logged today: *${durText(total)}*`
      ],`${name} of ${clientName} has logged out at ${phtClock(out)} PHT. Total logged today: ${durText(total)}`);
    }
    const result=await sendSlackOnce({eventKey:`logout:${shift.id}`,destination:'SMB general',eventType:'activity',entityId:shift.id,webhook:SLACK_GENERAL_WEBHOOK_URL,payload});
    res.json({ok:true,...result});
  }catch(e){console.error('Slack logout notification failed:',e);res.status(502).json({error:e.message||'Slack notification failed.'});}
});


// ============================================================
// SMB VS PORTAL — document storage (Supabase Storage) + signatures
// Switched from Google Drive on 2026-09-05: the destination folder lived in
// a personal Gmail account, and Google service accounts always have 0
// storage quota — they can only own files inside a paid Shared Drive or via
// full OAuth delegation. Supabase Storage avoids that entirely (same
// project/creds we already use for the DB, normal quota, no separate auth).
// ============================================================
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 25 * 1024 * 1024 } });
const PORTAL_BUCKET = 'portal-docs';

// --- 9. Portal: admin uploads a document ----------------------------------
// multipart/form-data fields: file, title, category, visibility ('all' or a staff id), requires_signature ('true'/'false')
app.post('/api/portal/upload', upload.single('file'), async (req, res) => {
  try {
    const caller = await requireAdmin(req, res); if (!caller) return;
    const { title, category, visibility, requires_signature } = req.body || {};
    if (!req.file) return res.status(400).json({ error: 'No file uploaded.' });
    if (!title || !category) return res.status(400).json({ error: 'Title and category are required.' });
    const isAll = !visibility || visibility === 'all';

    let targetStaff = null;
    let folderSegment = 'all';
    if (!isAll) {
      const { data: staffRow } = await admin.from('staff').select('id, full_name').eq('id', visibility).single();
      if (!staffRow) return res.status(400).json({ error: 'Selected staff not found.' });
      targetStaff = staffRow;
      folderSegment = staffRow.id;
    }

    const safeName = req.file.originalname.replace(/[^a-zA-Z0-9._-]/g, '_');
    const storagePath = `${folderSegment}/${Date.now()}-${randomUUID()}-${safeName}`;

    const { error: upErr } = await admin.storage.from(PORTAL_BUCKET).upload(storagePath, req.file.buffer, {
      contentType: req.file.mimetype,
      upsert: false
    });
    if (upErr) throw upErr;

    const { data: docRow, error: insErr } = await admin.from('portal_docs').insert({
      title,
      category,
      visibility: isAll ? 'all' : targetStaff.id,
      storage_path: storagePath,
      file_type: req.file.mimetype,
      requires_signature: requires_signature === 'true' || requires_signature === true,
      uploaded_by: caller.id
    }).select().single();
    if (insErr) throw insErr;

    res.json({ ok: true, doc: docRow });
  } catch (e) {
    console.error('Portal upload failed:', e);
    res.status(500).json({ error: e.message || 'Upload failed.' });
  }
});

// --- 10. Portal: list documents (staff sees their own + company-wide; admin sees all) ---
app.get('/api/portal/docs', async (req, res) => {
  try {
    const caller = await requireActiveUser(req, res); if (!caller) return;
    const { data: staffRow } = await admin.from('staff').select('role').eq('id', caller.user.id).single();
    const isAdmin = staffRow?.role === 'admin';

    let query = admin.from('portal_docs').select('*').order('created_at', { ascending: false });
    if (!isAdmin) query = query.or(`visibility.eq.all,visibility.eq.${caller.user.id}`);
    const { data: rawDocs, error } = await query;
    if (error) throw error;

    // Storage is private, so hand back a short-lived signed URL per doc instead
    // of a permanent link. Field stays named `drive_link` so the existing
    // frontend (which just does <a href="${d.drive_link}">) needs no changes.
    const docs = await Promise.all((rawDocs || []).map(async d => {
      let drive_link = null;
      if (d.storage_path) {
        const { data: signed } = await admin.storage.from(PORTAL_BUCKET).createSignedUrl(d.storage_path, 3600);
        drive_link = signed?.signedUrl || null;
      }
      return { ...d, drive_link };
    }));

    const { data: mySigs } = await admin.from('portal_signatures').select('doc_id, signed_at').eq('staff_id', caller.user.id);
    const signedMap = Object.fromEntries((mySigs || []).map(s => [s.doc_id, s.signed_at]));

    if (isAdmin) {
      // attach signature progress per doc that requires signature
      const docIds = docs.filter(d => d.requires_signature).map(d => d.id);
      let sigCounts = {};
      if (docIds.length) {
        const { data: allSigs, error: sigErr } = await admin.from('portal_signatures').select('doc_id, staff_id, signed_at').in('doc_id', docIds);
        if (sigErr) throw sigErr;
        for (const s of allSigs || []) (sigCounts[s.doc_id] = sigCounts[s.doc_id] || []).push(s);
      }
      // Active staff only: inactive staff are neither counted as eligible nor as signed.
      const { data: activeStaff, error: staffErr } = await admin.from('staff').select('id, full_name, hire_date').eq('active', true);
      if (staffErr) throw staffErr;
      const staffById = Object.fromEntries((activeStaff || []).map(s => [s.id, s]));
      const withCounts = docs.map(d => {
        if (!d.requires_signature) return { ...d, signed_count: 0, eligible_count: 0, signed: [], unsigned: [] };
        const eligible = d.visibility === 'all' ? (activeStaff || []) : (staffById[d.visibility] ? [staffById[d.visibility]] : []);
        const sigByStaff = Object.fromEntries((sigCounts[d.id] || []).map(s => [s.staff_id, s.signed_at]));
        const signed = eligible.filter(s => sigByStaff[s.id]).map(s => ({ id: s.id, full_name: s.full_name, hire_date: s.hire_date, signed_at: sigByStaff[s.id] }));
        const unsigned = eligible.filter(s => !sigByStaff[s.id]).map(s => ({ id: s.id, full_name: s.full_name, hire_date: s.hire_date }));
        return { ...d, signed_count: signed.length, eligible_count: eligible.length, signed, unsigned };
      });
      return res.json({ ok: true, docs: withCounts });
    }

    const withStatus = docs.map(d => ({ ...d, signed_at: signedMap[d.id] || null }));
    res.json({ ok: true, docs: withStatus });
  } catch (e) {
    console.error('Portal docs list failed:', e);
    res.status(500).json({ error: e.message || 'Could not load documents.' });
  }
});

// --- 11. Portal: staff signs/acknowledges a document -----------------------
app.post('/api/portal/sign', async (req, res) => {
  try {
    const caller = await requireActiveUser(req, res); if (!caller) return;
    const { doc_id, signature_name } = req.body || {};
    if (!doc_id || !signature_name || !signature_name.trim()) {
      return res.status(400).json({ error: 'Document and typed name are required.' });
    }
    const { data: doc } = await admin.from('portal_docs').select('id, visibility').eq('id', doc_id).single();
    if (!doc) return res.status(404).json({ error: 'Document not found.' });
    if (doc.visibility !== 'all' && doc.visibility !== caller.user.id) {
      return res.status(403).json({ error: 'This document is not assigned to you.' });
    }
    const { data: sig, error } = await admin.from('portal_signatures').upsert({
      doc_id,
      staff_id: caller.user.id,
      signature_name: signature_name.trim(),
      ip: (req.headers['x-forwarded-for'] || req.ip || '').toString().split(',')[0].trim(),
      user_agent: req.headers['user-agent'] || ''
    }, { onConflict: 'doc_id,staff_id' }).select().single();
    if (error) throw error;
    res.json({ ok: true, signature: sig });
  } catch (e) {
    console.error('Portal signature failed:', e);
    res.status(500).json({ error: e.message || 'Could not save signature.' });
  }
});

// --- 12. Portal: admin deletes a document (removes DB row + storage object) ---
app.delete('/api/portal/docs/:id', async (req, res) => {
  try {
    const caller = await requireAdmin(req, res); if (!caller) return;
    const { data: doc } = await admin.from('portal_docs').select('storage_path').eq('id', req.params.id).single();
    if (!doc) return res.status(404).json({ error: 'Document not found.' });
    if (doc.storage_path) {
      try { await admin.storage.from(PORTAL_BUCKET).remove([doc.storage_path]); } catch (_) {}
    }
    const { error } = await admin.from('portal_docs').delete().eq('id', req.params.id);
    if (error) throw error;
    res.json({ ok: true });
  } catch (e) {
    console.error('Portal delete failed:', e);
    res.status(500).json({ error: e.message || 'Could not delete document.' });
  }
});


// ============================================================
// SERVER-SIDE 10H AUTO FORCE-LOGOUT SWEEP
// The in-browser checkForceLogout() only runs while a staff member's tab is
// open. If they close the laptop / lose connection / crash the tab before it
// fires, the shift just stays open forever (this is what happened to Kat
// Barrameda and Fatima Payuno on 2026-09-04). This sweep is the real,
// browser-independent fix: it runs on the server every 5 minutes and force-
// closes any shift open >10h, same 10h cap and Overtime waiver as the client.
// ============================================================
const FORCE_LOGOUT_MS = 10 * 3600 * 1000;
const OVERTIME_ACTIVITY = 'Overtime';

async function closeOpenEntries(shiftId, endedAt) {
  const { error } = await admin.from('entries').update({ ended_at: endedAt })
    .eq('shift_id', shiftId).eq('active', true).is('ended_at', null);
  return error;
}

// Shared by both the automatic sweep and the admin's manual "Force Logout" button.
async function forceLogoutShift(shift, endedAtIso, { manual = false, adminName = '' } = {}) {
  const closeErr = await closeOpenEntries(shift.id, endedAtIso);
  if (closeErr) throw closeErr;
  const { error } = await admin.from('shifts').update({ logout_at: endedAtIso }).eq('id', shift.id);
  if (error) throw error;

  const { data: staffRow } = await admin.from('staff').select('full_name, client_id').eq('id', shift.staff_id).single();
  const client = await clientName(staffRow?.client_id);
  const durationMin = Math.round((new Date(endedAtIso) - new Date(shift.login_at)) / 60000);
  const title = manual ? '⏰ SMB Time Force-Logout (admin)' : '⏰ SMB Time Auto Force-Logout (10h cap)';
  const context = manual
    ? `Manually force-logged-out by admin${adminName ? ' ' + adminName : ''}.`
    : 'Staff exceeded 10 hours on shift without selecting Overtime — auto logged out by the server sweep (browser was not required to be open).';
  const payload = slackPayload(title, [
    ['Staff', staffRow?.full_name || shift.staff_id],
    ['Client', client],
    ['Shift start', phtDateTime(shift.login_at)],
    ['Logged out', phtDateTime(endedAtIso)],
    ['Total shift time', `${Math.floor(durationMin / 60)}h ${durationMin % 60}m`]
  ], context);
  await sendSlackOnce({
    eventKey: `force-logout:${shift.id}${manual ? ':manual' : ':sweep'}`,
    destination: 'payroll-and-sheet', eventType: 'force-logout', entityId: shift.id,
    webhook: SLACK_PAYROLL_WEBHOOK_URL, payload
  }).catch(e => console.error('Force-logout Slack notice failed:', e.message));
}

async function sweepStaleShifts() {
  try {
    const cutoff = new Date(Date.now() - FORCE_LOGOUT_MS).toISOString();
    const { data: staleShifts, error } = await admin.from('shifts')
      .select('id, staff_id, login_at').is('logout_at', null).lt('login_at', cutoff);
    if (error) { console.error('Force-logout sweep query failed:', error.message); return; }
    for (const shift of staleShifts || []) {
      try {
        const { data: openEntry } = await admin.from('entries')
          .select('activity').eq('shift_id', shift.id).eq('active', true).is('ended_at', null)
          .order('started_at', { ascending: false }).limit(1).maybeSingle();
        if (openEntry?.activity === OVERTIME_ACTIVITY) continue; // waived while on Overtime, same as client rule
        await forceLogoutShift(shift, new Date().toISOString());
        console.log('Force-logout sweep closed stale shift', shift.id, 'staff', shift.staff_id);
      } catch (e) {
        console.error('Force-logout sweep failed for shift', shift.id, e.message);
      }
    }
  } catch (e) {
    console.error('Force-logout sweep crashed:', e.message);
  }
}
setInterval(sweepStaleShifts, 5 * 60 * 1000);
sweepStaleShifts(); // also run once at boot so a stale shift never waits up to 5 min after a deploy

// --- 13. Admin: manual "Force Logout" button (Live Status tab) -----------
app.post('/api/admin/shifts/:id/force-logout', async (req, res) => {
  try {
    const adminCaller = await requireAdmin(req, res); if (!adminCaller) return;
    const shiftId = String(req.params.id || '');
    if (!uuidRe.test(shiftId)) return res.status(400).json({ error: 'Valid shift id required.' });
    const { data: shift, error } = await admin.from('shifts')
      .select('id, staff_id, login_at, logout_at').eq('id', shiftId).single();
    if (error || !shift) return res.status(404).json({ error: 'Shift not found.' });
    if (shift.logout_at) return res.status(409).json({ error: 'That shift is already closed.' });
    await forceLogoutShift(shift, new Date().toISOString(), { manual: true, adminName: adminCaller.full_name });
    res.json({ ok: true });
  } catch (e) {
    console.error('Admin force-logout failed:', e);
    res.status(500).json({ error: e.message || 'Force-logout failed.' });
  }
});

/* ============================================================================
   Bagani DMs to staff  [Rendy, 2026-10-23]
   Private Slack DMs (bot token, Render env SLACK_BOT_TOKEN) for:
     • new PM Bulletin posts (only the post's audience, when it publishes)
     • Contractor Fee: Sent Early ticked / cutoff marked PAID (PAID skipped if Sent Early)
     • requests approved / rejected (PTO, PCH, PA, Sick, Reimbursement, SA, CA)
     • time log corrections applied / not applied
     • timesheet acknowledgement: 10 PM PHT on the 8th (21–4) and 23rd (5–20),
       Friday before if that is a weekend; 24h reminder; auto-acknowledge after 48h;
       new DM when an admin asks to re-acknowledge; issues → payroll-and-sheet.
   Everything runs from one idempotent sweep (dmSweep): every 5 min while awake, at boot,
   on POST/GET /api/notify/sweep (the hourly free pinger + the portal after admin actions).
   slack_notification_log (destination 'dm') is the once-only guard. Only events after the
   go-live marker (first boot of this code) send DMs — no flood of old items.
   ============================================================================ */
const SLACK_BOT_TOKEN = process.env.SLACK_BOT_TOKEN || '';
const PORTAL_URL = APP_URL || 'https://rengpro1985.github.io/time-tracker-app/';
const DM_REQ_LABEL = {pto:'PTO',pch:'Paid Client Holiday',planned_absence:'Planned Absence',sick_leave:'Sick Leave',
  reimbursement:'Reimbursement',salary_advance:'Salary Advance',cash_advance:'Cash Advance',half_day:'Half Day'};
const DM_DATED = new Set(['pto','pch','planned_absence','sick_leave','half_day']);

async function slackApi(method, body){
  if(!SLACK_BOT_TOKEN) throw new Error('SLACK_BOT_TOKEN is not set on Render.');
  let lastError;
  for(let attempt=1;attempt<=3;attempt++){
    try{
      const isGet = method==='users.lookupByEmail';
      const url = 'https://slack.com/api/'+method+(isGet?'?'+new URLSearchParams(body):'');
      const r = await fetch(url, isGet
        ? {headers:{Authorization:'Bearer '+SLACK_BOT_TOKEN}}
        : {method:'POST',headers:{'Content-Type':'application/json; charset=utf-8',Authorization:'Bearer '+SLACK_BOT_TOKEN},body:JSON.stringify(body)});
      if(r.status===429){ await sleep(Math.max(1200,Number(r.headers.get('retry-after')||1)*1000)); continue; }
      const j = await r.json().catch(()=>({ok:false,error:'bad_json_'+r.status}));
      if(j.ok) return j;
      lastError = Object.assign(new Error(j.error||'slack_error'),{slack:j.error});
      if(j.error!=='ratelimited' && j.error!=='internal_error' && j.error!=='fatal_error') break;
    }catch(e){ lastError=e; }
    if(attempt<3) await sleep(1200*attempt);
  }
  throw lastError || new Error('Slack API failed.');
}

// email → Slack user id (positive cache 24h, negative cache 3h so unmatched staff don't hammer Slack)
const slackIdCache = new Map();
async function slackUserIdFor(email){
  const key = String(email||'').trim().toLowerCase();
  if(!key) return null;
  const hit = slackIdCache.get(key);
  if(hit && Date.now()-hit.at < (hit.id?24:3)*3600000) return hit.id;
  let id = null;
  try{ const j = await slackApi('users.lookupByEmail',{email:key}); id = j.user && !j.user.deleted ? j.user.id : null; }
  catch(e){ if(e.slack!=='users_not_found') throw e; }
  slackIdCache.set(key,{id,at:Date.now()});
  return id;
}

function dmBlocks(lines, context){
  const blocks = [{type:'section',text:{type:'mrkdwn',text:lines.filter(Boolean).join('\n')}}];
  if(context) blocks.push({type:'context',elements:[{type:'mrkdwn',text:context}]});
  return blocks;
}
// Sends one DM once (event key). Returns {sent}|{duplicate}|{noSlack}. Throws on Slack errors.
async function sendDmOnce({eventKey, entityId, staff, text, blocks}){
  const claim = await claimNotification(eventKey,'dm','dm',entityId);
  if(!claim.claimed) return {sent:false,...claim};
  const now = () => new Date().toISOString();
  try{
    const uid = await slackUserIdFor(staff.email);
    if(!uid){
      await admin.from('slack_notification_log').update({status:'failed',last_error:'No Slack user with email '+String(staff.email||'(none)').slice(0,120),updated_at:now()}).eq('event_key',eventKey);
      return {sent:false,noSlack:true};
    }
    await slackApi('chat.postMessage',{channel:uid,text:String(text).slice(0,2900),blocks,unfurl_links:false,unfurl_media:false});
    await admin.from('slack_notification_log').update({status:'sent',sent_at:now(),last_error:null,updated_at:now()}).eq('event_key',eventKey);
    await sleep(350); // stay well under Slack's per-second posting limit
    return {sent:true};
  }catch(e){
    await admin.from('slack_notification_log').update({status:'failed',last_error:String(e.message||e).slice(0,1000),updated_at:now()}).eq('event_key',eventKey);
    throw e;
  }
}

// ---- dates (PHT) ----
function dmNiceDate(iso){ return new Intl.DateTimeFormat('en-US',{timeZone:'UTC',month:'short',day:'numeric',year:'numeric'}).format(new Date(iso+'T00:00:00Z')); }
function dmShortDate(iso){ return new Intl.DateTimeFormat('en-US',{timeZone:'UTC',month:'short',day:'numeric'}).format(new Date(iso+'T00:00:00Z')); }
function dmRange(a,b){ if(!b||a===b) return dmNiceDate(a); return a.slice(0,4)===b.slice(0,4) ? `${dmShortDate(a)} – ${dmNiceDate(b)}` : `${dmNiceDate(a)} – ${dmNiceDate(b)}`; }
function dmCutoffLabel(iso){ return `${dmNiceDate(iso)} (${Number(iso.slice(8,10))===15?'15th':'end of month'})`; }
function lastDayIso(y,m){ const d=new Date(Date.UTC(y,m,0)).getUTCDate(); return `${y}-${String(m).padStart(2,'0')}-${String(d).padStart(2,'0')}`; }
function ymd(y,m,d){ return `${y}-${String(m).padStart(2,'0')}-${String(d).padStart(2,'0')}`; }
/* Hours periods 21st–4th (paid 15th, DM on the 8th) and 5th–20th (paid end of month, DM on
   the 23rd), 10 PM PHT; if that day is Sat/Sun, the Friday before. */
function tsPeriodsAround(now=new Date()){
  const today = phIsoDate(now); let [y,m] = today.split('-').map(Number);
  const out = [];
  for(let back=0; back<2; back++){
    let yy=y, mm=m-back; if(mm<1){mm+=12;yy--;}
    const py = mm===1?yy-1:yy, pm = mm===1?12:mm-1;
    out.push({start:ymd(py,pm,21), end:ymd(yy,mm,4), cutoff:ymd(yy,mm,15), sendDay:ymd(yy,mm,7)});
    out.push({start:ymd(yy,mm,5), end:ymd(yy,mm,20), cutoff:lastDayIso(yy,mm), sendDay:ymd(yy,mm,23)});
  }
  return out.map(p=>{
    const dow = new Date(p.sendDay+'T00:00:00Z').getUTCDay();
    const sd = dow===6?addIsoDays(p.sendDay,-1):dow===0?addIsoDays(p.sendDay,-2):p.sendDay;
    return {...p, sendDay:sd, sendAt:new Date(sd+'T22:00:00+08:00')};
  });
}
function tsDeadline(sentAtIso){ return phtDateTime(new Date(new Date(sentAtIso).getTime()+48*3600000)); }

// ---- go-live marker: DMs only for things that happen after this ----
let dmSinceIso = null;
async function dmSince(){
  if(dmSinceIso) return dmSinceIso;
  const now = new Date().toISOString();
  const {error} = await admin.from('slack_notification_log').insert({event_key:'dm:golive',destination:'dm',event_type:'dm',entity_id:'golive',status:'sent',attempts:1,claimed_at:now,sent_at:now,updated_at:now});
  if(error && error.code!=='23505') throw error;
  const {data,error:e2} = await admin.from('slack_notification_log').select('claimed_at').eq('event_key','dm:golive').single();
  if(e2) throw e2;
  dmSinceIso = new Date(data.claimed_at).toISOString();
  return dmSinceIso;
}

async function dmStaffMap(ids){
  const uniq = [...new Set(ids.filter(Boolean).map(String))];
  if(!uniq.length) return new Map();
  const {data,error} = await admin.from('staff').select('id, full_name, email, role, active, client_id').in('id',uniq);
  if(error) throw error;
  return new Map((data||[]).map(s=>[String(s.id),s]));
}
function firstName(s){ return safeSlack(String(s?.full_name||'').trim().split(/\s+/)[0]||'there',60); }

// ---- message builders ----
function requestDm(r, s){
  const label = DM_REQ_LABEL[r.type] || 'Request';
  let what = `${label}`;
  if(DM_DATED.has(r.type) && r.start_date) what += ` for ${dmRange(r.start_date, r.end_date||r.start_date)}`;
  else if(r.amount!=null) what += ` of ${peso(r.amount)}`;
  const ok = r.status!=='rejected';
  const lines = [ok ? `✅ *Your ${what} was approved*` : `❌ *Your ${what} was not approved*`];
  if(ok && (r.type==='salary_advance'||r.type==='cash_advance') && Number(r.cutoffs)>0) lines.push(`Repaid over ${Number(r.cutoffs)} cutoff${Number(r.cutoffs)===1?'':'s'}.`);
  if(ok && r.type==='half_day') lines.push('That shift will not count against your Reliability rating. Your Contractor Fee is based on the hours you actually logged.');
  if(ok && r.type==='reimbursement' && r.payout_cutoff) lines.push(`Added to your Contractor Fee on ${dmCutoffLabel(String(r.payout_cutoff).slice(0,10))}.`);
  if(!ok && r.rejection_reason) lines.push(`*Reason:* ${safeSlack(r.rejection_reason,800)}`);
  return {text:(ok?'Approved: ':'Not approved: ')+what, blocks:dmBlocks(lines,`Details: <${PORTAL_URL}|SMB Portal> → Requests`)};
}
function correctionDm(c){
  const ok = c.status==='approved';
  const day = c.target_date ? ` for ${dmNiceDate(String(c.target_date).slice(0,10))}` : '';
  const lines = [ok ? `✅ *Your time log correction${day} was applied*` : `❌ *Your time log correction${day} was not applied*`];
  if(c.admin_note) lines.push(`*${ok?'Note':'Reason'}:* ${safeSlack(c.admin_note,800)}`);
  return {text:`Time log correction${day} ${ok?'applied':'not applied'}`, blocks:dmBlocks(lines,`Check your hours in the <${PORTAL_URL}|SMB Portal>`)};
}
function paidDm(p){
  const cutoff = String(p.cutoff_date).slice(0,10), amt = p.snapshot && p.snapshot.net_amount_payable;
  const lines = ['✅ *Your Contractor Fee has been sent*',`Cutoff: *${dmCutoffLabel(cutoff)}*`];
  if(amt!=null && Number.isFinite(Number(amt))) lines.push(`Net amount: *${peso(amt)}*`);
  lines.push('Salamat sa hard work! 💪');
  return {text:`Your Contractor Fee for the ${dmNiceDate(cutoff)} cutoff has been sent`, blocks:dmBlocks(lines,`Contractor Fee details: <${PORTAL_URL}|SMB Portal> → Contractor Ledger`)};
}
function sentEarlyDm(cutoff, amount){
  const lines = ['💸 *Your Contractor Fee was sent early*',`Cutoff: *${dmCutoffLabel(cutoff)}*`];
  if(amount!=null && Number.isFinite(Number(amount))) lines.push(`Amount: *${peso(amount)}*`);
  lines.push('Please check your account. 🙏');
  return {text:`Your Contractor Fee for the ${dmNiceDate(cutoff)} cutoff was sent early`, blocks:dmBlocks(lines,`Contractor Fee details: <${PORTAL_URL}|SMB Portal> → Contractor Ledger`)};
}
function bulletinDm(p){
  const tags = [p.urgent?'`URGENT`':'', p.require_ack?'`NEEDS "GOT IT"`':''].filter(Boolean).join(' ');
  const body = String(p.body||'').replace(/\s+/g,' ').trim();
  const snip = body.length>220 ? body.slice(0,220).replace(/\s+\S*$/,'')+'…' : body;
  const lines = [`📌 *New PM Bulletin post*${tags?' · '+tags:''}`, `*${safeSlack(p.title||'(untitled)',200)}*`];
  if(snip) lines.push('>'+safeSlack(snip,400));
  lines.push(`👉 <${PORTAL_URL}|Open the SMB Portal> to read it${p.require_ack?' and tap *Got it*':''}.`);
  return {text:`New PM Bulletin post: ${String(p.title||'').slice(0,150)}`, blocks:dmBlocks(lines,safeSlack([p.category,p.created_by_name?'from '+p.created_by_name:''].filter(Boolean).join(' · '),200))};
}
function timesheetDm(a, kind){
  const per = dmRange(String(a.period_start).slice(0,10), String(a.period_end).slice(0,10));
  const due = tsDeadline(a.sent_at || new Date().toISOString());
  let head;
  if(kind==='reminder') head = `⏰ *Reminder: please review your timesheet for ${per}*`;
  else if(kind==='again') head = `🗓️ *Your timesheet for ${per} was updated. Please review it again*`;
  else head = `🗓️ *Your timesheet for ${per} is ready*`;
  const lines = [head];
  if(kind==='again' && a.reset_reason) lines.push(`*What changed:* ${safeSlack(a.reset_reason,300)}`);
  lines.push(`👉 <${PORTAL_URL}|Open the SMB Portal> and tap *Acknowledge*, or report an issue, by *${due}*.`);
  return {text:`Timesheet ${per}: please review and acknowledge`, blocks:dmBlocks(lines,`Contractor Fee for this period: ${dmCutoffLabel(String(a.cutoff_date).slice(0,10))}`)};
}

function fmtPhtShort(iso){ return new Intl.DateTimeFormat('en-US',{timeZone:'Asia/Manila',month:'short',day:'numeric',hour:'numeric',minute:'2-digit',hour12:true}).format(new Date(iso)); }
function editLogoutDm(l){
  const day = l.shift_date ? dmNiceDate(String(l.shift_date).slice(0,10)) : fmtPhtShort(l.new_logout);
  const lines = [`🕘 *Sir Rendy updated your logout time for ${day}*`, `New logout: *${phtClock(l.new_logout)} PHT*${l.old_logout?` (was ${phtClock(l.old_logout)})`:' (your shift was still open)'}`];
  if(l.merged && Array.isArray(l.merged) && l.merged.length) lines.push(`Your log-in after that was joined into the same shift.`);
  if(l.reason) lines.push(`*Reason:* ${safeSlack(l.reason,300)}`);
  return {text:`Sir Rendy updated your logout time for ${day}`, blocks:dmBlocks(lines,`Check your hours in the <${PORTAL_URL}|SMB Portal>`)};
}
function addShiftDm(rows){
  rows = rows.slice().sort((a,b)=>String(a.shift_date)<String(b.shift_date)?-1:1);
  const n = rows.length, d0 = String(rows[0].shift_date).slice(0,10), d1 = String(rows[n-1].shift_date).slice(0,10);
  const lines = [`🗓️ *Sir Rendy added ${n} shift${n===1?'':'s'} (${dmRange(d0,d1)}) to your timesheet*`];
  rows.slice(0,8).forEach(r=>lines.push(`• ${dmShortDate(String(r.shift_date).slice(0,10))}: ${phtClock(r.new_login)} – ${phtClock(r.new_logout)} PHT`));
  if(n>8) lines.push(`…and ${n-8} more.`);
  if(rows[0].reason) lines.push(`*Reason:* ${safeSlack(rows[0].reason,300)}`);
  return {text:`Sir Rendy added ${n} shift${n===1?'':'s'} to your timesheet`, blocks:dmBlocks(lines,`Check your hours in the <${PORTAL_URL}|SMB Portal>`)};
}
function halfDayReminderDm(dateIso, workedMin){
  const lines = [`🌓 *Your shift on ${dmNiceDate(dateIso)} was short* (${durText(workedMin)} logged).`,
    'If this was a half day, please file a *Half Day* request now (Requests → New request → Half Day). It must be filed within *24 hours* of the shift.',
    'If it was something else, you can ignore this message.'];
  return {text:`Your shift on ${dmNiceDate(dateIso)} was short — file a Half Day request within 24h if it was a half day`, blocks:dmBlocks(lines,`<${PORTAL_URL}|Open the SMB Portal>`)};
}

/* Half Day reminder [Rendy, 2026-10-23]: when a shift-day ends more than 1h short of 8h worked
   inside the scheduled window (60min Break not counted), and no Half Day / leave is on file,
   DM once asking them to file a Half Day within 24h. Waits 30 min after the last logout (in case
   they log back in) and only looks at the last 24h. */
const HALFDAY_SHORT_MIN = 420; // worked under 7h (8h minus 1h) inside the shift window
async function halfDayReminderSweep(since){
  const now = Date.now();
  const {data:shifts,error} = await admin.from('shifts').select('id, staff_id, login_at, logout_at')
    .gte('login_at',new Date(Math.max(now-36*3600000,new Date(since).getTime()-12*3600000)).toISOString()).limit(2000);
  if(error) throw error;
  if(!(shifts||[]).length) return;
  const sm = await dmStaffMap(shifts.map(x=>x.staff_id));
  const clientIds = [...new Set([...sm.values()].map(s=>s.client_id).filter(Boolean))];
  const {data:cl} = clientIds.length ? await admin.from('clients').select('id, shift_start, shift_end').in('id',clientIds) : {data:[]};
  const groups = new Map();
  for(const sh of shifts){
    const st = sm.get(String(sh.staff_id)); if(!st||!st.active||st.role==='admin') continue;
    const c = (cl||[]).find(x=>x.id===st.client_id); if(!c) continue;
    const w = anchoredShiftWindow(c,new Date(sh.login_at)); if(!w) continue;
    const k = st.id+'|'+w.date; if(!groups.has(k)) groups.set(k,{st,w,shifts:[]});
    groups.get(k).shifts.push(sh);
  }
  for(const g of groups.values()){
    const {st,w} = g;
    if(w.end.getTime() > now) continue;                          // scheduled shift not over yet
    if(g.shifts.some(s=>!s.logout_at)) continue;                  // still logged in somewhere
    const lastOut = Math.max(...g.shifts.map(s=>new Date(s.logout_at).getTime()));
    if(now-lastOut < 30*60000 || now-w.end.getTime() > 24*3600000) continue;
    if(w.end.getTime() < new Date(since).getTime()) continue;     // nothing from before this feature went live
    const key = `dm:halfday:${st.id}:${w.date}`;
    const {data:done} = await admin.from('slack_notification_log').select('event_key').eq('event_key',key).maybeSingle();
    if(done) continue;
    const {data:ents,error:ee} = await admin.from('entries').select('activity, started_at, ended_at, active').in('shift_id',g.shifts.map(s=>s.id));
    if(ee) throw ee;
    const ws=w.start.getTime(), we=w.end.getTime();
    const worked = (ents||[]).filter(e=>e.active!==false&&e.activity!=='60min Break'&&e.ended_at).reduce((m,e)=>{
      const a=Math.max(ws,new Date(e.started_at).getTime()), b=Math.min(we,new Date(e.ended_at).getTime());
      return m+Math.max(0,b-a)/60000; },0);
    if(worked >= HALFDAY_SHORT_MIN || worked < 1) continue;
    const {data:hd} = await admin.from('requests').select('id').eq('staff_id',st.id).eq('type','half_day').eq('start_date',w.date).neq('status','rejected').limit(1);
    if(hd&&hd.length) continue;
    const {data:lv} = await admin.from('leave_days').select('id').eq('staff_id',st.id).eq('date',w.date).limit(1);
    if(lv&&lv.length) continue;
    await dmTry(()=>sendDmOnce({eventKey:key,entityId:`${st.id}:${w.date}`,staff:st,...halfDayReminderDm(w.date,worked)}),'halfday-reminder');
  }
}

// ---- the sweep ----
let dmRunning = false, dmLastRun = 0, dmRerun = false;
const dmStats = {last:null, lastError:null, sent:0, noSlack:0, failed:0};
async function dmTry(fn, label){
  try{ const r = await fn(); if(r?.sent) dmStats.sent++; if(r?.noSlack) dmStats.noSlack++; return r; }
  catch(e){ dmStats.failed++; console.error('DM failed ('+label+'):', e.message); return null; }
}
async function dmSweep(force=false){
  if(!SLACK_BOT_TOKEN) return {skipped:'no SLACK_BOT_TOKEN'};
  if(dmRunning){ dmRerun = true; return {skipped:'running'}; }
  if(!force && Date.now()-dmLastRun < 20000){ dmRerun = true; setTimeout(()=>{ if(dmRerun){ dmRerun=false; dmSweep(true); } }, 21000); return {skipped:'recent'}; }
  dmRunning = true; dmLastRun = Date.now();
  try{
    const since = await dmSince();
    const nowIso = new Date().toISOString();
    const recent = new Date(Date.now()-14*86400000).toISOString();
    const floor = since > recent ? since : recent;

    // 1) requests approved / rejected
    {
      const {data,error} = await admin.from('requests').select('*').in('status',['approved','paid','rejected']).gte('reviewed_at',floor).limit(500);
      if(error) throw error;
      const sm = await dmStaffMap((data||[]).map(r=>r.staff_id));
      for(const r of data||[]){
        const s = sm.get(String(r.staff_id)); if(!s||!s.active||!DM_REQ_LABEL[r.type]) continue;
        const kind = r.status==='rejected'?'rejected':'approved';
        await dmTry(()=>sendDmOnce({eventKey:`dm:req:${r.id}:${kind}`,entityId:r.id,staff:s,...requestDm(r,s)}),'request');
      }
    }
    // 2) time log corrections
    {
      const {data,error} = await admin.from('corrections').select('*').in('status',['approved','rejected']).or(`reviewed_at.gte.${floor},and(reviewed_at.is.null,created_at.gte.${floor})`).limit(500);
      if(error) throw error;
      const sm = await dmStaffMap((data||[]).map(c=>c.staff_id));
      for(const c of data||[]){
        const s = sm.get(String(c.staff_id)); if(!s||!s.active) continue;
        await dmTry(()=>sendDmOnce({eventKey:`dm:corr:${c.id}:${c.status}`,entityId:c.id,staff:s,...correctionDm(c)}),'correction');
      }
    }
    // 3) Sent Early (fallback without amount if the portal's instant call failed) + 4) PAID
    {
      const {data:early,error:e1} = await admin.from('ledger_extras').select('staff_id, cutoff_date, amount, updated_at').eq('field_key','sent_early').gte('updated_at',floor).limit(1000);
      if(e1) throw e1;
      const {data:paid,error:e2} = await admin.from('paid_cutoffs').select('staff_id, cutoff_date, status, snapshot, confirmed_at').eq('status','paid').gte('confirmed_at',floor).limit(1000);
      if(e2) throw e2;
      const sm = await dmStaffMap([...(early||[]),...(paid||[])].map(x=>x.staff_id));
      for(const x of early||[]){
        if(Number(x.amount)!==1) continue;
        const s = sm.get(String(x.staff_id)); if(!s||!s.active) continue;
        const cutoff = String(x.cutoff_date).slice(0,10);
        // give the portal's instant call (which includes the amount) a head start
        if(Date.now()-new Date(x.updated_at).getTime() < 3*60000) continue;
        await dmTry(()=>sendDmOnce({eventKey:`dm:early:${x.staff_id}:${cutoff}`,entityId:`${x.staff_id}:${cutoff}`,staff:s,...sentEarlyDm(cutoff,null)}),'sent-early');
      }
      for(const p of paid||[]){
        const s = sm.get(String(p.staff_id)); if(!s) continue;
        const cutoff = String(p.cutoff_date).slice(0,10);
        const {data:se} = await admin.from('ledger_extras').select('amount').eq('field_key','sent_early').eq('staff_id',p.staff_id).eq('cutoff_date',cutoff).maybeSingle();
        if(se && Number(se.amount)===1) continue; // Rendy: skip the PAID DM when Sent Early was ticked
        await dmTry(()=>sendDmOnce({eventKey:`dm:paid:${p.staff_id}:${cutoff}`,entityId:`${p.staff_id}:${cutoff}`,staff:s,...paidDm(p)}),'paid');
      }
    }
    // 5) PM Bulletin posts (when live, only their audience)
    {
      const {data:posts,error} = await admin.from('bulletin_posts').select('*').gte('created_at',floor).lte('publish_at',nowIso).limit(200);
      if(error) throw error;
      const live = (posts||[]).filter(p=>!p.archived && (!p.expires_at || p.expires_at > nowIso));
      if(live.length){
        const {data:staff,error:se} = await admin.from('staff').select('id, full_name, email, role, active, client_id').eq('active',true).neq('role','admin');
        if(se) throw se;
        for(const p of live){
          const ids = (p.audience_ids||[]).map(String);
          const aud = (staff||[]).filter(s=>p.audience==='all'||(p.audience==='client'&&s.client_id!=null&&ids.includes(String(s.client_id)))||(p.audience==='staff'&&ids.includes(String(s.id))));
          for(const s of aud) await dmTry(()=>sendDmOnce({eventKey:`dm:bb:${p.id}:${s.id}`,entityId:p.id,staff:s,...bulletinDm(p)}),'bulletin');
        }
      }
    }
    // 6) timesheet acknowledgements
    await tsSweep(since);
    // 7) admin shift changes: Edit logout time + Add shift (SQL table shift_admin_log) [2026-10-23]
    {
      const {data:logs,error} = await admin.from('shift_admin_log').select('*').gte('edited_at',floor).order('edited_at').limit(500);
      if(!error && logs && logs.length){
        const sm = await dmStaffMap(logs.map(l=>l.staff_id));
        for(const l of logs.filter(x=>x.action==='edit_logout')){
          const s = sm.get(String(l.staff_id)); if(!s||!s.active||s.role==='admin') continue;
          await dmTry(()=>sendDmOnce({eventKey:`dm:editlogout:${l.id}`,entityId:l.id,staff:s,...editLogoutDm(l)}),'edit-logout');
        }
        const batches = new Map();
        logs.filter(x=>x.action==='add_shift'&&x.batch_id).forEach(l=>{ if(!batches.has(l.batch_id)) batches.set(l.batch_id,[]); batches.get(l.batch_id).push(l); });
        for(const [bid,rows] of batches){
          const s = sm.get(String(rows[0].staff_id)); if(!s||!s.active||s.role==='admin') continue;
          await dmTry(()=>sendDmOnce({eventKey:`dm:addshift:${bid}`,entityId:bid,staff:s,...addShiftDm(rows)}),'add-shift');
        }
      }
    }
    // 8) Half Day reminder for short shifts
    try{ await halfDayReminderSweep(since); }catch(e){ console.error('Half Day reminder sweep failed:', e.message); }
    dmStats.last = new Date().toISOString(); dmStats.lastError = null;
    return {ok:true};
  }catch(e){
    dmStats.lastError = String(e.message||e).slice(0,300);
    console.error('DM sweep crashed:', e.message);
    return {ok:false,error:dmStats.lastError};
  }finally{
    dmRunning = false;
    if(dmRerun){ dmRerun=false; setTimeout(()=>dmSweep(true), 1000); }
  }
}

async function tsSweep(since){
  const {error:probe} = await admin.from('timesheet_acks').select('id').limit(1);
  if(probe) return; // SQL not run yet
  const now = new Date();
  // a) create rows (and first DM) for periods whose send time has passed (within 5 days, after go-live boot day)
  for(const p of tsPeriodsAround(now)){
    if(p.sendAt > now || now - p.sendAt > 5*86400000) continue;
    if(p.sendAt.getTime() < new Date(since).getTime() - 2*86400000) continue; // no back-filling old periods at go-live
    const fromIso = new Date(p.start+'T00:00:00+08:00').toISOString(), toIso = new Date(addIsoDays(p.end,1)+'T00:00:00+08:00').toISOString();
    const {data:sh,error} = await admin.from('shifts').select('staff_id').gte('login_at',fromIso).lt('login_at',toIso).limit(5000);
    if(error) throw error;
    const ids = [...new Set((sh||[]).map(x=>String(x.staff_id)))];
    if(!ids.length) continue;
    const sm = await dmStaffMap(ids);
    const rows = ids.map(id=>sm.get(id)).filter(s=>s&&s.active&&s.role!=='admin')
      .map(s=>({staff_id:s.id,period_start:p.start,period_end:p.end,cutoff_date:p.cutoff}));
    if(rows.length){
      const {error:ie} = await admin.from('timesheet_acks').upsert(rows,{onConflict:'staff_id,period_start',ignoreDuplicates:true});
      if(ie) throw ie;
    }
  }
  const recentStart = addIsoDays(phIsoDate(now), -45);
  const {data:acks,error} = await admin.from('timesheet_acks').select('*').gte('period_start',recentStart).limit(2000);
  if(error) throw error;
  const sm = await dmStaffMap((acks||[]).map(a=>a.staff_id));
  const periods = tsPeriodsAround(now);
  for(const a of acks||[]){
    const s = sm.get(String(a.staff_id)); if(!s) continue;
    const per = periods.find(p=>p.start===String(a.period_start).slice(0,10));
    if(per && per.sendAt > now) continue; // never before the scheduled time
    // b) first DM / re-acknowledge DM for the current round
    if(a.status==='waiting' && Number(a.notified_round) < Number(a.round)){
      const sentAt = new Date().toISOString();
      const msg = timesheetDm({...a,sent_at:sentAt}, Number(a.round)>1?'again':'first');
      const r = await dmTry(()=>sendDmOnce({eventKey:`dm:ts:${a.id}:${a.round}`,entityId:a.id,staff:s,...msg}),'timesheet');
      if(r && (r.sent || r.noSlack || r.duplicate)){
        await admin.from('timesheet_acks').update({notified_round:a.round,sent_at:sentAt,reminded_at:null,updated_at:sentAt}).eq('id',a.id).eq('round',a.round);
      }
      continue;
    }
    if(a.status==='waiting' && a.sent_at){
      const age = now - new Date(a.sent_at);
      // c) auto-acknowledge after 48h
      if(age >= 48*3600000){
        await admin.from('timesheet_acks').update({status:'auto',answered_at:now.toISOString(),updated_at:now.toISOString()}).eq('id',a.id).eq('status','waiting').eq('round',a.round);
        continue;
      }
      // d) one reminder after 24h
      if(age >= 24*3600000 && !a.reminded_at){
        const r = await dmTry(()=>sendDmOnce({eventKey:`dm:ts-remind:${a.id}:${a.round}`,entityId:a.id,staff:s,...timesheetDm(a,'reminder')}),'timesheet-reminder');
        if(r && (r.sent || r.noSlack || r.duplicate)) await admin.from('timesheet_acks').update({reminded_at:now.toISOString(),updated_at:now.toISOString()}).eq('id',a.id).eq('round',a.round);
      }
    }
    // e) issue reported → payroll-and-sheet (once per round)
    // (waits 45 s after the answer so screenshots uploaded right after it are counted)
    if(a.status==='issue' && a.answered_at && now - new Date(a.answered_at) >= 45000 && now - new Date(a.answered_at) < 7*86400000 && SLACK_PAYROLL_WEBHOOK_URL){
      const client = await clientName(s.client_id);
      let shots = 0;
      { const {count,error:fe} = await admin.from('staff_files').select('id',{count:'exact',head:true}).eq('ts_ack_id',a.id).eq('ts_ack_round',a.round); if(!fe) shots = count||0; }
      const fields = [['Staff',s.full_name],['Client',client],['Period',dmRange(String(a.period_start).slice(0,10),String(a.period_end).slice(0,10))]];
      if(a.issue_date) fields.push(['Day',dmNiceDate(String(a.issue_date).slice(0,10))]);
      if(a.hours!=null) fields.push(['Hours they saw',String(a.hours)]);
      if(shots) fields.push(['Screenshots',`📎 ${shots} screenshot${shots===1?'':'s'} attached (open in the portal: Contractor Ledger → ⚠️ Issue)`]);
      const payload = slackPayload('⚠️ Timesheet Issue Reported', fields, 'Fix it in the portal, then use "Ask again" on the Contractor Ledger so they re-acknowledge.', a.issue_text||'', 'Issue');
      await sendSlackOnce({eventKey:`ts-issue:${a.id}:${a.round}`,destination:'payroll-and-sheet',eventType:'request',entityId:a.id,webhook:SLACK_PAYROLL_WEBHOOK_URL,payload})
        .catch(e=>console.error('Timesheet issue post failed:', e.message));
    }
  }
}

// pinger + portal "kick" (idempotent; rate limited)
async function dmSweepRoute(_req,res){
  const r = await dmSweep(false);
  res.json({ok:true, bot:!!SLACK_BOT_TOKEN, ...r, last:dmStats.last, lastError:dmStats.lastError});
}
app.get('/api/notify/sweep', notificationRateLimit, dmSweepRoute);
app.post('/api/notify/sweep', notificationRateLimit, dmSweepRoute);

// admin: instant Sent Early DM with the amount shown on the Ledger
app.post('/api/dm/sent-early', notificationRateLimit, async (req,res)=>{
  try{
    const adminRow = await requireAdmin(req,res); if(!adminRow) return;
    const staffId = String(req.body?.staff_id||''), cutoff = String(req.body?.cutoff_date||'');
    if(!uuidRe.test(staffId) || !/^\d{4}-\d{2}-\d{2}$/.test(cutoff)) return res.status(400).json({error:'staff_id and cutoff_date required.'});
    const amount = req.body?.amount==null ? null : Number(req.body.amount);
    if(amount!=null && (!Number.isFinite(amount) || amount<0 || amount>10000000)) return res.status(400).json({error:'Invalid amount.'});
    const {data:se} = await admin.from('ledger_extras').select('amount').eq('field_key','sent_early').eq('staff_id',staffId).eq('cutoff_date',cutoff).maybeSingle();
    if(!se || Number(se.amount)!==1) return res.status(409).json({error:'Sent Early is not ticked for this staff member and cutoff.'});
    const sm = await dmStaffMap([staffId]); const s = sm.get(staffId);
    if(!s) return res.status(404).json({error:'Staff not found.'});
    const r = await sendDmOnce({eventKey:`dm:early:${staffId}:${cutoff}`,entityId:`${staffId}:${cutoff}`,staff:s,...sentEarlyDm(cutoff,amount)});
    res.json({ok:true,...r});
  }catch(e){ console.error('Sent Early DM failed:',e); res.status(502).json({error:e.message||'DM failed.'}); }
});

// admin: which staff can receive DMs (Slack email match)
app.get('/api/dm/check', async (req,res)=>{
  try{
    const adminRow = await requireAdmin(req,res); if(!adminRow) return;
    if(!SLACK_BOT_TOKEN) return res.status(409).json({error:'SLACK_BOT_TOKEN is not set on Render yet.'});
    const {data:staff,error} = await admin.from('staff').select('id, full_name, email, role, active').eq('active',true).order('full_name');
    if(error) throw error;
    const out = [];
    for(const s of staff||[]){
      let slack = null, err = null;
      try{ slack = await slackUserIdFor(s.email); }catch(e){ err = e.slack||e.message; }
      out.push({id:s.id,name:s.full_name,email:s.email,role:s.role,matched:!!slack,error:err});
    }
    res.json({ok:true,staff:out,last_sweep:dmStats.last,last_error:dmStats.lastError,since:dmSinceIso});
  }catch(e){ console.error('DM check failed:',e); res.status(502).json({error:e.message||'Check failed.'}); }
});

// admin: test DM to yourself
app.post('/api/dm/test', notificationRateLimit, async (req,res)=>{
  try{
    const adminRow = await requireAdmin(req,res); if(!adminRow) return;
    const {data:s} = await admin.from('staff').select('id, full_name, email').eq('id',adminRow.id).single();
    const uid = await slackUserIdFor(s?.email);
    if(!uid) return res.status(404).json({error:`No Slack user found with your portal email (${s?.email||'none'}).`});
    await slackApi('chat.postMessage',{channel:uid,text:'Test DM from the SMB Portal',blocks:dmBlocks(['👋 *Test DM from the SMB Portal*','If you can read this, staff DMs are working.'],`Sent ${phtDateTime(new Date())}`)});
    res.json({ok:true});
  }catch(e){ console.error('Test DM failed:',e); res.status(502).json({error:e.slack==='missing_scope'?'Bagani is missing a Slack permission (scope). Re-check step 2 and reinstall.':(e.message||'Test DM failed.')}); }
});

setInterval(()=>dmSweep(true), 5*60*1000);
setTimeout(()=>dmSweep(true), 15000); // once shortly after boot

app.listen(PORT, () => console.log('SMB Time server listening on ' + PORT));
