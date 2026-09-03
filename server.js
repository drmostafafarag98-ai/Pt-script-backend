// Qalam PT Scribe — backend proxy
//
// AUTH MODEL: no shared password. Every request must carry a real Google
// access token (from the doctor's own Google sign-in, via a popup on the
// frontend) in the Authorization: Bearer <token> header. This server
// verifies that token with Google on every request, then checks the
// doctors table to confirm that email is an APPROVED doctor at this
// clinic before doing anything. Owner-only actions additionally require
// role = 'owner' in that table.
//
// The one exception is a one-time bootstrap step: OWNER_SECRET (an env
// var) is used ONLY to promote the very first signed-in user to owner,
// since the doctors table starts empty and someone has to be able to
// approve the first person.

const express = require('express');
const cors = require('cors');
const crypto = require('crypto');

const app = express();

const DEEPGRAM_API_KEY = process.env.DEEPGRAM_API_KEY || '';
const ANTHROPIC_API_KEY = process.env.ANTHROPIC_API_KEY || '';
const GEMINI_API_KEY = process.env.GEMINI_API_KEY || '';
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || '*';
const SUPABASE_URL = process.env.SUPABASE_URL || '';
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_KEY || '';
const OWNER_SECRET = process.env.OWNER_SECRET || '';

app.use(cors({ origin: ALLOWED_ORIGIN }));
app.use(express.json({ limit: '20mb' }));

// Our own long-lived session tokens, stored in a Supabase table
// (app_sessions: token text primary key, email text, created_at
// timestamptz, expires_at timestamptz). Created once after a real Google
// sign-in; from then on the frontend uses THIS token instead of the
// short-lived Google access token, so staying signed in no longer depends
// on Google's ~1hr token lifetime or on the browser keeping a Google
// session alive.
const APP_SESSION_DAYS = 30;

async function lookupAppSession(token) {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY || !token) return null;
  const url = `${SUPABASE_URL}/rest/v1/app_sessions?token=eq.${encodeURIComponent(token)}`;
  const res = await fetch(url, {
    headers: { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}` },
  });
  const rows = await res.json();
  const row = Array.isArray(rows) && rows.length > 0 ? rows[0] : null;
  if (!row) return null;
  if (new Date(row.expires_at).getTime() <= Date.now()) return null;
  return row;
}

async function createAppSession(email) {
  const token = crypto.randomBytes(32).toString('hex');
  const expiresAt = new Date(Date.now() + APP_SESSION_DAYS * 24 * 60 * 60 * 1000).toISOString();
  await fetch(`${SUPABASE_URL}/rest/v1/app_sessions`, {
    method: 'POST',
    headers: {
      apikey: SUPABASE_SERVICE_KEY,
      Authorization: `Bearer ${SUPABASE_SERVICE_KEY}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ token, email, expires_at: expiresAt }),
  });
  return token;
}

async function verifyGoogleToken(accessToken) {
  if (!accessToken) return null;
  // Try our own app session token first (the common case once someone has
  // signed in at least once) — this never calls Google at all.
  const session = await lookupAppSession(accessToken);
  if (session) return session.email;
  // Fall back to a real Google access token (first sign-in, or a session
  // that hasn't been issued one yet).
  try {
    const res = await fetch(
      `https://www.googleapis.com/oauth2/v3/tokeninfo?access_token=${encodeURIComponent(accessToken)}`
    );
    if (!res.ok) return null;
    const info = await res.json();
    return info.email || null;
  } catch (err) {
    console.error('Google token verify error:', err);
    return null;
  }
}

async function lookupDoctor(email) {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return null;
  const url = `${SUPABASE_URL}/rest/v1/doctors?email=eq.${encodeURIComponent(email)}`;
  const res = await fetch(url, {
    headers: { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}` },
  });
  const rows = await res.json();
  return Array.isArray(rows) && rows.length > 0 ? rows[0] : null;
}

// Manually-added doctors (added by the owner from the roster, before that
// doctor has ever signed in with Google) get a placeholder email at
// @empower.local instead of a real one — they're full, normal team members
// (name + color + approved status), just not yet linked to a Google
// account. This looks one up by name so /api/doctors/checkin can merge a
// real Google sign-in into the existing row instead of creating a
// duplicate.
async function lookupManualDoctorByName(name) {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY || !name) return null;
  const normalized = name.trim();
  if (!normalized) return null;
  const url = `${SUPABASE_URL}/rest/v1/doctors?email=like.*@empower.local&name=ilike.${encodeURIComponent(normalized)}`;
  const res = await fetch(url, {
    headers: { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}` },
  });
  const rows = await res.json();
  return Array.isArray(rows) && rows.length > 0 ? rows[0] : null;
}

function extractBearerToken(req) {
  const header = req.header('authorization') || '';
  const match = header.match(/^Bearer\s+(.+)$/i);
  return match ? match[1] : null;
}

async function requireApprovedDoctor(req, res, next) {
  const token = extractBearerToken(req);
  const email = await verifyGoogleToken(token);
  if (!email) {
    return res.status(401).json({ error: 'Sign in with Google required.' });
  }
  const doctor = await lookupDoctor(email);
  if (!doctor || doctor.status !== 'approved') {
    return res.status(403).json({
      error: doctor ? 'Your access is pending approval from the clinic owner.' : 'You are not registered at this clinic yet.',
    });
  }
  if (doctor.role === 'secretary') {
    return res.status(403).json({ error: 'Secretary accounts only have access to the calendar.' });
  }
  req.doctor = doctor;
  next();
}

// Any approved role (doctor, owner, or secretary) — used for calendar
// endpoints, since secretaries need to view/book appointments too.
async function requireApprovedAny(req, res, next) {
  const token = extractBearerToken(req);
  const email = await verifyGoogleToken(token);
  if (!email) {
    return res.status(401).json({ error: 'Sign in with Google required.' });
  }
  const doctor = await lookupDoctor(email);
  if (!doctor || doctor.status !== 'approved') {
    return res.status(403).json({
      error: doctor ? 'Your access is pending approval from the clinic owner.' : 'You are not registered at this clinic yet.',
    });
  }
  req.doctor = doctor;
  next();
}

async function requireOwnerDoctor(req, res, next) {
  const token = extractBearerToken(req);
  const email = await verifyGoogleToken(token);
  if (!email) {
    return res.status(401).json({ error: 'Sign in with Google required.' });
  }
  const doctor = await lookupDoctor(email);
  if (!doctor || doctor.status !== 'approved' || doctor.role !== 'owner') {
    return res.status(403).json({ error: 'Owner access required.' });
  }
  req.doctor = doctor;
  next();
}

// Owner or secretary — used for calendar-color management, since
// secretaries handle the schedule day-to-day but shouldn't approve staff.
async function requireOwnerOrSecretary(req, res, next) {
  const token = extractBearerToken(req);
  const email = await verifyGoogleToken(token);
  if (!email) {
    return res.status(401).json({ error: 'Sign in with Google required.' });
  }
  const doctor = await lookupDoctor(email);
  if (!doctor || doctor.status !== 'approved' || (doctor.role !== 'owner' && doctor.role !== 'secretary')) {
    return res.status(403).json({ error: 'Owner or secretary access required.' });
  }
  req.doctor = doctor;
  next();
}

app.post(
  '/api/transcribe',
  requireApprovedDoctor,
  express.raw({ type: '*/*', limit: '50mb' }),
  async (req, res) => {
    if (!DEEPGRAM_API_KEY) {
      return res.status(500).json({ error: 'Server is missing DEEPGRAM_API_KEY.' });
    }
    try {
      const queryString = req.url.split('?')[1] || '';
      const deepgramUrl = `https://api.deepgram.com/v1/listen?${queryString}`;
      const contentType = req.header('content-type') || 'audio/webm';
      const upstream = await fetch(deepgramUrl, {
        method: 'POST',
        headers: { Authorization: `Token ${DEEPGRAM_API_KEY}`, 'Content-Type': contentType },
        body: req.body,
      });
      const data = await upstream.text();
      res.status(upstream.status).type('application/json').send(data);
    } catch (err) {
      console.error('Transcribe proxy error:', err);
      res.status(500).json({ error: 'Transcription proxy failed: ' + err.message });
    }
  }
);

app.post('/api/ai', requireApprovedDoctor, async (req, res) => {
  const { systemPrompt, userContent, maxTokens, provider } = req.body || {};
  if (!systemPrompt || !userContent) {
    return res.status(400).json({ error: 'Missing systemPrompt or userContent.' });
  }
  const tokens = maxTokens || 4000;
  try {
    if (provider === 'gemini') {
      if (!GEMINI_API_KEY) return res.status(500).json({ error: 'Server is missing GEMINI_API_KEY.' });
      const url = `https://generativelanguage.googleapis.com/v1beta/models/gemini-3.6-flash:generateContent?key=${encodeURIComponent(GEMINI_API_KEY)}`;
      const upstream = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          contents: [{ parts: [{ text: userContent }] }],
          systemInstruction: { parts: [{ text: systemPrompt }] },
          generationConfig: { maxOutputTokens: tokens },
        }),
      });
      const data = await upstream.json();
      if (!upstream.ok) return res.status(upstream.status).json({ error: JSON.stringify(data).slice(0, 300) });
      const text = (data?.candidates?.[0]?.content?.parts || []).map((p) => p.text || '').join('');
      return res.json({ text });
    } else {
      if (!ANTHROPIC_API_KEY) return res.status(500).json({ error: 'Server is missing ANTHROPIC_API_KEY.' });
      const upstream = await fetch('https://api.anthropic.com/v1/messages', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-api-key': ANTHROPIC_API_KEY,
          'anthropic-version': '2023-06-01',
        },
        body: JSON.stringify({
          model: 'claude-sonnet-5',
          max_tokens: tokens,
          system: systemPrompt,
          messages: [{ role: 'user', content: userContent }],
        }),
      });
      const data = await upstream.json();
      if (!upstream.ok) return res.status(upstream.status).json({ error: JSON.stringify(data).slice(0, 300) });
      const text = (data.content || []).filter((b) => b.type === 'text').map((b) => b.text).join('');
      return res.json({ text });
    }
  } catch (err) {
    console.error('AI proxy error:', err);
    res.status(500).json({ error: 'AI proxy failed: ' + err.message });
  }
});

// ---- Clinic-wide settings (key-value store) ----
// Any approved role can read (everyone needs to see the current elevator
// code, for example), but only the owner or secretary can change one.
app.get('/api/settings/:key', requireApprovedAny, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  try {
    const url = `${SUPABASE_URL}/rest/v1/clinic_settings?key=eq.${encodeURIComponent(req.params.key)}`;
    const upstream = await fetch(url, {
      headers: { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}` },
    });
    const rows = await upstream.json();
    const row = Array.isArray(rows) && rows.length > 0 ? rows[0] : null;
    res.json({ key: req.params.key, value: row ? row.value : null, updated_at: row ? row.updated_at : null });
  } catch (err) {
    console.error('Settings read error:', err);
    res.status(500).json({ error: 'Failed to read setting: ' + err.message });
  }
});

app.post('/api/settings/:key', requireOwnerOrSecretary, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  const { value } = req.body || {};
  try {
    const url = `${SUPABASE_URL}/rest/v1/clinic_settings`;
    const upstream = await fetch(url, {
      method: 'POST',
      headers: {
        apikey: SUPABASE_SERVICE_KEY,
        Authorization: `Bearer ${SUPABASE_SERVICE_KEY}`,
        'Content-Type': 'application/json',
        Prefer: 'resolution=merge-duplicates,return=representation',
      },
      body: JSON.stringify({ key: req.params.key, value: value || '', updated_at: new Date().toISOString() }),
    });
    const data = await upstream.json();
    if (!upstream.ok) {
      console.error('Settings write failed:', upstream.status, data);
      return res.status(500).json({ error: 'Could not save setting.' });
    }
    res.json(Array.isArray(data) ? data[0] : data);
  } catch (err) {
    console.error('Settings write error:', err);
    res.status(500).json({ error: 'Failed to save setting: ' + err.message });
  }
});

// ---- GET /api/patients ----
// A quick "have we seen this patient before" lookup, built from past
// appointments (name + their most recent phone number) rather than a
// separate patients table. Used by the frontend to autocomplete the name
// and auto-fill the phone when booking a returning patient again.
app.get('/api/patients', requireApprovedAny, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  try {
    const url = `${SUPABASE_URL}/rest/v1/appointments?select=patient_name,patient_phone,start_time&order=start_time.desc&limit=1000`;
    const upstream = await fetch(url, { headers: { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}` } });
    const rows = await upstream.json();
    if (!upstream.ok) {
      console.error('Patients GET error:', upstream.status, rows);
      return res.status(500).json({ error: 'Failed to load patients.' });
    }
    const seen = new Map();
    (rows || []).forEach(r => {
      const name = (r.patient_name || '').trim();
      if (!name) return;
      const key = name.toLowerCase();
      if (!seen.has(key)) seen.set(key, { name, phone: r.patient_phone || null });
    });
    res.json(Array.from(seen.values()));
  } catch (err) {
    console.error('Patients GET error:', err);
    res.status(500).json({ error: 'Failed to load patients: ' + err.message });
  }
});

// ---- GET /api/appointments/unpaid-by-patient ----
// A patient doesn't always pay per-session — sometimes one payment covers
// this session plus an earlier unpaid one. This lets the owner see every
// unpaid appointment for that patient name so they can pick which ones a
// single payment settles.
app.get('/api/appointments/unpaid-by-patient', requireApprovedAny, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  const { patientName } = req.query;
  if (!patientName) return res.status(400).json({ error: 'Missing patientName.' });
  try {
    const url = `${SUPABASE_URL}/rest/v1/appointments?patient_name=eq.${encodeURIComponent(patientName)}&paid=eq.false&status=neq.cancelled&order=start_time.desc&limit=20`;
    const upstream = await fetch(url, { headers: { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}` } });
    const data = await upstream.text();
    res.status(upstream.status).type('application/json').send(data);
  } catch (err) {
    console.error('Unpaid-by-patient GET error:', err);
    res.status(500).json({ error: 'Failed to load unpaid appointments: ' + err.message });
  }
});

app.get('/api/appointments', requireApprovedAny, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  const { start, end } = req.query;
  if (!start || !end) return res.status(400).json({ error: 'Missing start or end query params.' });
  try {
    const url = `${SUPABASE_URL}/rest/v1/appointments?start_time=gte.${encodeURIComponent(start)}&start_time=lte.${encodeURIComponent(end)}&order=start_time.asc`;
    const upstream = await fetch(url, { headers: { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}` } });
    const data = await upstream.text();
    res.status(upstream.status).type('application/json').send(data);
  } catch (err) {
    console.error('Appointments GET error:', err);
    res.status(500).json({ error: 'Failed to load appointments: ' + err.message });
  }
});

app.post('/api/appointments', requireApprovedAny, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  const { patientName, startTime, endTime, doctorColor, doctorName, patientPhone } = req.body || {};
  if (!patientName || !startTime || !endTime) return res.status(400).json({ error: 'Missing patientName, startTime, or endTime.' });
  try {
    const url = `${SUPABASE_URL}/rest/v1/appointments`;
    const upstream = await fetch(url, {
      method: 'POST',
      headers: {
        apikey: SUPABASE_SERVICE_KEY,
        Authorization: `Bearer ${SUPABASE_SERVICE_KEY}`,
        'Content-Type': 'application/json',
        Prefer: 'return=representation',
      },
      body: JSON.stringify({
        patient_name: patientName,
        start_time: startTime,
        end_time: endTime,
        doctor_color: doctorColor || req.doctor.color || null,
        doctor_name: doctorName || req.doctor.name || req.doctor.email,
        patient_phone: patientPhone || null,
      }),
    });
    const data = await upstream.text();
    res.status(upstream.status).type('application/json').send(data);
  } catch (err) {
    console.error('Appointments POST error:', err);
    res.status(500).json({ error: 'Failed to book appointment: ' + err.message });
  }
});

// ---- PATCH /api/appointments/:id ----
// Edits an existing booking — any subset of patientName, patientPhone,
// startTime, endTime, doctorColor, doctorName. Same access as booking
// (owner, doctor, or secretary), since secretaries manage the day-to-day
// calendar too.
app.patch('/api/appointments/:id', requireApprovedAny, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  const { patientName, patientPhone, startTime, endTime, doctorColor, doctorName, status, paid } = req.body || {};
  const patch = {};
  if (patientName !== undefined) patch.patient_name = patientName;
  if (patientPhone !== undefined) patch.patient_phone = patientPhone || null;
  if (startTime !== undefined) patch.start_time = startTime;
  if (endTime !== undefined) patch.end_time = endTime;
  if (doctorColor !== undefined) patch.doctor_color = doctorColor || null;
  if (doctorName !== undefined) patch.doctor_name = doctorName || null;
  if (status !== undefined) patch.status = status;
  if (paid !== undefined) patch.paid = paid;
  if (Object.keys(patch).length === 0) return res.status(400).json({ error: 'Nothing to update.' });
  try {
    const url = `${SUPABASE_URL}/rest/v1/appointments?id=eq.${encodeURIComponent(req.params.id)}`;
    const upstream = await fetch(url, {
      method: 'PATCH',
      headers: {
        apikey: SUPABASE_SERVICE_KEY,
        Authorization: `Bearer ${SUPABASE_SERVICE_KEY}`,
        'Content-Type': 'application/json',
        Prefer: 'return=representation',
      },
      body: JSON.stringify(patch),
    });
    const data = await upstream.text();
    res.status(upstream.status).type('application/json').send(data);
  } catch (err) {
    console.error('Appointment PATCH error:', err);
    res.status(500).json({ error: 'Failed to update appointment: ' + err.message });
  }
});

// ---- DELETE /api/appointments/:id ----
app.delete('/api/appointments/:id', requireApprovedAny, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  try {
    const url = `${SUPABASE_URL}/rest/v1/appointments?id=eq.${encodeURIComponent(req.params.id)}`;
    const upstream = await fetch(url, {
      method: 'DELETE',
      headers: {
        apikey: SUPABASE_SERVICE_KEY,
        Authorization: `Bearer ${SUPABASE_SERVICE_KEY}`,
      },
    });
    res.status(upstream.status).json({ ok: upstream.ok });
  } catch (err) {
    console.error('Appointment DELETE error:', err);
    res.status(500).json({ error: 'Failed to delete appointment: ' + err.message });
  }
});

// ---- WhatsApp webhook (Meta calls these directly, so no doctor-auth
// middleware here — protected by the verify token instead). ----
const META_WEBHOOK_VERIFY_TOKEN = process.env.META_WEBHOOK_VERIFY_TOKEN || 'empower_verify_2026';

app.get('/api/whatsapp/webhook', (req, res) => {
  const mode = req.query['hub.mode'];
  const token = req.query['hub.verify_token'];
  const challenge = req.query['hub.challenge'];
  if (mode === 'subscribe' && token === META_WEBHOOK_VERIFY_TOKEN) {
    res.status(200).send(challenge);
  } else {
    res.sendStatus(403);
  }
});

app.post('/api/whatsapp/webhook', (req, res) => {
  // Logs incoming messages/status updates for now (visible in Render logs).
  // This is the hook point for the payment-confirmation flow later: detect
  // whether a reply contains an image, and if not, resend the payment link.
  console.log('WhatsApp webhook event:', JSON.stringify(req.body));
  res.sendStatus(200);
});

// ---- WhatsApp Cloud API: reusable sender ----
function normalizeEgyptPhone(raw) {
  let digits = String(raw || '').replace(/[^\d]/g, '');
  if (digits.startsWith('0')) digits = digits.slice(1);
  if (!digits.startsWith('20')) digits = '20' + digits;
  return digits;
}

// Meta requires an APPROVED template (not free-form text) for any message
// outside an active 24h customer-initiated window — the same whether you
// go direct or through a BSP. `params` is an array of plain strings for
// the template's {{1}} {{2}} {{3}}... body variables; pass an empty array
// for a template with no variables (package_policy, recovery_session_policy).
async function sendWhatsAppTemplate(phone, templateName, params) {
  const META_PHONE_NUMBER_ID = process.env.META_WHATSAPP_PHONE_NUMBER_ID || '';
  const META_ACCESS_TOKEN = process.env.META_WHATSAPP_ACCESS_TOKEN || '';
  if (!META_PHONE_NUMBER_ID || !META_ACCESS_TOKEN) {
    throw new Error('WhatsApp Business API is not set up — set META_WHATSAPP_PHONE_NUMBER_ID and META_WHATSAPP_ACCESS_TOKEN in Render.');
  }
  const normalizedPhone = normalizeEgyptPhone(phone);
  const url = `https://graph.facebook.com/v21.0/${META_PHONE_NUMBER_ID}/messages`;
  const template = { name: templateName, language: { code: 'en' } };
  if (params && params.length > 0) {
    template.components = [{ type: 'body', parameters: params.map(p => ({ type: 'text', text: String(p || '') })) }];
  }
  const payload = { messaging_product: 'whatsapp', to: normalizedPhone, type: 'template', template };
  const upstream = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${META_ACCESS_TOKEN}` },
    body: JSON.stringify(payload),
  });
  const data = await upstream.json();
  if (!upstream.ok) {
    throw new Error((data.error && data.error.message) || 'Failed to send WhatsApp message.');
  }
  return data.messages && data.messages[0] && data.messages[0].id;
}

app.post('/api/whatsapp/send-reminder', requireApprovedAny, async (req, res) => {
  const { patientPhone, patientName, appointmentTime, appointmentDate, templateName } = req.body || {};
  if (!patientPhone) return res.status(400).json({ error: 'Missing patientPhone.' });
  const finalTemplate = templateName || 'appointment_confirmation';
  // Static (no-variable) templates vs. the two that take name/date/time.
  const noVariableTemplates = ['package_policy', 'recovery_session_policy', 'instapay_payment'];
  const params = noVariableTemplates.includes(finalTemplate)
    ? []
    : [patientName || '', appointmentDate || '', appointmentTime || ''];
  try {
    const messageId = await sendWhatsAppTemplate(patientPhone, finalTemplate, params);
    res.json({ ok: true, messageId });
  } catch (err) {
    console.error('Meta WhatsApp send failed:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// ---- Automatic midnight sending ----
// Runs inside this same always-on process (kept awake by the UptimeRobot
// monitor) — no separate cron infrastructure needed. Checks every 5
// minutes; once per day, the first check that lands between 00:00 and
// 00:10 Cairo time fires the run and then waits for the date to change
// again before it can fire a second time.
let lastAutoSendDate = null;
async function runMidnightAutoConfirmations() {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return;
  const nowCairo = new Date(new Date().toLocaleString('en-US', { timeZone: 'Africa/Cairo' }));
  const todayKey = nowCairo.toISOString().slice(0, 10);
  const isMidnightWindow = nowCairo.getHours() === 0 && nowCairo.getMinutes() < 10;
  if (!isMidnightWindow || lastAutoSendDate === todayKey) return;
  lastAutoSendDate = todayKey;
  console.log(`[auto-confirm] Running for ${todayKey}`);
  try {
    const tomorrow = new Date(nowCairo.getFullYear(), nowCairo.getMonth(), nowCairo.getDate() + 1);
    const start = new Date(tomorrow.getFullYear(), tomorrow.getMonth(), tomorrow.getDate(), 0, 0, 0);
    const end = new Date(tomorrow.getFullYear(), tomorrow.getMonth(), tomorrow.getDate(), 23, 59, 59);
    const url = `${SUPABASE_URL}/rest/v1/appointments?start_time=gte.${encodeURIComponent(start.toISOString())}&start_time=lte.${encodeURIComponent(end.toISOString())}&status=neq.cancelled`;
    const res = await fetch(url, { headers: { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}` } });
    const appointments = await res.json();
    if (!Array.isArray(appointments)) return;
    for (const appt of appointments) {
      if (!appt.patient_phone) continue;
      const apptDate = new Date(appt.start_time);
      const dateLabel = apptDate.toLocaleDateString('en-GB', { timeZone: 'Africa/Cairo', weekday: 'long', day: 'numeric', month: 'long' });
      const timeLabel = apptDate.toLocaleTimeString('en-US', { timeZone: 'Africa/Cairo', hour: 'numeric', minute: '2-digit', hour12: true });
      try {
        await sendWhatsAppTemplate(appt.patient_phone, 'appointment_confirmation', [appt.patient_name || '', dateLabel, timeLabel]);
        console.log(`[auto-confirm] Sent to ${appt.patient_name} (${appt.patient_phone})`);
      } catch (err) {
        console.error(`[auto-confirm] Failed for ${appt.patient_name} (${appt.patient_phone}):`, err.message);
      }
      await new Promise(r => setTimeout(r, 1200)); // gentle pacing, avoid tripping Meta's rate limits
    }
    console.log(`[auto-confirm] Done — ${appointments.length} appointment(s) checked.`);
  } catch (err) {
    console.error('[auto-confirm] Run failed:', err);
  }
}
// DISABLED for now — the Cloud API test showed "sent" without an actual
// delivery (likely needs Meta Business Verification / a recipient
// allow-list before it can message real numbers). Re-enable this line
// once a test message is confirmed actually arriving on WhatsApp.
// setInterval(runMidnightAutoConfirmations, 5 * 60 * 1000);

// ---- GET /api/appointments/:id/notes ----
app.get('/api/appointments/:id/notes', requireApprovedAny, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  try {
    const url = `${SUPABASE_URL}/rest/v1/appointments?id=eq.${encodeURIComponent(req.params.id)}&select=notes,patient_name`;
    const upstream = await fetch(url, {
      headers: { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}` },
    });
    const rows = await upstream.json();
    const row = Array.isArray(rows) && rows.length > 0 ? rows[0] : null;
    res.json({ patientName: row ? row.patient_name : null, notes: (row && row.notes) || [] });
  } catch (err) {
    console.error('Appointment notes GET error:', err);
    res.status(500).json({ error: 'Failed to load notes: ' + err.message });
  }
});

// ---- DELETE /api/appointments/:id/notes ---- (remove one note by its timestamp)
app.delete('/api/appointments/:id/notes', requireApprovedAny, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  const { at } = req.query;
  if (!at) return res.status(400).json({ error: 'Missing at (note timestamp).' });
  try {
    const getUrl = `${SUPABASE_URL}/rest/v1/appointments?id=eq.${encodeURIComponent(req.params.id)}&select=notes`;
    const getRes = await fetch(getUrl, {
      headers: { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}` },
    });
    const rows = await getRes.json();
    const existingNotes = (Array.isArray(rows) && rows[0] && rows[0].notes) || [];
    const updatedNotes = existingNotes.filter(n => n.at !== at);
    const patchUrl = `${SUPABASE_URL}/rest/v1/appointments?id=eq.${encodeURIComponent(req.params.id)}`;
    const patchRes = await fetch(patchUrl, {
      method: 'PATCH',
      headers: {
        apikey: SUPABASE_SERVICE_KEY,
        Authorization: `Bearer ${SUPABASE_SERVICE_KEY}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ notes: updatedNotes }),
    });
    if (!patchRes.ok) {
      const errBody = await patchRes.text();
      throw new Error(errBody);
    }
    res.json({ notes: updatedNotes });
  } catch (err) {
    console.error('Appointment notes DELETE error:', err);
    res.status(500).json({ error: 'Failed to delete note: ' + err.message });
  }
});

// ---- POST /api/appointments/:id/notes ---- (append one note)
app.post('/api/appointments/:id/notes', requireApprovedAny, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  const { text } = req.body || {};
  if (!text || !text.trim()) return res.status(400).json({ error: 'Missing note text.' });
  try {
    const getUrl = `${SUPABASE_URL}/rest/v1/appointments?id=eq.${encodeURIComponent(req.params.id)}&select=notes`;
    const getRes = await fetch(getUrl, {
      headers: { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}` },
    });
    const rows = await getRes.json();
    const existingNotes = (Array.isArray(rows) && rows[0] && rows[0].notes) || [];
    const newNote = {
      text: text.trim(),
      author: req.doctor.name || req.doctor.email,
      at: new Date().toISOString(),
    };
    const updatedNotes = [...existingNotes, newNote];
    const patchUrl = `${SUPABASE_URL}/rest/v1/appointments?id=eq.${encodeURIComponent(req.params.id)}`;
    const patchRes = await fetch(patchUrl, {
      method: 'PATCH',
      headers: {
        apikey: SUPABASE_SERVICE_KEY,
        Authorization: `Bearer ${SUPABASE_SERVICE_KEY}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ notes: updatedNotes }),
    });
    if (!patchRes.ok) {
      const errBody = await patchRes.text();
      throw new Error(errBody);
    }
    res.json({ notes: updatedNotes });
  } catch (err) {
    console.error('Appointment notes POST error:', err);
    res.status(500).json({ error: 'Failed to add note: ' + err.message });
  }
});

// ---- PATCH /api/sessions/rename-doctor ----
// A session's doctor_name is a snapshot taken when it was saved (same
// idea as appointments' doctor_color/doctor_name) — it doesn't
// automatically follow later renames or account merges. This lets the
// owner fix the sidebar showing the same person's sessions split across
// several name spellings, by bulk-renaming every session under fromName
// to toName in one go.
app.patch('/api/sessions/rename-doctor', requireOwnerDoctor, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  const { fromName, toName } = req.body || {};
  if (!fromName || !toName) return res.status(400).json({ error: 'Missing fromName or toName.' });
  try {
    // Fetch every session and match by TRIMMED name in JS, rather than an
    // exact eq. filter against the raw column — a stray leading/trailing
    // space in the stored value (invisible in the UI, which trims for
    // display) would otherwise make the filter match zero rows while the
    // endpoint still reports success, so nothing visibly changes.
    const allRes = await fetch(`${SUPABASE_URL}/rest/v1/sessions?select=id,doctor_name`, {
      headers: { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}` },
    });
    const allSessions = await allRes.json();
    if (!allRes.ok) {
      console.error('Session rename-doctor: could not list sessions', allRes.status, allSessions);
      return res.status(500).json({ error: 'Could not read sessions to merge.' });
    }
    const target = fromName.trim();
    const matchingIds = (allSessions || [])
      .filter(s => (s.doctor_name || '').trim() === target)
      .map(s => s.id);
    if (matchingIds.length === 0) {
      return res.status(404).json({ error: `No sessions found under "${fromName}" (nothing to merge).` });
    }
    const idList = matchingIds.map(id => `"${id}"`).join(',');
    const updateRes = await fetch(`${SUPABASE_URL}/rest/v1/sessions?id=in.(${idList})`, {
      method: 'PATCH',
      headers: {
        apikey: SUPABASE_SERVICE_KEY,
        Authorization: `Bearer ${SUPABASE_SERVICE_KEY}`,
        'Content-Type': 'application/json',
        Prefer: 'return=representation',
      },
      body: JSON.stringify({ doctor_name: toName.trim() }),
    });
    const data = await updateRes.json();
    if (!updateRes.ok) {
      console.error('Session rename-doctor failed:', updateRes.status, data);
      return res.status(500).json({ error: 'Failed to rename sessions.' });
    }
    res.json({ ok: true, count: Array.isArray(data) ? data.length : 0 });
  } catch (err) {
    console.error('Session rename-doctor error:', err);
    res.status(500).json({ error: 'Failed to rename sessions: ' + err.message });
  }
});

app.post('/api/sessions', requireApprovedDoctor, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  const { id, patientName, sessionDate, sessionType, transcript, note } = req.body || {};
  if (!id || !patientName) return res.status(400).json({ error: 'Missing id or patientName.' });
  try {
    const url = `${SUPABASE_URL}/rest/v1/sessions?on_conflict=id`;
    const upstream = await fetch(url, {
      method: 'POST',
      headers: {
        apikey: SUPABASE_SERVICE_KEY,
        Authorization: `Bearer ${SUPABASE_SERVICE_KEY}`,
        'Content-Type': 'application/json',
        Prefer: 'resolution=merge-duplicates,return=representation',
      },
      body: JSON.stringify({
        id,
        patient_name: patientName,
        session_date: sessionDate || null,
        session_type: sessionType || null,
        transcript: transcript || null,
        note: note || null,
        doctor_name: req.doctor.name || req.doctor.email,
        updated_at: new Date().toISOString(),
      }),
    });
    const data = await upstream.text();
    res.status(upstream.status).type('application/json').send(data);
  } catch (err) {
    console.error('Sessions POST error:', err);
    res.status(500).json({ error: 'Failed to save session: ' + err.message });
  }
});

app.get('/api/sessions', requireApprovedDoctor, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  try {
    const { patientName, order } = req.query;
    let url = `${SUPABASE_URL}/rest/v1/sessions?order=${order === 'asc' ? 'created_at.asc' : 'created_at.desc'}`;
    if (patientName) {
      url += `&patient_name=ilike.${encodeURIComponent('%' + patientName + '%')}`;
    }
    const upstream = await fetch(url, { headers: { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}` } });
    const data = await upstream.text();
    res.status(upstream.status).type('application/json').send(data);
  } catch (err) {
    console.error('Sessions GET error:', err);
    res.status(500).json({ error: 'Failed to load sessions: ' + err.message });
  }
});

// ---- Session images (Supabase Storage — cross-device, unlike the old
// device-only IndexedDB storage) ----
const IMAGE_BUCKET = 'session-images';

app.post('/api/sessions/:id/images', requireApprovedDoctor, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  const { base64Data, mimeType, filename } = req.body || {};
  if (!base64Data || !mimeType) return res.status(400).json({ error: 'Missing base64Data or mimeType.' });
  try {
    const bytes = Buffer.from(base64Data, 'base64');
    const ext = (mimeType.split('/')[1] || 'jpg').replace(/[^a-z0-9]/gi, '');
    const safeName = (filename || 'image').replace(/[^a-zA-Z0-9._-]/g, '_');
    const path = `${req.params.id}/${Date.now()}_${safeName}.${ext}`;
    const uploadUrl = `${SUPABASE_URL}/storage/v1/object/${IMAGE_BUCKET}/${path}`;
    const upstream = await fetch(uploadUrl, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${SUPABASE_SERVICE_KEY}`,
        'Content-Type': mimeType,
        'x-upsert': 'false',
      },
      body: bytes,
    });
    const data = await upstream.json();
    if (!upstream.ok) {
      console.error('Image upload failed:', data);
      return res.status(500).json({ error: data.message || 'Failed to upload image.' });
    }
    res.json({ ok: true, path });
  } catch (err) {
    console.error('Image upload error:', err);
    res.status(500).json({ error: 'Failed to upload image: ' + err.message });
  }
});

app.get('/api/sessions/:id/images', requireApprovedDoctor, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  try {
    const listUrl = `${SUPABASE_URL}/storage/v1/object/list/${IMAGE_BUCKET}`;
    const listRes = await fetch(listUrl, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${SUPABASE_SERVICE_KEY}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ prefix: `${req.params.id}/`, limit: 200, sortBy: { column: 'created_at', order: 'asc' } }),
    });
    const files = await listRes.json();
    if (!listRes.ok) {
      console.error('Image list failed:', files);
      return res.status(500).json({ error: 'Failed to list images.' });
    }
    if (!Array.isArray(files) || files.length === 0) return res.json([]);
    // Batch-sign all paths in one call rather than one request per image.
    const signUrl = `${SUPABASE_URL}/storage/v1/object/sign/${IMAGE_BUCKET}`;
    const signRes = await fetch(signUrl, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${SUPABASE_SERVICE_KEY}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        expiresIn: 3600,
        paths: files.map(f => `${req.params.id}/${f.name}`),
      }),
    });
    const signed = await signRes.json();
    if (!signRes.ok) {
      console.error('Image sign failed:', signed);
      return res.status(500).json({ error: 'Failed to sign image URLs.' });
    }
    const result = files.map((f, i) => ({
      path: `${req.params.id}/${f.name}`,
      filename: f.name,
      url: signed[i] && signed[i].signedURL ? `${SUPABASE_URL}/storage/v1${signed[i].signedURL}` : null,
      createdAt: f.created_at,
    }));
    res.json(result);
  } catch (err) {
    console.error('Image list error:', err);
    res.status(500).json({ error: 'Failed to list images: ' + err.message });
  }
});

app.delete('/api/sessions/:id/images', requireApprovedDoctor, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  const { path } = req.body || {};
  if (!path || !path.startsWith(`${req.params.id}/`)) return res.status(400).json({ error: 'Invalid or missing path.' });
  try {
    const deleteUrl = `${SUPABASE_URL}/storage/v1/object/${IMAGE_BUCKET}`;
    const upstream = await fetch(deleteUrl, {
      method: 'DELETE',
      headers: {
        Authorization: `Bearer ${SUPABASE_SERVICE_KEY}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ prefixes: [path] }),
    });
    if (!upstream.ok) {
      const errData = await upstream.json();
      console.error('Image delete failed:', errData);
      return res.status(500).json({ error: 'Failed to delete image.' });
    }
    res.json({ ok: true });
  } catch (err) {
    console.error('Image delete error:', err);
    res.status(500).json({ error: 'Failed to delete image: ' + err.message });
  }
});

app.post('/api/sessions/:id/request-delete', requireApprovedDoctor, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  try {
    const url = `${SUPABASE_URL}/rest/v1/sessions?id=eq.${encodeURIComponent(req.params.id)}`;
    const upstream = await fetch(url, {
      method: 'PATCH',
      headers: {
        apikey: SUPABASE_SERVICE_KEY,
        Authorization: `Bearer ${SUPABASE_SERVICE_KEY}`,
        'Content-Type': 'application/json',
        Prefer: 'return=representation',
      },
      body: JSON.stringify({
        delete_requested: true,
        delete_requested_by: req.doctor.name || req.doctor.email,
        delete_requested_at: new Date().toISOString(),
      }),
    });
    const data = await upstream.text();
    res.status(upstream.status).type('application/json').send(data);
  } catch (err) {
    console.error('Request-delete error:', err);
    res.status(500).json({ error: 'Failed to request delete: ' + err.message });
  }
});

app.get('/api/sessions/pending-deletes', requireOwnerDoctor, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  try {
    const url = `${SUPABASE_URL}/rest/v1/sessions?delete_requested=eq.true&order=delete_requested_at.desc`;
    const upstream = await fetch(url, { headers: { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}` } });
    const data = await upstream.text();
    res.status(upstream.status).type('application/json').send(data);
  } catch (err) {
    console.error('Pending-deletes GET error:', err);
    res.status(500).json({ error: 'Failed to load pending deletes: ' + err.message });
  }
});

app.post('/api/sessions/:id/approve-delete', requireOwnerDoctor, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  try {
    const url = `${SUPABASE_URL}/rest/v1/sessions?id=eq.${encodeURIComponent(req.params.id)}`;
    const upstream = await fetch(url, {
      method: 'DELETE',
      headers: { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}` },
    });
    res.status(upstream.status).json({ ok: upstream.ok });
  } catch (err) {
    console.error('Approve-delete error:', err);
    res.status(500).json({ error: 'Failed to delete session: ' + err.message });
  }
});

app.post('/api/sessions/:id/reject-delete', requireOwnerDoctor, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  try {
    const url = `${SUPABASE_URL}/rest/v1/sessions?id=eq.${encodeURIComponent(req.params.id)}`;
    const upstream = await fetch(url, {
      method: 'PATCH',
      headers: {
        apikey: SUPABASE_SERVICE_KEY,
        Authorization: `Bearer ${SUPABASE_SERVICE_KEY}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ delete_requested: false, delete_requested_by: null, delete_requested_at: null }),
    });
    res.status(upstream.status).json({ ok: upstream.ok });
  } catch (err) {
    console.error('Reject-delete error:', err);
    res.status(500).json({ error: 'Failed to reject delete: ' + err.message });
  }
});

// ---- POST /api/doctors/checkin ----
app.post('/api/doctors/checkin', async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  const token = extractBearerToken(req);
  // Distinguish "resuming with our own session token" (no new session
  // needed) from "a real Google token came in" (issue a fresh 30-day app
  // session, this is a first sign-in on this device).
  const existingSession = await lookupAppSession(token);
  const email = existingSession ? existingSession.email : await verifyGoogleToken(token);
  if (!email) return res.status(401).json({ error: 'Invalid or expired Google token.' });
  const newSessionToken = existingSession ? null : await createAppSession(email);
  const { name } = req.body || {};
  try {
    const existing = await lookupDoctor(email);
    if (existing) return res.json(newSessionToken ? { ...existing, session_token: newSessionToken } : existing);

    // No row for this exact Google email yet — check whether the owner
    // already added this person manually (by name) before they ever
    // signed in. If so, link this Google email into that existing row
    // (keeping their color/status/history) instead of creating a new one.
    const manualMatch = await lookupManualDoctorByName(name);
    if (manualMatch) {
      const linkUrl = `${SUPABASE_URL}/rest/v1/doctors?email=eq.${encodeURIComponent(manualMatch.email)}`;
      const linkRes = await fetch(linkUrl, {
        method: 'PATCH',
        headers: {
          apikey: SUPABASE_SERVICE_KEY,
          Authorization: `Bearer ${SUPABASE_SERVICE_KEY}`,
          'Content-Type': 'application/json',
          Prefer: 'return=representation',
        },
        body: JSON.stringify({ email }),
      });
      const linked = await linkRes.json();
      if (!linkRes.ok) {
        console.error('Doctor auto-link failed:', linkRes.status, linked);
        return res.status(500).json({ error: 'Could not link your account: ' + (linked.message || JSON.stringify(linked)).slice(0, 300) });
      }
      const linkedRow = Array.isArray(linked) ? linked[0] : linked;
      return res.json(newSessionToken ? { ...linkedRow, session_token: newSessionToken } : linkedRow);
    }

    const insertRes = await fetch(`${SUPABASE_URL}/rest/v1/doctors`, {
      method: 'POST',
      headers: {
        apikey: SUPABASE_SERVICE_KEY,
        Authorization: `Bearer ${SUPABASE_SERVICE_KEY}`,
        'Content-Type': 'application/json',
        Prefer: 'return=representation',
      },
      body: JSON.stringify({ email, name: name || email, status: 'pending' }),
    });
    const inserted = await insertRes.json();
    if (!insertRes.ok) {
      console.error('Doctor insert failed:', insertRes.status, inserted);
      return res.status(500).json({ error: 'Could not create doctor record: ' + (inserted.message || JSON.stringify(inserted)).slice(0, 300) });
    }
    const doctorRow = Array.isArray(inserted) ? inserted[0] : inserted;
    if (!doctorRow || !doctorRow.email) {
      console.error('Doctor insert returned unexpected shape:', inserted);
      return res.status(500).json({ error: 'Doctor record was created but the server response was malformed.' });
    }
    res.json(newSessionToken ? { ...doctorRow, session_token: newSessionToken } : doctorRow);
  } catch (err) {
    console.error('Doctor checkin error:', err);
    res.status(500).json({ error: 'Check-in failed: ' + err.message });
  }
});

// ---- POST /api/doctors/me/name ----
// Lets a signed-in doctor (any status — pending or approved) set their own
// display name at any time, so they're never stuck showing as their raw
// email. The email itself is taken from the verified token, never from
// client input, so nobody can rename another doctor's row.
app.post('/api/doctors/me/name', async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  const token = extractBearerToken(req);
  const email = await verifyGoogleToken(token);
  if (!email) return res.status(401).json({ error: 'Sign in with Google required.' });
  const { name } = req.body || {};
  if (!name || !name.trim()) return res.status(400).json({ error: 'Missing name.' });
  try {
    const existing = await lookupDoctor(email);
    if (!existing) return res.status(404).json({ error: 'You are not registered at this clinic yet — sign in first.' });
    const url = `${SUPABASE_URL}/rest/v1/doctors?email=eq.${encodeURIComponent(email)}`;
    const upstream = await fetch(url, {
      method: 'PATCH',
      headers: {
        apikey: SUPABASE_SERVICE_KEY,
        Authorization: `Bearer ${SUPABASE_SERVICE_KEY}`,
        'Content-Type': 'application/json',
        Prefer: 'return=representation',
      },
      body: JSON.stringify({ name: name.trim() }),
    });
    const data = await upstream.json();
    if (!upstream.ok) {
      console.error('Name update failed:', upstream.status, data);
      return res.status(500).json({ error: 'Could not update name.' });
    }
    res.json(Array.isArray(data) ? data[0] : data);
  } catch (err) {
    console.error('Doctor name update error:', err);
    res.status(500).json({ error: 'Failed to update name: ' + err.message });
  }
});

// ---- POST /api/doctors/me/color ----
// Lets a signed-in doctor set their own calendar color (the "Your color
// on the clinic calendar" swatches in Settings). Previously that picker
// only saved to the device — it never told the server, so the doctors
// table (and anything reading from it) kept showing the old color. This
// also cascades the new color onto that doctor's own upcoming
// appointments, same as the owner/secretary color-panel endpoint does.
app.post('/api/doctors/me/color', async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  const token = extractBearerToken(req);
  const email = await verifyGoogleToken(token);
  if (!email) return res.status(401).json({ error: 'Sign in with Google required.' });
  const { color } = req.body || {};
  if (!color) return res.status(400).json({ error: 'Missing color.' });
  try {
    const existing = await lookupDoctor(email);
    if (!existing) return res.status(404).json({ error: 'You are not registered at this clinic yet — sign in first.' });
    const url = `${SUPABASE_URL}/rest/v1/doctors?email=eq.${encodeURIComponent(email)}`;
    const upstream = await fetch(url, {
      method: 'PATCH',
      headers: {
        apikey: SUPABASE_SERVICE_KEY,
        Authorization: `Bearer ${SUPABASE_SERVICE_KEY}`,
        'Content-Type': 'application/json',
        Prefer: 'return=representation',
      },
      body: JSON.stringify({ color }),
    });
    const data = await upstream.json();
    if (!upstream.ok) {
      console.error('Self color update failed:', upstream.status, data);
      return res.status(500).json({ error: 'Could not update color.' });
    }
    if (existing.name) {
      const nowIso = new Date().toISOString();
      const cascadeUrl = `${SUPABASE_URL}/rest/v1/appointments?doctor_name=eq.${encodeURIComponent(existing.name)}&start_time=gte.${encodeURIComponent(nowIso)}`;
      const cascadeRes = await fetch(cascadeUrl, {
        method: 'PATCH',
        headers: {
          apikey: SUPABASE_SERVICE_KEY,
          Authorization: `Bearer ${SUPABASE_SERVICE_KEY}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ doctor_color: color }),
      });
      if (!cascadeRes.ok) {
        console.error('Self color cascade to appointments failed:', cascadeRes.status, await cascadeRes.text());
      }
    }
    res.json(Array.isArray(data) ? data[0] : data);
  } catch (err) {
    console.error('Self color update error:', err);
    res.status(500).json({ error: 'Failed to update color: ' + err.message });
  }
});

// ---- POST /api/auth/logout ----
// Revokes just the session token used for this request (normal sign-out).
app.post('/api/auth/logout', async (req, res) => {
  const token = extractBearerToken(req);
  if (!token) return res.json({ ok: true });
  try {
    await fetch(`${SUPABASE_URL}/rest/v1/app_sessions?token=eq.${encodeURIComponent(token)}`, {
      method: 'DELETE',
      headers: { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}` },
    });
    res.json({ ok: true });
  } catch (err) {
    console.error('Logout error:', err);
    res.json({ ok: true }); // don't block sign-out on the client either way
  }
});

// ---- POST /api/auth/logout-all ----
// Revokes EVERY session for the signed-in doctor (all devices) — for a
// lost or stolen phone, so old sessions stop working immediately rather
// than waiting out the 30-day expiry.
app.post('/api/auth/logout-all', requireApprovedAny, async (req, res) => {
  try {
    await fetch(`${SUPABASE_URL}/rest/v1/app_sessions?email=eq.${encodeURIComponent(req.doctor.email)}`, {
      method: 'DELETE',
      headers: { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}` },
    });
    res.json({ ok: true });
  } catch (err) {
    console.error('Logout-all error:', err);
    res.status(500).json({ error: 'Failed to revoke sessions: ' + err.message });
  }
});

app.post('/api/doctors/bootstrap-owner', async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  if (!OWNER_SECRET) return res.status(500).json({ error: 'Server is missing OWNER_SECRET.' });
  const provided = req.header('x-owner-secret');
  if (provided !== OWNER_SECRET) return res.status(401).json({ error: 'Invalid owner secret.' });
  const token = extractBearerToken(req);
  const email = await verifyGoogleToken(token);
  if (!email) return res.status(401).json({ error: 'Sign in with Google required.' });
  const { name } = req.body || {};
  try {
    const existing = await lookupDoctor(email);
    const url = existing
      ? `${SUPABASE_URL}/rest/v1/doctors?email=eq.${encodeURIComponent(email)}`
      : `${SUPABASE_URL}/rest/v1/doctors`;
    const upstream = await fetch(url, {
      method: existing ? 'PATCH' : 'POST',
      headers: {
        apikey: SUPABASE_SERVICE_KEY,
        Authorization: `Bearer ${SUPABASE_SERVICE_KEY}`,
        'Content-Type': 'application/json',
        Prefer: 'return=representation',
      },
      body: JSON.stringify({
        email,
        name: name || email,
        role: 'owner',
        status: 'approved',
        approved_at: new Date().toISOString(),
      }),
    });
    const data = await upstream.json();
    res.json(Array.isArray(data) ? data[0] : data);
  } catch (err) {
    console.error('Bootstrap-owner error:', err);
    res.status(500).json({ error: 'Bootstrap failed: ' + err.message });
  }
});

// ---- POST /api/doctors/manual ----
// Owner adds a real clinic team member (name + color) who hasn't signed
// into the app with Google yet. This is a normal, fully-approved doctor
// row from day one — not a "pending" placeholder — it just carries a
// synthetic @empower.local email until she signs in for real, at which
// point /api/doctors/checkin links her Google account into this same row.
// ---- Email + password login (alternative to Google Sign-In) ----
// Same doctors table, same email as identity — this just adds a second
// way to prove you're that email besides a Google token, since the
// Google popup/redirect flow turned out to be unreliable from an
// "Add to Home Screen" icon. Password hashing uses Node's built-in
// scrypt (no extra npm dependency needed).
function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return `${salt}:${hash}`;
}
function verifyPassword(password, stored) {
  if (!stored || !stored.includes(':')) return false;
  const [salt, hash] = stored.split(':');
  const check = crypto.scryptSync(password, salt, 64).toString('hex');
  try {
    return crypto.timingSafeEqual(Buffer.from(hash, 'hex'), Buffer.from(check, 'hex'));
  } catch (e) {
    return false;
  }
}

// ---- POST /api/auth/login ----
app.post('/api/auth/login', async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'Missing email or password.' });
  try {
    const doctor = await lookupDoctor(email.trim().toLowerCase());
    if (!doctor || !doctor.password_hash || !verifyPassword(password, doctor.password_hash)) {
      return res.status(401).json({ error: 'Wrong email or password.' });
    }
    const sessionToken = await createAppSession(doctor.email);
    const { password_hash, ...safeDoctor } = doctor;
    res.json({ ...safeDoctor, session_token: sessionToken });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Login failed: ' + err.message });
  }
});

// ---- POST /api/doctors/:email/set-password ----
// Owner sets or resets a team member's password — the normal way someone
// gets onboarded onto password login, or recovers a forgotten one.
app.post('/api/doctors/:email/set-password', requireOwnerDoctor, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  const { password } = req.body || {};
  if (!password || password.length < 4) return res.status(400).json({ error: 'Password must be at least 4 characters.' });
  try {
    const url = `${SUPABASE_URL}/rest/v1/doctors?email=eq.${encodeURIComponent(req.params.email)}`;
    const upstream = await fetch(url, {
      method: 'PATCH',
      headers: {
        apikey: SUPABASE_SERVICE_KEY,
        Authorization: `Bearer ${SUPABASE_SERVICE_KEY}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ password_hash: hashPassword(password) }),
    });
    res.status(upstream.status).json({ ok: upstream.ok });
  } catch (err) {
    console.error('Set-password error:', err);
    res.status(500).json({ error: 'Failed to set password: ' + err.message });
  }
});

// ---- POST /api/auth/change-password ----
// Self-service: a signed-in doctor changes their own password.
app.post('/api/auth/change-password', requireApprovedAny, async (req, res) => {
  const { newPassword } = req.body || {};
  if (!newPassword || newPassword.length < 4) return res.status(400).json({ error: 'Password must be at least 4 characters.' });
  try {
    const url = `${SUPABASE_URL}/rest/v1/doctors?email=eq.${encodeURIComponent(req.doctor.email)}`;
    await fetch(url, {
      method: 'PATCH',
      headers: {
        apikey: SUPABASE_SERVICE_KEY,
        Authorization: `Bearer ${SUPABASE_SERVICE_KEY}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ password_hash: hashPassword(newPassword) }),
    });
    res.json({ ok: true });
  } catch (err) {
    console.error('Change-password error:', err);
    res.status(500).json({ error: 'Failed to change password: ' + err.message });
  }
});

app.post('/api/doctors/manual', requireOwnerDoctor, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  const { name, color, email } = req.body || {};
  if (!name || !name.trim()) return res.status(400).json({ error: 'Missing doctor name.' });
  try {
    const already = await lookupManualDoctorByName(name);
    if (already) return res.status(409).json({ error: 'A doctor with that name is already on the roster.' });
    let finalEmail;
    if (email && email.trim()) {
      // Owner already knows this person's real email — use it directly.
      // No placeholder, no later merge needed: Google sign-in AND
      // password login both work immediately against this same row.
      finalEmail = email.trim().toLowerCase();
      const existing = await lookupDoctor(finalEmail);
      if (existing) return res.status(409).json({ error: 'A doctor with that email already exists on the roster.' });
    } else {
      const slug = name.trim().toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '') || 'doctor';
      finalEmail = `manual-${slug}-${Date.now().toString(36)}@empower.local`;
    }
    const insertRes = await fetch(`${SUPABASE_URL}/rest/v1/doctors`, {
      method: 'POST',
      headers: {
        apikey: SUPABASE_SERVICE_KEY,
        Authorization: `Bearer ${SUPABASE_SERVICE_KEY}`,
        'Content-Type': 'application/json',
        Prefer: 'return=representation',
      },
      body: JSON.stringify({
        email: finalEmail,
        name: name.trim(),
        role: 'doctor',
        status: 'approved',
        color: color || null,
        approved_at: new Date().toISOString(),
      }),
    });
    const inserted = await insertRes.json();
    if (!insertRes.ok) {
      console.error('Manual doctor insert failed:', insertRes.status, inserted);
      return res.status(500).json({ error: 'Could not add doctor: ' + (inserted.message || JSON.stringify(inserted)).slice(0, 300) });
    }
    res.json(Array.isArray(inserted) ? inserted[0] : inserted);
  } catch (err) {
    console.error('Manual doctor add error:', err);
    res.status(500).json({ error: 'Failed to add doctor: ' + err.message });
  }
});

// ---- POST /api/doctors/merge ----
// Fixes the "same person ended up as two rows" problem — usually a
// manually-added doctor (placeholder @empower.local email) whose real
// Google sign-in didn't auto-link because the name didn't match closely
// enough, so it created a second row instead. Owner picks which row to
// KEEP (its name/color/history survive) and which to REMOVE; whichever
// of the two has a real email (not @empower.local) becomes the surviving
// row's email, so future sign-ins map correctly.
app.post('/api/doctors/merge', requireOwnerDoctor, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  const { keepEmail, removeEmail } = req.body || {};
  if (!keepEmail || !removeEmail || keepEmail === removeEmail) {
    return res.status(400).json({ error: 'Need two different doctor emails: keepEmail and removeEmail.' });
  }
  try {
    const keepRow = await lookupDoctor(keepEmail);
    const removeRow = await lookupDoctor(removeEmail);
    if (!keepRow || !removeRow) return res.status(404).json({ error: 'One of those doctors was not found.' });

    const isPlaceholder = (email) => email.endsWith('@empower.local');
    let finalEmail = keepEmail;
    if (isPlaceholder(keepEmail) && !isPlaceholder(removeEmail)) finalEmail = removeEmail;

    // Delete the row being removed first — if finalEmail === removeEmail,
    // that address needs to be free before we can move it onto keepRow.
    await fetch(`${SUPABASE_URL}/rest/v1/doctors?email=eq.${encodeURIComponent(removeEmail)}`, {
      method: 'DELETE',
      headers: { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}` },
    });

    if (finalEmail !== keepEmail) {
      const patchRes = await fetch(`${SUPABASE_URL}/rest/v1/doctors?email=eq.${encodeURIComponent(keepEmail)}`, {
        method: 'PATCH',
        headers: {
          apikey: SUPABASE_SERVICE_KEY,
          Authorization: `Bearer ${SUPABASE_SERVICE_KEY}`,
          'Content-Type': 'application/json',
          Prefer: 'return=representation',
        },
        body: JSON.stringify({ email: finalEmail }),
      });
      const patched = await patchRes.json();
      if (!patchRes.ok) {
        console.error('Merge email update failed:', patchRes.status, patched);
        return res.status(500).json({ error: 'Merged, but could not update the email on the kept record.' });
      }
    }

    // Also fold any push notification subscriptions from the removed
    // email over to the surviving email, so notifications keep working.
    if (finalEmail !== removeEmail) {
      await fetch(`${SUPABASE_URL}/rest/v1/push_subscriptions?email=eq.${encodeURIComponent(removeEmail)}`, {
        method: 'PATCH',
        headers: {
          apikey: SUPABASE_SERVICE_KEY,
          Authorization: `Bearer ${SUPABASE_SERVICE_KEY}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ email: finalEmail }),
      }).catch(() => {});
    }

    res.json({ ok: true, email: finalEmail, name: keepRow.name });
  } catch (err) {
    console.error('Doctor merge error:', err);
    res.status(500).json({ error: 'Failed to merge: ' + err.message });
  }
});

app.get('/api/doctors', requireOwnerDoctor, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  try {
    const url = `${SUPABASE_URL}/rest/v1/doctors?order=requested_at.desc`;
    const upstream = await fetch(url, { headers: { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}` } });
    const data = await upstream.text();
    res.status(upstream.status).type('application/json').send(data);
  } catch (err) {
    console.error('Doctors GET error:', err);
    res.status(500).json({ error: 'Failed to load doctors: ' + err.message });
  }
});

// Lighter-weight roster for color assignment — owner OR secretary, and
// only exposes approved doctors/owners (not pending/removed accounts).
app.get('/api/doctors/colors', requireOwnerOrSecretary, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  try {
    const url = `${SUPABASE_URL}/rest/v1/doctors?status=eq.approved&role=in.(doctor,owner)&order=name.asc`;
    const upstream = await fetch(url, { headers: { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}` } });
    const data = await upstream.text();
    res.status(upstream.status).type('application/json').send(data);
  } catch (err) {
    console.error('Doctor colors GET error:', err);
    res.status(500).json({ error: 'Failed to load doctor colors: ' + err.message });
  }
});

// ---- POST /api/doctors/:email/dashboard-access ----
// Owner grants/revokes a specific team member's access to the Dashboard
// (stats view with payment/confirmation numbers) — not tied to role, so
// the owner can, say, give a trusted secretary access without making
// them an owner, or keep it from a doctor who shouldn't see clinic-wide
// financials.
app.post('/api/doctors/:email/dashboard-access', requireOwnerDoctor, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  const { canView } = req.body || {};
  try {
    const url = `${SUPABASE_URL}/rest/v1/doctors?email=eq.${encodeURIComponent(req.params.email)}`;
    const upstream = await fetch(url, {
      method: 'PATCH',
      headers: {
        apikey: SUPABASE_SERVICE_KEY,
        Authorization: `Bearer ${SUPABASE_SERVICE_KEY}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ can_view_dashboard: !!canView }),
    });
    res.status(upstream.status).json({ ok: upstream.ok });
  } catch (err) {
    console.error('Dashboard-access toggle error:', err);
    res.status(500).json({ error: 'Failed to update dashboard access: ' + err.message });
  }
});

app.post('/api/doctors/:email/color', requireOwnerOrSecretary, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  const { color } = req.body || {};
  if (!color) return res.status(400).json({ error: 'Missing color.' });
  try {
    const doctor = await lookupDoctor(req.params.email);
    const url = `${SUPABASE_URL}/rest/v1/doctors?email=eq.${encodeURIComponent(req.params.email)}`;
    const upstream = await fetch(url, {
      method: 'PATCH',
      headers: {
        apikey: SUPABASE_SERVICE_KEY,
        Authorization: `Bearer ${SUPABASE_SERVICE_KEY}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ color }),
    });

    // Cascade the new color onto this doctor's upcoming appointments —
    // they were booked with the old color baked in (doctor_color is
    // stored per-appointment, not looked up live), so without this a
    // color change wouldn't show up on anything already on the calendar.
    // Past appointments are left alone; only start_time >= now is touched.
    if (upstream.ok && doctor && doctor.name) {
      const nowIso = new Date().toISOString();
      const cascadeUrl = `${SUPABASE_URL}/rest/v1/appointments?doctor_name=eq.${encodeURIComponent(doctor.name)}&start_time=gte.${encodeURIComponent(nowIso)}`;
      const cascadeRes = await fetch(cascadeUrl, {
        method: 'PATCH',
        headers: {
          apikey: SUPABASE_SERVICE_KEY,
          Authorization: `Bearer ${SUPABASE_SERVICE_KEY}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ doctor_color: color }),
      });
      if (!cascadeRes.ok) {
        console.error('Color cascade to appointments failed:', cascadeRes.status, await cascadeRes.text());
      }
    }

    res.status(upstream.status).json({ ok: upstream.ok });
  } catch (err) {
    console.error('Doctor color update error:', err);
    res.status(500).json({ error: 'Failed to update color: ' + err.message });
  }
});

app.post('/api/doctors/:email/approve', requireOwnerDoctor, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  const { role } = req.body || {};
  const assignedRole = role === 'secretary' ? 'secretary' : role === 'owner' ? 'owner' : 'doctor';
  try {
    const url = `${SUPABASE_URL}/rest/v1/doctors?email=eq.${encodeURIComponent(req.params.email)}`;
    const upstream = await fetch(url, {
      method: 'PATCH',
      headers: {
        apikey: SUPABASE_SERVICE_KEY,
        Authorization: `Bearer ${SUPABASE_SERVICE_KEY}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ status: 'approved', role: assignedRole, approved_at: new Date().toISOString() }),
    });
    res.status(upstream.status).json({ ok: upstream.ok });
  } catch (err) {
    console.error('Doctor approve error:', err);
    res.status(500).json({ error: 'Failed to approve: ' + err.message });
  }
});

app.post('/api/doctors/:email/reject', requireOwnerDoctor, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  try {
    const url = `${SUPABASE_URL}/rest/v1/doctors?email=eq.${encodeURIComponent(req.params.email)}`;
    const upstream = await fetch(url, {
      method: 'PATCH',
      headers: {
        apikey: SUPABASE_SERVICE_KEY,
        Authorization: `Bearer ${SUPABASE_SERVICE_KEY}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ status: 'removed' }),
    });
    res.status(upstream.status).json({ ok: upstream.ok });
  } catch (err) {
    console.error('Doctor reject error:', err);
    res.status(500).json({ error: 'Failed to reject: ' + err.message });
  }
});

app.get('/', (req, res) => {
  res.send('Qalam PT Scribe backend is running.');
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`);
});
