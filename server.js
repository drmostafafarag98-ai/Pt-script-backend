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
const webpush = require('web-push');

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

const VAPID_PUBLIC_KEY = process.env.VAPID_PUBLIC_KEY || '';
const VAPID_PRIVATE_KEY = process.env.VAPID_PRIVATE_KEY || '';
if (VAPID_PUBLIC_KEY && VAPID_PRIVATE_KEY) {
  webpush.setVapidDetails('mailto:physiotherapyempower@gmail.com', VAPID_PUBLIC_KEY, VAPID_PRIVATE_KEY);
} else {
  console.warn('VAPID_PUBLIC_KEY / VAPID_PRIVATE_KEY not set — push notifications are disabled.');
}

// ---- POST /api/push/subscribe ----
// Saves this device's push subscription against the signed-in doctor's
// email. A doctor can have several devices/subscriptions at once (each
// keyed by its unique endpoint URL), all of which get notified.
app.post('/api/push/subscribe', requireApprovedAny, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  const { subscription } = req.body || {};
  if (!subscription || !subscription.endpoint) return res.status(400).json({ error: 'Missing subscription.' });
  try {
    await fetch(`${SUPABASE_URL}/rest/v1/push_subscriptions`, {
      method: 'POST',
      headers: {
        apikey: SUPABASE_SERVICE_KEY,
        Authorization: `Bearer ${SUPABASE_SERVICE_KEY}`,
        'Content-Type': 'application/json',
        Prefer: 'resolution=merge-duplicates',
      },
      body: JSON.stringify({
        endpoint: subscription.endpoint,
        email: req.doctor.email,
        subscription,
      }),
    });
    res.json({ ok: true });
  } catch (err) {
    console.error('Push subscribe error:', err);
    res.status(500).json({ error: 'Failed to save subscription: ' + err.message });
  }
});

// ---- POST /api/push/unsubscribe ----
app.post('/api/push/unsubscribe', requireApprovedAny, async (req, res) => {
  const { endpoint } = req.body || {};
  if (!endpoint) return res.json({ ok: true });
  try {
    await fetch(`${SUPABASE_URL}/rest/v1/push_subscriptions?endpoint=eq.${encodeURIComponent(endpoint)}`, {
      method: 'DELETE',
      headers: { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}` },
    });
    res.json({ ok: true });
  } catch (err) {
    console.error('Push unsubscribe error:', err);
    res.json({ ok: true });
  }
});

// Sends a push notification to every device subscribed under the given
// doctor NAME (appointments store doctor_name, not email, so we resolve
// name -> email -> subscriptions). Best-effort: failures are logged, never
// thrown, so a notification problem never blocks the appointment save
// itself. Expired subscriptions (410/404 from the push service) are
// cleaned up automatically.
async function notifyDoctorByName(doctorName, title, body) {
  if (!VAPID_PUBLIC_KEY || !VAPID_PRIVATE_KEY || !doctorName || !SUPABASE_URL || !SUPABASE_SERVICE_KEY) return;
  try {
    const doctorRes = await fetch(`${SUPABASE_URL}/rest/v1/doctors?name=eq.${encodeURIComponent(doctorName)}`, {
      headers: { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}` },
    });
    const doctors = await doctorRes.json();
    const doctor = Array.isArray(doctors) && doctors.length > 0 ? doctors[0] : null;
    if (!doctor) return;
    const subsRes = await fetch(`${SUPABASE_URL}/rest/v1/push_subscriptions?email=eq.${encodeURIComponent(doctor.email)}`, {
      headers: { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}` },
    });
    const subs = await subsRes.json();
    if (!Array.isArray(subs) || subs.length === 0) return;
    const payload = JSON.stringify({ title, body });
    await Promise.all(subs.map(async (row) => {
      try {
        await webpush.sendNotification(row.subscription, payload);
      } catch (err) {
        if (err.statusCode === 404 || err.statusCode === 410) {
          await fetch(`${SUPABASE_URL}/rest/v1/push_subscriptions?endpoint=eq.${encodeURIComponent(row.endpoint)}`, {
            method: 'DELETE',
            headers: { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}` },
          }).catch(()=>{});
        } else {
          console.error('Push send error:', err.statusCode, err.body || err.message);
        }
      }
    }));
  } catch (err) {
    console.error('notifyDoctorByName error:', err);
  }
}

// Our own long-lived session tokens, stored in a Supabase table
// (app_sessions: token text primary key, email text, created_at
// timestamptz, expires_at timestamptz). Created once after a real Google
// sign-in; from then on the frontend uses THIS token instead of the
// short-lived Google access token, so staying signed in no longer depends
// on Google's ~1hr token lifetime or on the browser keeping a Google
// session alive.
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
    if (upstream.ok) {
      const finalDoctorName = doctorName || req.doctor.name || req.doctor.email;
      const timeLabel = new Date(startTime).toLocaleString('en-GB', { timeZone: 'Africa/Cairo', weekday: 'short', day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit' });
      notifyDoctorByName(finalDoctorName, 'New appointment', `${patientName} — ${timeLabel}`);
    }
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
  const { patientName, patientPhone, startTime, endTime, doctorColor, doctorName, status } = req.body || {};
  const patch = {};
  if (patientName !== undefined) patch.patient_name = patientName;
  if (patientPhone !== undefined) patch.patient_phone = patientPhone || null;
  if (startTime !== undefined) patch.start_time = startTime;
  if (endTime !== undefined) patch.end_time = endTime;
  if (doctorColor !== undefined) patch.doctor_color = doctorColor || null;
  if (doctorName !== undefined) patch.doctor_name = doctorName || null;
  if (status !== undefined) patch.status = status;
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
    if (upstream.ok) {
      try {
        const rows = JSON.parse(data);
        const updated = Array.isArray(rows) ? rows[0] : rows;
        if (updated && updated.doctor_name) {
          const timeLabel = updated.start_time
            ? new Date(updated.start_time).toLocaleString('en-GB', { timeZone: 'Africa/Cairo', weekday: 'short', day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit' })
            : '';
          const title = updated.status === 'cancelled' ? 'Appointment cancelled' : 'Appointment updated';
          notifyDoctorByName(updated.doctor_name, title, `${updated.patient_name || ''} — ${timeLabel}`);
        }
      } catch (e) { /* non-fatal — notification is best-effort */ }
    }
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

// ---- POST /api/whatsapp/send-reminder ----
// The genuinely free path: Meta's own WhatsApp Cloud API, direct — no BSP
// (no Twilio, no 360dialog, no monthly subscription or per-message markup
// on top of Meta's own small per-message rate). Inactive until
// META_WHATSAPP_PHONE_NUMBER_ID and META_WHATSAPP_ACCESS_TOKEN are set in
// Render — set those once your Meta Business verification + message
// template approval are complete, and this starts working with no code
// changes.
function normalizeEgyptPhone(raw) {
  let digits = String(raw || '').replace(/[^\d]/g, '');
  if (digits.startsWith('0')) digits = digits.slice(1);
  if (!digits.startsWith('20')) digits = '20' + digits;
  return digits;
}

app.post('/api/whatsapp/send-reminder', requireApprovedAny, async (req, res) => {
  const META_PHONE_NUMBER_ID = process.env.META_WHATSAPP_PHONE_NUMBER_ID || '';
  const META_ACCESS_TOKEN = process.env.META_WHATSAPP_ACCESS_TOKEN || '';
  // Set this once Meta approves your reminder template (e.g. "appointment_reminder").
  // Until then this defaults to a placeholder name that will fail at Meta's
  // end with a clear "template not found" error rather than silently doing
  // the wrong thing.
  const META_TEMPLATE_NAME = process.env.META_WHATSAPP_TEMPLATE_NAME || 'appointment_reminder';
  if (!META_PHONE_NUMBER_ID || !META_ACCESS_TOKEN) {
    return res.status(501).json({
      error: 'WhatsApp Business API is not set up yet. Once your Meta Business verification and message template are approved, set META_WHATSAPP_PHONE_NUMBER_ID and META_WHATSAPP_ACCESS_TOKEN in Render — no code changes needed after that.',
    });
  }
  const { patientPhone, patientName, appointmentTime } = req.body || {};
  if (!patientPhone) return res.status(400).json({ error: 'Missing patientPhone.' });
  try {
    const normalizedPhone = normalizeEgyptPhone(patientPhone);
    const url = `https://graph.facebook.com/v21.0/${META_PHONE_NUMBER_ID}/messages`;
    // Outside an active 24h customer-initiated window, WhatsApp requires an
    // APPROVED message template (not free-form text) — this is a Meta-wide
    // rule, the same whether you go direct or through a BSP. Adjust the
    // component/parameter structure below to match your approved template's
    // actual variables once you have it (Meta's dashboard shows the exact
    // shape after approval).
    const payload = {
      messaging_product: 'whatsapp',
      to: normalizedPhone,
      type: 'template',
      template: {
        name: META_TEMPLATE_NAME,
        language: { code: 'ar' },
        components: [
          {
            type: 'body',
            parameters: [
              { type: 'text', text: patientName || '' },
              { type: 'text', text: appointmentTime || '' },
            ],
          },
        ],
      },
    };
    const upstream = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${META_ACCESS_TOKEN}`,
      },
      body: JSON.stringify(payload),
    });
    const data = await upstream.json();
    if (!upstream.ok) {
      console.error('Meta WhatsApp send failed:', data);
      return res.status(500).json({ error: (data.error && data.error.message) || 'Failed to send WhatsApp message.' });
    }
    res.json({ ok: true, messageId: data.messages && data.messages[0] && data.messages[0].id });
  } catch (err) {
    console.error('WhatsApp send error:', err);
    res.status(500).json({ error: 'Failed to send: ' + err.message });
  }
});

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
app.post('/api/doctors/manual', requireOwnerDoctor, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  const { name, color } = req.body || {};
  if (!name || !name.trim()) return res.status(400).json({ error: 'Missing doctor name.' });
  try {
    const already = await lookupManualDoctorByName(name);
    if (already) return res.status(409).json({ error: 'A doctor with that name is already on the roster.' });
    const slug = name.trim().toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '') || 'doctor';
    const placeholderEmail = `manual-${slug}-${Date.now().toString(36)}@empower.local`;
    const insertRes = await fetch(`${SUPABASE_URL}/rest/v1/doctors`, {
      method: 'POST',
      headers: {
        apikey: SUPABASE_SERVICE_KEY,
        Authorization: `Bearer ${SUPABASE_SERVICE_KEY}`,
        'Content-Type': 'application/json',
        Prefer: 'return=representation',
      },
      body: JSON.stringify({
        email: placeholderEmail,
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
