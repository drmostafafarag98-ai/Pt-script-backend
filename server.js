// Qalam PT Scribe — backend proxy
//
// AUTH MODEL: no shared password. Every request must carry a real Google
// access token (from the doctor's own Google sign-in) in the
// Authorization: Bearer <token> header. This server verifies that token
// with Google on every request, then checks the doctors table to confirm
// that email is an APPROVED doctor at this clinic before doing anything.
// Owner-only actions additionally require role = 'owner' in that table.
//
// The one exception is a one-time bootstrap step: OWNER_SECRET (an env
// var) is used ONLY to promote the very first signed-in user to owner,
// since the doctors table starts empty and someone has to be able to
// approve the first person.

const express = require('express');
const cors = require('cors');

const app = express();

const DEEPGRAM_API_KEY = process.env.DEEPGRAM_API_KEY || '';
const ANTHROPIC_API_KEY = process.env.ANTHROPIC_API_KEY || '';
const GEMINI_API_KEY = process.env.GEMINI_API_KEY || '';
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || '*';
const SUPABASE_URL = process.env.SUPABASE_URL || '';
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_KEY || '';
const OWNER_SECRET = process.env.OWNER_SECRET || '';

app.use(cors({ origin: ALLOWED_ORIGIN }));

async function verifyGoogleToken(accessToken) {
  if (!accessToken) return null;
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

app.use(express.json({ limit: '10mb' }));

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

app.post('/api/doctors/checkin', async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  const token = extractBearerToken(req);
  const email = await verifyGoogleToken(token);
  if (!email) return res.status(401).json({ error: 'Invalid or expired Google token.' });
  const { name } = req.body || {};
  try {
    const existing = await lookupDoctor(email);
    if (existing) return res.json(existing);
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
    res.json(doctorRow);
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
