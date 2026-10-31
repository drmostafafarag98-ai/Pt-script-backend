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

const ALLOWED_ORIGIN_LIST = ALLOWED_ORIGIN.split(',').map(x => x.trim()).filter(Boolean);
app.use(cors({
  origin: ALLOWED_ORIGIN_LIST.includes('*') ? '*' : function (origin, cb) {
    // no Origin header (curl, server-to-server) or a listed origin -> allow
    if (!origin || ALLOWED_ORIGIN_LIST.includes(origin)) return cb(null, true);
    return cb(null, false);
  }
}));
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


// ---- Login activity log (owner can see who opened/signed in, from which device) ----
const loginLogSeen = new Map();
function logDevice(ua) {
  ua = String(ua || '');
  const os = /Android/i.test(ua) ? 'Android' : /iPhone|iPad|iOS/i.test(ua) ? 'iPhone/iPad' : /Windows/i.test(ua) ? 'Windows' : /Mac OS/i.test(ua) ? 'Mac' : /Linux/i.test(ua) ? 'Linux' : 'Other';
  const br = /; wv\)|Version\/[\d.]+ Chrome/i.test(ua) ? 'WebView/App' : /Edg\//i.test(ua) ? 'Edge' : /Firefox/i.test(ua) ? 'Firefox' : /Chrome/i.test(ua) ? 'Chrome' : /Safari/i.test(ua) ? 'Safari' : 'Other';
  return os + ' · ' + br;
}
function logActivity(req, event, email, extra) {
  try {
    if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return;
    const ip = String(req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();
    if (event === 'open' || event === 'page') {
      const k = event + '|' + (email || '') + '|' + ip + '|' + (extra || '');
      const now = Date.now();
      if (now - (loginLogSeen.get(k) || 0) < 30 * 60000) return;
      loginLogSeen.set(k, now);
      if (loginLogSeen.size > 5000) loginLogSeen.clear();
    }
    fetch(`${SUPABASE_URL}/rest/v1/login_log`, {
      method: 'POST',
      headers: { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}`, 'Content-Type': 'application/json', Prefer: 'return=minimal' },
      body: JSON.stringify({ event, email: email ? String(email).slice(0, 160) : null, ip: ip.slice(0, 60), device: logDevice(req.headers['user-agent']), detail: extra ? String(extra).slice(0, 80) : null }),
    }).catch(() => {});
  } catch (e) { /* never break the request */ }
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

// Owner always has every permission implicitly. Everyone else needs the
// specific permission key set true on their own doctor row.
function hasPermission(doctor, key) {
  if (!doctor) return false;
  if (doctor.role === 'owner') return true;
  return !!(doctor.permissions && doctor.permissions[key] === true);
}

// "Own patients only" mode: a non-owner doctor with permissions.own_patients_only
// sees ONLY appointments/patients/packages that belong to them (doctor_name = their name).
function isOwnOnly(doctor) {
  return !!doctor && doctor.role !== 'owner' && !!(doctor.permissions && doctor.permissions.own_patients_only === true);
}
function ownDoctorName(doctor) { return String(doctor.name || doctor.email || ''); }
async function ownPatientSet(doctor) {
  const url = `${SUPABASE_URL}/rest/v1/appointments?select=patient_name&doctor_name=eq.${encodeURIComponent(ownDoctorName(doctor))}&deleted_at=is.null&limit=5000`;
  const r = await fetch(url, { headers: { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}` } });
  const rows = r.ok ? await r.json() : [];
  return new Set((Array.isArray(rows) ? rows : []).map(x => String(x.patient_name || '').trim().toLowerCase()).filter(Boolean));
}
// Guard for /api/appointments/:id... — own-only doctors may only touch their own visits.
async function ownApptGuard(req, res, next) {
  try {
    if (!isOwnOnly(req.doctor)) return next();
    const r = await fetch(`${SUPABASE_URL}/rest/v1/appointments?id=eq.${encodeURIComponent(req.params.id)}&select=doctor_name&limit=1`, { headers: { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}` } });
    const rows = r.ok ? await r.json() : [];
    const dn = rows && rows[0] ? String(rows[0].doctor_name || '').trim().toLowerCase() : null;
    if (dn === null || dn !== ownDoctorName(req.doctor).trim().toLowerCase()) return res.status(403).json({ error: 'This visit belongs to another doctor.' });
    next();
  } catch (e) { res.status(500).json({ error: 'Access check failed.' }); }
}
// Guard for /api/packages/:id/... — package must belong to one of the doctor's own patients.
async function ownPkgGuard(req, res, next) {
  try {
    if (!isOwnOnly(req.doctor)) return next();
    const r = await fetch(`${SUPABASE_URL}/rest/v1/packages?id=eq.${encodeURIComponent(req.params.id)}&select=patient_name&limit=1`, { headers: { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}` } });
    const rows = r.ok ? await r.json() : [];
    const nm = rows && rows[0] ? String(rows[0].patient_name || '').trim().toLowerCase() : '';
    const set = await ownPatientSet(req.doctor);
    if (!nm || !set.has(nm)) return res.status(403).json({ error: 'This package belongs to another doctor\'s patient.' });
    next();
  } catch (e) { res.status(500).json({ error: 'Access check failed.' }); }
}
// Money ledger (expenses, transfers, other income, withdrawals): owner or dashboard-access only.
function requireFinanceAccess(req, res, next) {
  return requireApprovedAny(req, res, () => {
    const d = req.doctor;
    if (d && (d.role === 'owner' || d.can_view_dashboard === true)) return next();
    res.status(403).json({ error: 'Dashboard/finance access required.' });
  });
}

// Middleware factory: owner passes automatically; anyone else needs the
// named permission set true on their account.
function requireOwnerOrPermission(key) {
  return async function (req, res, next) {
    const token = extractBearerToken(req);
    const email = await verifyGoogleToken(token);
    if (!email) return res.status(401).json({ error: 'Sign in with Google required.' });
    const doctor = await lookupDoctor(email);
    if (!doctor || doctor.status !== 'approved') return res.status(403).json({ error: 'Approved account required.' });
    if (!hasPermission(doctor, key)) return res.status(403).json({ error: `You don't have the "${key}" permission — ask the clinic owner to grant it.` });
    req.doctor = doctor;
    next();
  };
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
    const url = `${SUPABASE_URL}/rest/v1/appointments?select=patient_name,patient_phone,start_time&deleted_at=is.null${isOwnOnly(req.doctor) ? '&doctor_name=eq.' + encodeURIComponent(ownDoctorName(req.doctor)) : ''}&order=start_time.desc&limit=1000`;
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
// ---- Package tracking ----
// A package is N pre-paid sessions at a discount (e.g. 6 sessions paid
// once). We track total vs used sessions so the app can tell the owner
// exactly when a patient's package runs out, instead of them having to
// remember/count manually.

// ---- POST /api/packages ---- (create a new package, e.g. right after the purchase payment)
// ---- Patient intake forms ----
// A public form (intake.html) patients fill in before their first visit —
// no login needed to submit. Staff then look it up by name/phone from
// inside a session and pull the answers in with one tap.

// ---- POST /api/intake ---- (public — no auth, the patient submits this themselves)
app.post('/api/intake', async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  const { patientName, patientPhone, chiefComplaint, referralSource } = req.body || {};
  if (!patientName || !patientPhone) return res.status(400).json({ error: 'Missing patientName or patientPhone.' });
  try {
    const insertRes = await fetch(`${SUPABASE_URL}/rest/v1/patient_intake_forms`, {
      method: 'POST',
      headers: {
        apikey: SUPABASE_SERVICE_KEY,
        Authorization: `Bearer ${SUPABASE_SERVICE_KEY}`,
        'Content-Type': 'application/json',
        Prefer: 'return=representation',
      },
      body: JSON.stringify({
        patient_name: patientName,
        patient_phone: patientPhone,
        chief_complaint: chiefComplaint || '',
        referral_source: referralSource || '',
        matched: false,
      }),
    });
    if (!insertRes.ok) throw new Error(await insertRes.text());
    res.json({ ok: true });
  } catch (err) {
    console.error('Intake submit error:', err);
    res.status(500).json({ error: 'Failed to submit: ' + err.message });
  }
});

// ---- GET /api/intake/unmatched-by-name ---- (staff-side lookup)
// ---- GET /api/intake/all-unmatched ----
// Every team member (not just the owner) can see the full list of
// intake forms nobody has pulled into a session yet.
app.get('/api/intake/all-unmatched', requireApprovedAny, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  try {
    const url = `${SUPABASE_URL}/rest/v1/patient_intake_forms?matched=eq.false&order=submitted_at.desc&limit=50`;
    const upstream = await fetch(url, { headers: { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}` } });
    const data = await upstream.text();
    res.status(upstream.status).type('application/json').send(data);
  } catch (err) {
    console.error('All-unmatched intake error:', err);
    res.status(500).json({ error: 'Failed to load: ' + err.message });
  }
});

app.get('/api/intake/unmatched-by-name', requireApprovedAny, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  const { name } = req.query;
  if (!name || name.trim().length < 2) return res.status(400).json({ error: 'Name too short.' });
  try {
    const url = `${SUPABASE_URL}/rest/v1/patient_intake_forms?patient_name=ilike.*${encodeURIComponent(name.trim())}*&matched=eq.false&order=submitted_at.desc&limit=1`;
    const upstream = await fetch(url, { headers: { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}` } });
    const rows = await upstream.json();
    res.json((Array.isArray(rows) && rows[0]) || null);
  } catch (err) {
    console.error('Intake lookup error:', err);
    res.status(500).json({ error: 'Lookup failed: ' + err.message });
  }
});

// ---- POST /api/intake/:id/mark-matched ----
app.post('/api/intake/:id/mark-matched', requireApprovedAny, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  try {
    const url = `${SUPABASE_URL}/rest/v1/patient_intake_forms?id=eq.${encodeURIComponent(req.params.id)}`;
    await fetch(url, {
      method: 'PATCH',
      headers: {
        apikey: SUPABASE_SERVICE_KEY,
        Authorization: `Bearer ${SUPABASE_SERVICE_KEY}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ matched: true }),
    });
    res.json({ ok: true });
  } catch (err) {
    console.error('Mark-matched error:', err);
    res.status(500).json({ error: 'Failed: ' + err.message });
  }
});

// ---- Doctor unavailability (e.g. "Dr X is off this day") ----
// GET /api/doctor-unavailability?start=X&end=Y — for highlighting the
// month grid; POST to mark a doctor unavailable on a date; DELETE to
// un-mark.
app.get('/api/doctor-unavailability', requireApprovedAny, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  const { start, end } = req.query;
  try {
    let url = `${SUPABASE_URL}/rest/v1/doctor_unavailability?order=date.asc`;
    if (start && end) url += `&date=gte.${encodeURIComponent(start)}&date=lte.${encodeURIComponent(end)}`;
    const upstream = await fetch(url, { headers: { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}` } });
    const data = await upstream.text();
    res.status(upstream.status).type('application/json').send(data);
  } catch (err) {
    console.error('Doctor-unavailability GET error:', err);
    res.status(500).json({ error: 'Failed: ' + err.message });
  }
});

// ---- Clinic expenses ----
// ---- GET /api/payroll ---- (?start=ISO&end=ISO) owner-only. Computes each
// doctor's pay for the period using the clinic's actual compensation rules:
// - Partners (Mostafa Farag, Youssef, Omnia Ahmed): 50% of their own
//   collected revenue, PLUS an equal 3-way split of net profit
//   (total collected − total expenses − everyone's payout).
// - Zeinab: fixed 3500 + 75/session. Menna: fixed 4000 + 50/session.
// - Marwa: 50% of her own collected revenue (not a partner, no profit share).
// Matching a doctor_name to a rule is done by a lowercase keyword so small
// spelling variations in doctor_name still resolve correctly.
let PAYROLL_RULES = []; // loaded from the clinic settings (owner edits them in Settings > Clinic)
function matchPayrollRule(doctorName) {
  const lower = (doctorName || '').toLowerCase();
  return PAYROLL_RULES.find((r) => lower.includes(r.keyword)) || null;
}

app.get('/api/payroll', requireOwnerDoctor, async (req, res) => {
  await getClinicConfig();
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  const { start, end } = req.query;
  if (!start || !end) return res.status(400).json({ error: 'Missing start or end.' });
  try {
    const headers = { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}` };
    const [apptRes, expRes] = await Promise.all([
      // Fetch everyone (including cancelled) so we can positively identify
      // and skip cancelled ones in JS below — a cancelled appointment
      // earns no revenue and doesn't count as a held session, for any
      // doctor, ever.
      fetch(`${SUPABASE_URL}/rest/v1/appointments?start_time=gte.${encodeURIComponent(start)}&start_time=lte.${encodeURIComponent(end)}&deleted_at=is.null`, { headers }),
      fetch(`${SUPABASE_URL}/rest/v1/expenses?expense_date=gte.${encodeURIComponent(start.slice(0, 10))}&expense_date=lte.${encodeURIComponent(end.slice(0, 10))}`, { headers }),
    ]);
    const appointments = await apptRes.json();
    const expenses = await expRes.json();
    if (!Array.isArray(appointments) || !Array.isArray(expenses)) {
      return res.status(500).json({ error: 'Could not read appointments or expenses for this range.' });
    }

    // Revenue/sessions per doctor: group by the MATCHED PAYROLL RULE first
    // (not the raw doctor_name string) — appointments spell the same
    // doctor's name in slightly different ways ("Dr Menna Azzam" vs
    // "menna azzam" etc.), and grouping by raw string would double-pay a
    // fixed-rate doctor once per spelling variant.
    const revenueByKey = {};
    const sessionsByKey = {};
    const unmatchedNames = {};
    appointments.forEach((ev) => {
      const doctorName = ev.doctor_name || 'Unassigned';
      const rule = matchPayrollRule(doctorName);
      const key = rule ? rule.label : `unmatched:${doctorName.trim().toLowerCase()}`;
      if (!rule) unmatchedNames[key] = doctorName;
      if (ev.status === 'cancelled') return; // a cancelled session earns nothing and doesn't count as held
      sessionsByKey[key] = (sessionsByKey[key] || 0) + 1;
      if (!ev.paid || ev.is_free) return;
      const notes = ev.notes || [];
      let amount = 0;
      notes.forEach((n) => {
        const m = (n.text || '').match(/^paid\s+([\d.,]+)\s*egp\s*\((cash|instapay)\)/i);
        if (m) amount = parseFloat(m[1].replace(/,/g, ''));
      });
      revenueByKey[key] = (revenueByKey[key] || 0) + amount;
    });

    const totalExpenses = expenses.reduce((sum, e) => sum + parseFloat(e.amount || 0), 0);
    const totalRevenue = Object.values(revenueByKey).reduce((a, b) => a + b, 0);

    const rows = [];
    let totalPayout = 0;
    const partnerRows = [];
    Object.keys({ ...revenueByKey, ...sessionsByKey }).forEach((key) => {
      const revenue = revenueByKey[key] || 0;
      const sessionCount = sessionsByKey[key] || 0;
      if (key.startsWith('unmatched:')) {
        // No matching compensation rule for this name — report their
        // revenue for visibility but don't guess a payout formula.
        rows.push({ doctorName: unmatchedNames[key], revenue, sessionCount, basePay: null, formula: 'No payroll rule set for this name', kind: 'unknown' });
        return;
      }
      const rule = PAYROLL_RULES.find((r) => r.label === key);
      let basePay = 0;
      let formula = '';
      if (rule.kind === 'partner') {
        basePay = revenue * (rule.share != null ? rule.share : 0.5);
        formula = Math.round((rule.share != null ? rule.share : 0.5) * 100) + '% of own revenue + equal share of net profit';
      } else if (rule.kind === 'revenue_share') {
        basePay = revenue * (rule.share != null ? rule.share : 0.5);
        formula = Math.round((rule.share != null ? rule.share : 0.5) * 100) + '% of own revenue';
      } else if (rule.kind === 'fixed_plus_rate') {
        basePay = rule.fixed + rule.rate * sessionCount;
        formula = `Fixed ${rule.fixed} + ${rule.rate}/session × ${sessionCount} sessions`;
      }
      totalPayout += basePay;
      const row = { doctorName: rule.label, revenue, sessionCount, basePay, formula, kind: rule.kind };
      rows.push(row);
      if (rule.kind === 'partner') partnerRows.push(row);
    });

    const netProfit = totalRevenue - totalExpenses - totalPayout;
    const profitShare = partnerRows.length > 0 ? netProfit / partnerRows.length : 0;
    partnerRows.forEach((row) => {
      row.profitShare = profitShare;
      row.totalPay = row.basePay + profitShare;
    });
    rows.forEach((row) => {
      if (row.kind !== 'partner') row.totalPay = row.basePay;
    });

    res.json({ rows, totalRevenue, totalExpenses, totalPayout, netProfit, profitShare, partnerCount: partnerRows.length });
  } catch (err) {
    console.error('Payroll error:', err);
    res.status(500).json({ error: 'Failed to compute payroll: ' + err.message });
  }
});

// ---- Internal Cash↔InstaPay transfers ----
// Moving money between the clinic's cash drawer and its InstaPay account
// isn't new revenue and isn't a real expense — it just needs to be
// tracked so Net Cash / Net InstaPay stay accurate.
app.get('/api/transfers', requireFinanceAccess, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  const { start, end } = req.query;
  try {
    let url = `${SUPABASE_URL}/rest/v1/transfers?order=transfer_date.desc`;
    if (start && end) url += `&transfer_date=gte.${encodeURIComponent(start)}&transfer_date=lte.${encodeURIComponent(end)}`;
    const upstream = await fetch(url, { headers: { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}` } });
    const data = await upstream.text();
    res.status(upstream.status).type('application/json').send(data);
  } catch (err) {
    console.error('Transfers GET error:', err);
    res.status(500).json({ error: 'Failed: ' + err.message });
  }
});

app.post('/api/transfers', requireFinanceAccess, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  const { amount, fromMethod, toMethod, transferDate, note, doctorName } = req.body || {};
  const trDoctor = String(doctorName || '').replace(/[\u0000-\u001f]/g, ' ').trim().slice(0, 80);
  if (!trDoctor) return res.status(400).json({ error: 'Please write which doctor took or sent the money.' });
  if (!amount || !fromMethod || !toMethod) return res.status(400).json({ error: 'Missing amount, fromMethod, or toMethod.' });
  if (fromMethod === toMethod) return res.status(400).json({ error: 'fromMethod and toMethod must differ.' });
  try {
    const insertRes = await fetch(`${SUPABASE_URL}/rest/v1/transfers`, {
      method: 'POST',
      headers: {
        apikey: SUPABASE_SERVICE_KEY,
        Authorization: `Bearer ${SUPABASE_SERVICE_KEY}`,
        'Content-Type': 'application/json',
        Prefer: 'return=representation',
      },
      body: JSON.stringify({
        amount,
        from_method: fromMethod,
        to_method: toMethod,
        transfer_date: transferDate || new Date().toISOString().slice(0, 10),
        note: note || null,
        doctor_name: trDoctor,
        created_by: req.doctor.name || req.doctor.email,
      }),
    });
    const inserted = await insertRes.json();
    if (!insertRes.ok) throw new Error(JSON.stringify(inserted));
    res.json(Array.isArray(inserted) ? inserted[0] : inserted);
  } catch (err) {
    console.error('Transfers POST error:', err);
    res.status(500).json({ error: 'Failed: ' + err.message });
  }
});

app.delete('/api/transfers/:id', requireFinanceAccess, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  try {
    await fetch(`${SUPABASE_URL}/rest/v1/transfers?id=eq.${encodeURIComponent(req.params.id)}`, {
      method: 'DELETE',
      headers: { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}` },
    });
    res.json({ ok: true });
  } catch (err) {
    console.error('Transfers DELETE error:', err);
    res.status(500).json({ error: 'Failed: ' + err.message });
  }
});

// ---- Other income ----
// Revenue that doesn't come from a patient session — clinic-run events,
// workshops, etc. Tracked the same way as Expenses (description, amount,
// date, payment method) but ADDS to the money totals instead of
// subtracting.
app.get('/api/other-income', requireFinanceAccess, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  const { start, end } = req.query;
  try {
    let url = `${SUPABASE_URL}/rest/v1/other_income?order=income_date.desc`;
    if (start && end) url += `&income_date=gte.${encodeURIComponent(start)}&income_date=lte.${encodeURIComponent(end)}`;
    const upstream = await fetch(url, { headers: { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}` } });
    const data = await upstream.text();
    res.status(upstream.status).type('application/json').send(data);
  } catch (err) {
    console.error('Other-income GET error:', err);
    res.status(500).json({ error: 'Failed: ' + err.message });
  }
});

app.post('/api/other-income', requireFinanceAccess, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  const { description, amount, incomeDate, paymentMethod } = req.body || {};
  if (!description || !amount) return res.status(400).json({ error: 'Missing description or amount.' });
  try {
    const insertRes = await fetch(`${SUPABASE_URL}/rest/v1/other_income`, {
      method: 'POST',
      headers: {
        apikey: SUPABASE_SERVICE_KEY,
        Authorization: `Bearer ${SUPABASE_SERVICE_KEY}`,
        'Content-Type': 'application/json',
        Prefer: 'return=representation',
      },
      body: JSON.stringify({
        description,
        amount,
        income_date: incomeDate || new Date().toISOString().slice(0, 10),
        payment_method: paymentMethod === 'instapay' ? 'instapay' : 'cash',
        created_by: req.doctor.name || req.doctor.email,
      }),
    });
    const inserted = await insertRes.json();
    if (!insertRes.ok) throw new Error(JSON.stringify(inserted));
    res.json(Array.isArray(inserted) ? inserted[0] : inserted);
  } catch (err) {
    console.error('Other-income POST error:', err);
    res.status(500).json({ error: 'Failed: ' + err.message });
  }
});

app.patch('/api/other-income/:id', requireFinanceAccess, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  const { paymentMethod } = req.body || {};
  if (paymentMethod !== 'cash' && paymentMethod !== 'instapay') return res.status(400).json({ error: 'paymentMethod must be cash or instapay.' });
  try {
    const patchRes = await fetch(`${SUPABASE_URL}/rest/v1/other_income?id=eq.${encodeURIComponent(req.params.id)}`, {
      method: 'PATCH',
      headers: {
        apikey: SUPABASE_SERVICE_KEY,
        Authorization: `Bearer ${SUPABASE_SERVICE_KEY}`,
        'Content-Type': 'application/json',
        Prefer: 'return=representation',
      },
      body: JSON.stringify({ payment_method: paymentMethod }),
    });
    const data = await patchRes.json();
    if (!patchRes.ok) throw new Error(JSON.stringify(data));
    res.json(Array.isArray(data) ? data[0] : data);
  } catch (err) {
    console.error('Other-income PATCH error:', err);
    res.status(500).json({ error: 'Failed: ' + err.message });
  }
});

app.delete('/api/other-income/:id', requireFinanceAccess, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  try {
    await fetch(`${SUPABASE_URL}/rest/v1/other_income?id=eq.${encodeURIComponent(req.params.id)}`, {
      method: 'DELETE',
      headers: { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}` },
    });
    res.json({ ok: true });
  } catch (err) {
    console.error('Other-income DELETE error:', err);
    res.status(500).json({ error: 'Failed: ' + err.message });
  }
});

// ---- Doctor withdrawals ----
// Money a doctor/partner takes out of the cash or InstaPay pool as their
// own earnings — tracked separately from general business Expenses so
// "Expenses" stays about clinic operating costs (rent, ads, supplies)
// and this stays about who's already been paid how much of their share.
app.get('/api/doctor-withdrawals', requireFinanceAccess, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  const { start, end } = req.query;
  try {
    let url = `${SUPABASE_URL}/rest/v1/doctor_withdrawals?order=withdrawal_date.desc`;
    if (start && end) url += `&withdrawal_date=gte.${encodeURIComponent(start)}&withdrawal_date=lte.${encodeURIComponent(end)}`;
    const upstream = await fetch(url, { headers: { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}` } });
    const data = await upstream.text();
    res.status(upstream.status).type('application/json').send(data);
  } catch (err) {
    console.error('Doctor-withdrawals GET error:', err);
    res.status(500).json({ error: 'Failed: ' + err.message });
  }
});

app.post('/api/doctor-withdrawals', requireFinanceAccess, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  const { doctorName, amount, paymentMethod, withdrawalDate, note } = req.body || {};
  if (!doctorName || !amount) return res.status(400).json({ error: 'Missing doctorName or amount.' });
  try {
    const insertRes = await fetch(`${SUPABASE_URL}/rest/v1/doctor_withdrawals`, {
      method: 'POST',
      headers: {
        apikey: SUPABASE_SERVICE_KEY,
        Authorization: `Bearer ${SUPABASE_SERVICE_KEY}`,
        'Content-Type': 'application/json',
        Prefer: 'return=representation',
      },
      body: JSON.stringify({
        doctor_name: doctorName,
        amount,
        payment_method: paymentMethod === 'instapay' ? 'instapay' : 'cash',
        withdrawal_date: withdrawalDate || new Date().toISOString().slice(0, 10),
        note: note || null,
        created_by: req.doctor.name || req.doctor.email,
      }),
    });
    const inserted = await insertRes.json();
    if (!insertRes.ok) throw new Error(JSON.stringify(inserted));
    res.json(Array.isArray(inserted) ? inserted[0] : inserted);
  } catch (err) {
    console.error('Doctor-withdrawals POST error:', err);
    res.status(500).json({ error: 'Failed: ' + err.message });
  }
});

app.delete('/api/doctor-withdrawals/:id', requireFinanceAccess, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  try {
    await fetch(`${SUPABASE_URL}/rest/v1/doctor_withdrawals?id=eq.${encodeURIComponent(req.params.id)}`, {
      method: 'DELETE',
      headers: { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}` },
    });
    res.json({ ok: true });
  } catch (err) {
    console.error('Doctor-withdrawals DELETE error:', err);
    res.status(500).json({ error: 'Failed: ' + err.message });
  }
});

app.get('/api/expenses', requireFinanceAccess, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  const { start, end } = req.query;
  try {
    let url = `${SUPABASE_URL}/rest/v1/expenses?order=expense_date.desc`;
    if (start && end) url += `&expense_date=gte.${encodeURIComponent(start)}&expense_date=lte.${encodeURIComponent(end)}`;
    const upstream = await fetch(url, { headers: { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}` } });
    const data = await upstream.text();
    res.status(upstream.status).type('application/json').send(data);
  } catch (err) {
    console.error('Expenses GET error:', err);
    res.status(500).json({ error: 'Failed: ' + err.message });
  }
});

app.post('/api/expenses', requireFinanceAccess, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  const { description, amount, expenseDate, paymentMethod } = req.body || {};
  if (!description || !amount) return res.status(400).json({ error: 'Missing description or amount.' });
  try {
    const insertRes = await fetch(`${SUPABASE_URL}/rest/v1/expenses`, {
      method: 'POST',
      headers: {
        apikey: SUPABASE_SERVICE_KEY,
        Authorization: `Bearer ${SUPABASE_SERVICE_KEY}`,
        'Content-Type': 'application/json',
        Prefer: 'return=representation',
      },
      body: JSON.stringify({
        description,
        amount,
        expense_date: expenseDate || new Date().toISOString().slice(0, 10),
        payment_method: paymentMethod === 'instapay' ? 'instapay' : 'cash',
        created_by: req.doctor.name || req.doctor.email,
      }),
    });
    const inserted = await insertRes.json();
    if (!insertRes.ok) throw new Error(JSON.stringify(inserted));
    res.json(Array.isArray(inserted) ? inserted[0] : inserted);
  } catch (err) {
    console.error('Expenses POST error:', err);
    res.status(500).json({ error: 'Failed: ' + err.message });
  }
});

app.patch('/api/expenses/:id', requireFinanceAccess, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  const { paymentMethod } = req.body || {};
  if (paymentMethod !== 'cash' && paymentMethod !== 'instapay') return res.status(400).json({ error: 'paymentMethod must be cash or instapay.' });
  try {
    const patchRes = await fetch(`${SUPABASE_URL}/rest/v1/expenses?id=eq.${encodeURIComponent(req.params.id)}`, {
      method: 'PATCH',
      headers: {
        apikey: SUPABASE_SERVICE_KEY,
        Authorization: `Bearer ${SUPABASE_SERVICE_KEY}`,
        'Content-Type': 'application/json',
        Prefer: 'return=representation',
      },
      body: JSON.stringify({ payment_method: paymentMethod }),
    });
    const data = await patchRes.json();
    if (!patchRes.ok) throw new Error(JSON.stringify(data));
    res.json(Array.isArray(data) ? data[0] : data);
  } catch (err) {
    console.error('Expenses PATCH error:', err);
    res.status(500).json({ error: 'Failed: ' + err.message });
  }
});

app.delete('/api/expenses/:id', requireFinanceAccess, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  try {
    await fetch(`${SUPABASE_URL}/rest/v1/expenses?id=eq.${encodeURIComponent(req.params.id)}`, {
      method: 'DELETE',
      headers: { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}` },
    });
    res.json({ ok: true });
  } catch (err) {
    console.error('Expenses DELETE error:', err);
    res.status(500).json({ error: 'Failed: ' + err.message });
  }
});

// ---- Day reminders ----
// A lightweight "don't forget to book this patient" note pinned to a
// day — NOT a real appointment (no time yet). Owner/staff schedule the
// actual appointment later and remove the reminder.
app.get('/api/day-reminders', requireApprovedAny, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  const { start, end } = req.query;
  try {
    let url = `${SUPABASE_URL}/rest/v1/day_reminders?order=reminder_date.asc`;
    if (start && end) url += `&reminder_date=gte.${encodeURIComponent(start)}&reminder_date=lte.${encodeURIComponent(end)}`;
    const upstream = await fetch(url, { headers: { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}` } });
    const data = await upstream.text();
    res.status(upstream.status).type('application/json').send(data);
  } catch (err) {
    console.error('Day-reminders GET error:', err);
    res.status(500).json({ error: 'Failed: ' + err.message });
  }
});

app.post('/api/day-reminders', requireApprovedAny, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  const { patientName, patientPhone, reminderDate, note } = req.body || {};
  if (!patientName || !reminderDate) return res.status(400).json({ error: 'Missing patientName or reminderDate.' });
  try {
    const insertRes = await fetch(`${SUPABASE_URL}/rest/v1/day_reminders`, {
      method: 'POST',
      headers: {
        apikey: SUPABASE_SERVICE_KEY,
        Authorization: `Bearer ${SUPABASE_SERVICE_KEY}`,
        'Content-Type': 'application/json',
        Prefer: 'return=representation',
      },
      body: JSON.stringify({
        patient_name: patientName,
        patient_phone: patientPhone || null,
        reminder_date: reminderDate,
        note: note || null,
        created_by: req.doctor.name || req.doctor.email,
      }),
    });
    const inserted = await insertRes.json();
    if (!insertRes.ok) throw new Error(JSON.stringify(inserted));
    res.json(Array.isArray(inserted) ? inserted[0] : inserted);
  } catch (err) {
    console.error('Day-reminders POST error:', err);
    res.status(500).json({ error: 'Failed: ' + err.message });
  }
});

app.delete('/api/day-reminders/:id', requireApprovedAny, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  try {
    await fetch(`${SUPABASE_URL}/rest/v1/day_reminders?id=eq.${encodeURIComponent(req.params.id)}`, {
      method: 'DELETE',
      headers: { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}` },
    });
    res.json({ ok: true });
  } catch (err) {
    console.error('Day-reminders DELETE error:', err);
    res.status(500).json({ error: 'Failed: ' + err.message });
  }
});

app.post('/api/doctor-unavailability', requireApprovedAny, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  const { doctorName, date } = req.body || {};
  if (!doctorName || !date) return res.status(400).json({ error: 'Missing doctorName or date.' });
  try {
    const insertRes = await fetch(`${SUPABASE_URL}/rest/v1/doctor_unavailability`, {
      method: 'POST',
      headers: {
        apikey: SUPABASE_SERVICE_KEY,
        Authorization: `Bearer ${SUPABASE_SERVICE_KEY}`,
        'Content-Type': 'application/json',
        Prefer: 'return=representation,resolution=merge-duplicates',
      },
      body: JSON.stringify({ doctor_name: doctorName, date }),
    });
    const inserted = await insertRes.json();
    if (!insertRes.ok) throw new Error(JSON.stringify(inserted));
    res.json(Array.isArray(inserted) ? inserted[0] : inserted);
  } catch (err) {
    console.error('Doctor-unavailability POST error:', err);
    res.status(500).json({ error: 'Failed: ' + err.message });
  }
});

app.delete('/api/doctor-unavailability/:id', requireApprovedAny, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  try {
    await fetch(`${SUPABASE_URL}/rest/v1/doctor_unavailability?id=eq.${encodeURIComponent(req.params.id)}`, {
      method: 'DELETE',
      headers: { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}` },
    });
    res.json({ ok: true });
  } catch (err) {
    console.error('Doctor-unavailability DELETE error:', err);
    res.status(500).json({ error: 'Failed: ' + err.message });
  }
});

// ---- TimeTree / generic iCal import ----
// TimeTree's own "Share calendar" feature gives a read-only iCal
// (webcal://... or https://...ics) feed — this is the only officially
// supported way to get data out of TimeTree (their real API was shut
// down in Dec 2023). We fetch + parse that feed server-side (avoids
// CORS) and hand back a plain list of events for the owner to review
// before anything is imported — nothing is written automatically.

function parseIcs(icsText) {
  // Unfold lines per RFC 5545 (a line starting with a space/tab is a
  // continuation of the previous line).
  const rawLines = icsText.split(/\r\n|\n|\r/);
  const lines = [];
  rawLines.forEach((line) => {
    if ((line.startsWith(' ') || line.startsWith('\t')) && lines.length > 0) {
      lines[lines.length - 1] += line.slice(1);
    } else {
      lines.push(line);
    }
  });

  function parseIcsDate(val) {
    // Handles YYYYMMDD or YYYYMMDDTHHMMSS(Z)
    const m = val.match(/^(\d{4})(\d{2})(\d{2})(T(\d{2})(\d{2})(\d{2})Z?)?$/);
    if (!m) return null;
    const [, y, mo, d, , h, mi, s] = m;
    if (h === undefined) return `${y}-${mo}-${d}`; // all-day, date only
    return new Date(Date.UTC(+y, +mo - 1, +d, +h, +mi, +s)).toISOString();
  }

  const events = [];
  let current = null;
  lines.forEach((line) => {
    if (line === 'BEGIN:VEVENT') {
      current = {};
    } else if (line === 'END:VEVENT') {
      if (current && current.summary) events.push(current);
      current = null;
    } else if (current) {
      const idx = line.indexOf(':');
      if (idx === -1) return;
      const rawKey = line.slice(0, idx);
      const key = rawKey.split(';')[0];
      const val = line.slice(idx + 1);
      if (key === 'SUMMARY') current.summary = val.replace(/\\,/g, ',').replace(/\\n/gi, ' ').trim();
      else if (key === 'DTSTART') current.start = parseIcsDate(val);
      else if (key === 'DTEND') current.end = parseIcsDate(val);
      else if (key === 'LOCATION') current.location = val;
      else if (key === 'UID') current.uid = val;
    }
  });
  return events;
}

// ---- POST /api/timetree/preview ---- ({ icalUrl }) — read-only, parses and returns events
// ---- POST /api/timetree/parse-screenshot ---- ({ imageBase64, mediaType }) —
// uses Claude's vision to read a TimeTree (or any calendar) screenshot and
// extract a list of events, in the same shape /preview returns, so the
// frontend can reuse the same review/select/import flow either way.
app.post('/api/timetree/parse-screenshot', requireApprovedAny, async (req, res) => {
  if (!ANTHROPIC_API_KEY) return res.status(500).json({ error: 'Server is missing ANTHROPIC_API_KEY.' });
  const { imageBase64, mediaType } = req.body || {};
  if (!imageBase64) return res.status(400).json({ error: 'Missing imageBase64.' });
  try {
    const todayStr = new Date().toISOString().slice(0, 10);
    const upstream = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': ANTHROPIC_API_KEY,
        'anthropic-version': '2023-06-01',
      },
      body: JSON.stringify({
        model: 'claude-sonnet-5',
        max_tokens: 2000,
        system: `You read screenshots of calendar apps (like TimeTree) and extract each visible appointment/event as JSON. Today's date is ${todayStr}. Each event has a colored bar or dot next to it — classify that color as exactly one of: "pink" (pink/magenta/light red), "green", "blue", "yellow" (yellow/gold/orange), "purple" (purple/lavender), "black" (black/very dark), "gray" (medium gray), or "unknown" if you can't tell. Respond with ONLY a raw JSON array, no markdown fences, no commentary. Each item: {"summary": "<patient or event name>", "start": "<ISO 8601 datetime, your best inference of the full date+time using today's date as reference for any relative/partial dates shown>", "color": "<one of the color words above>"}. If a year isn't shown, assume the current or nearest upcoming year. If you can't confidently read an item, skip it rather than guessing.`,
        messages: [{
          role: 'user',
          content: [
            { type: 'image', source: { type: 'base64', media_type: mediaType || 'image/jpeg', data: imageBase64 } },
            { type: 'text', text: 'Extract every appointment/event visible in this calendar screenshot as the JSON array described.' },
          ],
        }],
      }),
    });
    const data = await upstream.json();
    if (!upstream.ok) return res.status(upstream.status).json({ error: JSON.stringify(data).slice(0, 300) });
    const text = (data.content || []).filter((b) => b.type === 'text').map((b) => b.text).join('').trim();
    let events = [];
    try {
      const cleaned = text.replace(/^```json\s*/i, '').replace(/```\s*$/i, '').trim();
      events = JSON.parse(cleaned);
    } catch (parseErr) {
      console.error('Could not parse Claude screenshot response as JSON:', text);
      return res.status(500).json({ error: 'Could not read structured events from that screenshot — try a clearer photo.' });
    }
    if (!Array.isArray(events)) events = [];
    res.json({ count: events.length, events });
  } catch (err) {
    console.error('TimeTree screenshot parse error:', err);
    res.status(500).json({ error: 'Failed to read the screenshot: ' + err.message });
  }
});

app.post('/api/timetree/preview', requireApprovedAny, async (req, res) => {
  const { icalUrl, icsText } = req.body || {};
  if (!icalUrl && !icsText) return res.status(400).json({ error: 'Provide either icalUrl or icsText.' });
  try {
    let text = icsText;
    if (!text) {
      const fetchUrl = icalUrl.replace(/^webcal:\/\//i, 'https://');
      const upstream = await fetch(fetchUrl);
      if (!upstream.ok) throw new Error(`Could not fetch the calendar (HTTP ${upstream.status}). Double check the link.`);
      text = await upstream.text();
    }
    const events = parseIcs(text);
    // Only future/recent events — no point reviewing years of history.
    const cutoff = Date.now() - 1000 * 60 * 60 * 24 * 30; // last 30 days onward
    const filtered = events.filter((e) => {
      if (!e.start) return false;
      const t = new Date(e.start).getTime();
      return !isNaN(t) && t >= cutoff;
    }).sort((a, b) => new Date(a.start) - new Date(b.start));
    res.json({ count: filtered.length, events: filtered.slice(0, 300) });
  } catch (err) {
    console.error('TimeTree preview error:', err);
    res.status(500).json({ error: 'Failed to read that calendar: ' + err.message });
  }
});

// ---- POST /api/timetree/import ---- ({ events: [{summary, start, end, patientName?, doctorName?}] })
app.post('/api/timetree/import', requireApprovedAny, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  const { events } = req.body || {};
  if (!Array.isArray(events) || events.length === 0) return res.status(400).json({ error: 'No events to import.' });
  let imported = 0;
  let phoneFilled = 0;
  const errors = [];
  const phoneCache = {}; // patientName (lowercased, trimmed) -> phone or null, so we only look each name up once per batch
  for (const ev of events) {
    const patientName = (ev.patientName || ev.summary || '').trim();
    if (!patientName || !ev.start) { errors.push(`Skipped one event — missing name or date.`); continue; }
    const start = ev.start;
    const end = ev.end || new Date(new Date(start).getTime() + 30 * 60000).toISOString();
    try {
      // TimeTree screenshots never show a phone number, so look up this
      // patient's most recent one from their own appointment history
      // (if they've been in before) rather than leaving it blank.
      const cacheKey = patientName.toLowerCase();
      let patientPhone = ev.patientPhone || null;
      if (!patientPhone) {
        if (cacheKey in phoneCache) {
          patientPhone = phoneCache[cacheKey];
        } else {
          const phoneUrl = `${SUPABASE_URL}/rest/v1/appointments?patient_name=eq.${encodeURIComponent(patientName)}&patient_phone=not.is.null&deleted_at=is.null&select=patient_phone&order=start_time.desc&limit=1`;
          const phoneRes = await fetch(phoneUrl, { headers: { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}` } });
          const phoneRows = await phoneRes.json();
          patientPhone = (Array.isArray(phoneRows) && phoneRows[0] && phoneRows[0].patient_phone) || null;
          phoneCache[cacheKey] = patientPhone;
        }
        if (patientPhone) phoneFilled++;
      }
      const insertRes = await fetch(`${SUPABASE_URL}/rest/v1/appointments`, {
        method: 'POST',
        headers: {
          apikey: SUPABASE_SERVICE_KEY,
          Authorization: `Bearer ${SUPABASE_SERVICE_KEY}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          patient_name: patientName,
          patient_phone: patientPhone,
          start_time: start,
          end_time: end,
          doctor_name: ev.doctorName || req.doctor.name || req.doctor.email,
          doctor_color: ev.doctorColor || req.doctor.color || null,
        }),
      });
      if (insertRes.ok) imported++;
      else errors.push(`Failed to import "${patientName}".`);
    } catch (e) {
      errors.push(`Failed to import "${patientName}": ${e.message}`);
    }
  }
  res.json({ imported, errors, phoneFilled });
});

// ---- Package duplicate protection helpers ----
// Compare patient names loosely: ignore case, and the "el"/"al" prefix.
const pkgCreateLocks = new Set();
function normalizePkgName(s) {
  return String(s || '').trim().toLowerCase().replace(/\s+/g, ' ').split(' ')
    .map(w => w.replace(/^(el|al)(?=[a-z]{3,})/, '')).join(' ');
}
function samePatientLoosely(a, b) {
  const x = normalizePkgName(a), y = normalizePkgName(b);
  if (!x || !y) return false;
  return x === y || (x.length >= 3 && y.length >= 3 && (x.includes(y) || y.includes(x)));
}

app.post('/api/packages', requireApprovedAny, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  if (req.doctor.role === 'doctor' && !hasPermission(req.doctor, 'view_payments')) {
    return res.status(403).json({ error: 'You don\'t have permission to record payments — ask the clinic owner to grant it.' });
  }
  const { patientName, totalSessions, startingUsed, totalPrice, amountPaid } = req.body || {};
  if (!patientName || !totalSessions || totalSessions < 1) return res.status(400).json({ error: 'Missing patientName or totalSessions.' });
  const used = Math.max(0, Math.min(totalSessions, parseInt(startingUsed, 10) || 0));
  if (used > 0 && req.doctor.role === 'doctor' && !hasPermission(req.doctor, 'register_packages')) {
    return res.status(403).json({ error: 'You don\'t have permission to backfill an existing package — ask the clinic owner to grant it.' });
  }
  // Only one package creation per patient at a time (stops double taps).
  const lockKey = normalizePkgName(patientName);
  if (pkgCreateLocks.has(lockKey)) {
    return res.status(409).json({ code: 'PACKAGE_JUST_CREATED', error: 'A package for this patient is being created right now — wait a moment and check the Payment tab before trying again.' });
  }
  pkgCreateLocks.add(lockKey);
  try {
    // A second package for the same patient within 3 minutes = double tap.
    try {
      const listRes = await fetch(`${SUPABASE_URL}/rest/v1/packages?select=id,patient_name,created_at&order=created_at.desc&limit=200`, {
        headers: { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}` },
      });
      const recent = listRes.ok ? await listRes.json() : [];
      const justCreated = (Array.isArray(recent) ? recent : []).find(p => normalizePkgName(p.patient_name) === lockKey && (Date.now() - new Date(p.created_at).getTime()) < 3 * 60 * 1000);
      if (justCreated) {
        return res.status(409).json({ code: 'PACKAGE_JUST_CREATED', error: `A package for "${justCreated.patient_name}" was created a moment ago, so a second one was NOT created (probably a double tap). Check the Payment tab.` });
      }
    } catch (e) { console.error('Duplicate check failed (continuing):', e.message); }
    const insertRes = await fetch(`${SUPABASE_URL}/rest/v1/packages`, {
      method: 'POST',
      headers: {
        apikey: SUPABASE_SERVICE_KEY,
        Authorization: `Bearer ${SUPABASE_SERVICE_KEY}`,
        'Content-Type': 'application/json',
        Prefer: 'return=representation',
      },
      body: JSON.stringify({
        patient_name: patientName,
        total_sessions: totalSessions,
        used_sessions: used,
        total_price: (totalPrice === undefined || totalPrice === null || totalPrice === '') ? null : Number(totalPrice),
        amount_paid: Number(amountPaid) || 0,
        created_by: req.doctor.email,
      }),
    });
    const inserted = await insertRes.json();
    if (!insertRes.ok) throw new Error(JSON.stringify(inserted));
    res.json(Array.isArray(inserted) ? inserted[0] : inserted);
  } catch (err) {
    console.error('Create package error:', err);
    res.status(500).json({ error: 'Failed to create package: ' + err.message });
  } finally {
    pkgCreateLocks.delete(lockKey);
  }
});

// ---- GET /api/packages/active-by-patient ---- (find this patient's not-yet-finished package, if any)
// ---- GET /api/appointments/no-show-count ----
// Counts how many times this patient has been marked "no_show" — the
// frontend only allows marking no_show on an appointment that already
// had a "Confirmed" note, so every row counted here was a confirmed
// appointment the patient still didn't attend.
app.get('/api/appointments/no-show-count', requireApprovedAny, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  const { patientName } = req.query;
  if (!patientName) return res.status(400).json({ error: 'Missing patientName.' });
  try {
    const url = `${SUPABASE_URL}/rest/v1/appointments?patient_name=eq.${encodeURIComponent(patientName)}&status=eq.no_show&deleted_at=is.null${isOwnOnly(req.doctor) ? '&doctor_name=eq.' + encodeURIComponent(ownDoctorName(req.doctor)) : ''}&select=id`;
    const upstream = await fetch(url, { headers: { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}`, Prefer: 'count=exact' } });
    const rows = await upstream.json();
    res.json({ count: Array.isArray(rows) ? rows.length : 0 });
  } catch (err) {
    console.error('No-show count error:', err);
    res.status(500).json({ error: 'Failed to count no-shows: ' + err.message });
  }
});

app.get('/api/packages/active-by-patient', requireApprovedAny, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  const { patientName } = req.query;
  if (!patientName) return res.status(400).json({ error: 'Missing patientName.' });
  try {
    if (isOwnOnly(req.doctor)) {
      const mine = await ownPatientSet(req.doctor);
      if (!mine.has(String(patientName).trim().toLowerCase())) return res.json(null);
    }
    // Oldest-first (FIFO): if a patient buys a new package while an older
    // one still has sessions left, the older package must keep being the
    // one sessions get consumed from until it's finished — otherwise its
    // leftover sessions would get stranded forever behind the new one.
    // ilike WITHOUT wildcards = whole-name match that ignores upper/lower case
    // ("Adham Tantawy" and "adham tantawy" are the same patient).
    const safeName = String(patientName).trim().replace(/\*/g, '').replace(/[\\%_]/g, c => '\\' + c);
    const url = `${SUPABASE_URL}/rest/v1/packages?patient_name=ilike.${encodeURIComponent(safeName)}&order=created_at.asc`;
    const upstream = await fetch(url, { headers: { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}` } });
    const rows = await upstream.json();
    const active = (Array.isArray(rows) ? rows : []).find(p => p.used_sessions < p.total_sessions);
    if (active) return res.json(active);
    if (req.query.allowSimilar === '1') {
      const allRes = await fetch(`${SUPABASE_URL}/rest/v1/packages?order=created_at.asc`, { headers: { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}` } });
      const all = await allRes.json();
      const similarActive = (Array.isArray(all) ? all : []).filter(p => p.used_sessions < p.total_sessions && samePatientLoosely(p.patient_name, patientName));
      const distinctNames = new Set(similarActive.map(p => normalizePkgName(p.patient_name)));
      if (similarActive.length > 0 && distinctNames.size === 1) {
        return res.json({ ...similarActive[0], matched_by_similar_name: true });
      }
    }
    res.json(null);
  } catch (err) {
    console.error('Active package lookup error:', err);
    res.status(500).json({ error: 'Failed to look up package: ' + err.message });
  }
});

// ---- GET /api/packages/owed ---- (every package with money still owed — finished or not — with the patient's phone)
app.get('/api/packages/owed', requireApprovedAny, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  try {
    const headers = { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}` };
    const pkgRes = await fetch(`${SUPABASE_URL}/rest/v1/packages?total_price=not.is.null&order=created_at.asc`, { headers });
    const rows = await pkgRes.json();
    if (!pkgRes.ok) throw new Error(JSON.stringify(rows));
    // PostgREST can't compare two columns, so the "still owed" test happens here.
    const ownSet = isOwnOnly(req.doctor) ? await ownPatientSet(req.doctor) : null;
    const owed = (Array.isArray(rows) ? rows : [])
      .filter(p => !ownSet || ownSet.has(String(p.patient_name || '').trim().toLowerCase()))
      .map(p => ({ ...p, owed: Number(p.total_price) - Number(p.amount_paid || 0) }))
      .filter(p => p.owed > 0.5);
    const phoneRes = await fetch(`${SUPABASE_URL}/rest/v1/appointments?select=patient_name,patient_phone&patient_phone=not.is.null&deleted_at=is.null&order=start_time.desc&limit=3000`, { headers });
    const phoneRows = phoneRes.ok ? await phoneRes.json() : [];
    const phoneByName = new Map();
    (Array.isArray(phoneRows) ? phoneRows : []).forEach(r => {
      const k = (r.patient_name || '').trim().toLowerCase();
      if (k && r.patient_phone && !phoneByName.has(k)) phoneByName.set(k, r.patient_phone);
    });
    owed.sort((a, b) => b.owed - a.owed);
    res.json(owed.map(p => ({ ...p, patient_phone: phoneByName.get((p.patient_name || '').trim().toLowerCase()) || null })));
  } catch (err) {
    console.error('Owed packages list error:', err);
    res.status(500).json({ error: 'Failed: ' + err.message });
  }
});

// ---- GET /api/packages/active ---- (every unfinished package, with the patient's phone, for the policy-sent check)
// ---- GET /api/packages/duplicate-report ----
// Finds patients who have 2+ packages (at least one unfinished) and tells the
// story of each: when every package was created, how many visits are really
// marked as "package" on the calendar, and what the counts should be if the
// oldest package is filled first (the app's own rule).
app.get('/api/packages/duplicate-report', requireApprovedAny, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  try {
    const headers = { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}` };
    const pkgRes = await fetch(`${SUPABASE_URL}/rest/v1/packages?order=created_at.asc`, { headers });
    const pkgs = await pkgRes.json();
    if (!pkgRes.ok) throw new Error(JSON.stringify(pkgs));
    const ownSet = isOwnOnly(req.doctor) ? await ownPatientSet(req.doctor) : null;
    const all = (Array.isArray(pkgs) ? pkgs : []).filter(p => !ownSet || ownSet.has(String(p.patient_name || '').trim().toLowerCase()));
    // group packages of the same patient (loose name match)
    const groups = [];
    all.forEach(p => {
      const g = groups.find(gr => gr.some(q => samePatientLoosely(q.patient_name, p.patient_name)));
      if (g) g.push(p); else groups.push([p]);
    });
    // Only SUSPICIOUS cases: a normal renewal (old package finished, new one started) is NOT a duplicate.
    // Suspicious = 2+ unfinished packages at the same time, OR two packages created within 10 minutes.
    const dupGroups = groups.filter(g => {
      if (g.length < 2) return false;
      const unfinished = g.filter(p => p.used_sessions < p.total_sessions).length;
      if (unfinished >= 2) return true;
      const times = g.map(p => new Date(p.created_at).getTime()).sort((x, y) => x - y);
      for (let i = 1; i < times.length; i++) if (times[i] - times[i - 1] < 10 * 60000) return true;
      return false;
    });
    if (dupGroups.length === 0) return res.json([]);
    const apRes = await fetch(`${SUPABASE_URL}/rest/v1/appointments?select=id,patient_name,start_time,status,notes&notes=not.is.null&deleted_at=is.null&status=neq.cancelled&order=start_time.asc&limit=6000`, { headers });
    const apRows = apRes.ok ? await apRes.json() : [];
    const appts = Array.isArray(apRows) ? apRows : [];
    const isPkgNote = t => /^covered by package/i.test(t) || /^paid\s+[\d.,]+\s*egp\s*\((cash|instapay)\)[^\n]*starts a package of/i.test(t) || /^nothing paid yet[^\n]*starts a package of/i.test(t);
    const out = dupGroups.map(g => {
      const visits = appts.filter(a => g.some(p => samePatientLoosely(p.patient_name, a.patient_name)) &&
        (Array.isArray(a.notes) ? a.notes : []).some(n => isPkgNote(String((n && n.text) || '').trim())));
      const tagged = visits.length;
      let remaining = tagged;
      const packages = g.map((p, i) => {
        const take = Math.min(remaining, p.total_sessions);
        remaining -= take;
        const prev = i > 0 ? g[i - 1] : null;
        const gapMinutes = prev ? Math.round((new Date(p.created_at) - new Date(prev.created_at)) / 60000) : null;
        return {
          id: p.id, patient_name: p.patient_name, total_sessions: p.total_sessions, used_sessions: p.used_sessions,
          total_price: p.total_price, amount_paid: p.amount_paid, created_at: p.created_at,
          gap_minutes: gapMinutes, suggested_used: take,
        };
      });
      const sumUsed = g.reduce((a, p) => a + p.used_sessions, 0);
      const noMoney = g.every(p => !(Number(p.total_price) > 0) && !(Number(p.amount_paid) > 0));
      const hints = [];
      if (packages.some(p => p.gap_minutes !== null && p.gap_minutes < 3)) hints.push('Two packages were created within minutes of each other — most likely a double tap.');
      else if (noMoney) hints.push('No price or payment on any of them — most likely the same package was registered twice.');
      else {
        const older = g[0];
        const newerPaid = g.slice(1).some(p => Number(p.amount_paid) > 0 || Number(p.total_price) > 0);
        if (older.used_sessions < older.total_sessions && newerPaid) hints.push('A newer package was sold while the older one was never finished in the app — often the older sessions were not tapped as "Package".');
      }
      if (tagged > 0 && sumUsed > tagged) hints.push(`The app counted ${sumUsed} sessions but only ${tagged} visit${tagged === 1 ? ' is' : 's are'} marked as package on the calendar — sessions may be counted twice.`);
      if (tagged > sumUsed) hints.push(`${tagged} visits are marked as package on the calendar but the app counted only ${sumUsed} — some sessions were not counted.`);
      if (hints.length === 0) hints.push('Counts match the calendar. If the patient really bought a second package, this is normal.');
      return { names: [...new Set(g.map(p => p.patient_name))], visits_marked_package: tagged, sum_used: sumUsed, hints, packages,
        visit_dates: visits.slice(-12).map(a => a.start_time) };
    });
    res.json(out);
  } catch (err) {
    console.error('Duplicate report error:', err);
    res.status(500).json({ error: 'Failed: ' + err.message });
  }
});

app.get('/api/packages/active', requireApprovedAny, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  try {
    const headers = { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}` };
    const pkgRes = await fetch(`${SUPABASE_URL}/rest/v1/packages?order=created_at.asc`, { headers });
    const rows = await pkgRes.json();
    if (!pkgRes.ok) throw new Error(JSON.stringify(rows));
    const ownSet = isOwnOnly(req.doctor) ? await ownPatientSet(req.doctor) : null;
    const active = (Array.isArray(rows) ? rows : []).filter(p => p.used_sessions < p.total_sessions && (!ownSet || ownSet.has(String(p.patient_name || '').trim().toLowerCase())));
    const phoneRes = await fetch(`${SUPABASE_URL}/rest/v1/appointments?select=patient_name,patient_phone&patient_phone=not.is.null&deleted_at=is.null&order=start_time.desc&limit=3000`, { headers });
    const phoneRows = phoneRes.ok ? await phoneRes.json() : [];
    const phoneByName = new Map();
    (Array.isArray(phoneRows) ? phoneRows : []).forEach(r => {
      const k = (r.patient_name || '').trim().toLowerCase();
      if (k && r.patient_phone && !phoneByName.has(k)) phoneByName.set(k, r.patient_phone);
    });
    res.json(active.map(p => ({ ...p, patient_phone: phoneByName.get((p.patient_name || '').trim().toLowerCase()) || null })));
  } catch (err) {
    console.error('Active packages list error:', err);
    res.status(500).json({ error: 'Failed: ' + err.message });
  }
});

// ---- GET /api/packages/dormant ---- (patients with sessions left on an unfinished package who haven't been in for a while and have nothing booked)
app.get('/api/packages/dormant', requireApprovedAny, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  const minDays = Math.max(1, parseInt(req.query.days, 10) || 14);
  try {
    const headers = { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}` };
    const pkgRes = await fetch(`${SUPABASE_URL}/rest/v1/packages?order=created_at.asc`, { headers });
    const rows = await pkgRes.json();
    if (!pkgRes.ok) throw new Error(JSON.stringify(rows));
    const ownSet = isOwnOnly(req.doctor) ? await ownPatientSet(req.doctor) : null;
    const active = (Array.isArray(rows) ? rows : []).filter(p => p.used_sessions < p.total_sessions && (!ownSet || ownSet.has(String(p.patient_name || '').trim().toLowerCase())));
    const since = new Date(Date.now() - 400 * 86400000).toISOString();
    const apRes = await fetch(`${SUPABASE_URL}/rest/v1/appointments?select=patient_name,patient_phone,start_time,status&deleted_at=is.null&start_time=gte.${encodeURIComponent(since)}&order=start_time.desc&limit=8000`, { headers });
    const apRows = apRes.ok ? await apRes.json() : [];
    const now = Date.now();
    const info = new Map(); // lower-case patient name -> { lastPast, nextFuture, phone }
    (Array.isArray(apRows) ? apRows : []).forEach(a => {
      if (a.status === 'cancelled') return;
      const k = (a.patient_name || '').trim().toLowerCase();
      if (!k) return;
      const t = new Date(a.start_time).getTime();
      if (isNaN(t)) return;
      let i = info.get(k);
      if (!i) { i = { lastPast: 0, nextFuture: 0, phone: null }; info.set(k, i); }
      if (a.patient_phone && !i.phone) i.phone = a.patient_phone; // rows come newest first
      if (t <= now) { if (t > i.lastPast) i.lastPast = t; }
      else if (!i.nextFuture || t < i.nextFuture) i.nextFuture = t;
    });
    const out = [];
    active.forEach(p => {
      const i = info.get((p.patient_name || '').trim().toLowerCase()) || { lastPast: 0, nextFuture: 0, phone: null };
      if (i.nextFuture) return; // already has a visit booked — not dormant
      const ref = i.lastPast || new Date(p.created_at).getTime();
      const daysSince = Math.floor((now - ref) / 86400000);
      if (isNaN(daysSince) || daysSince < minDays) return;
      out.push({ ...p, last_visit: i.lastPast ? new Date(i.lastPast).toISOString() : null, days_since: daysSince, patient_phone: i.phone });
    });
    out.sort((a, b) => b.days_since - a.days_since);
    res.json(out);
  } catch (err) {
    console.error('Dormant packages list error:', err);
    res.status(500).json({ error: 'Failed: ' + err.message });
  }
});

// ---- POST /api/packages/:id/followup ---- (record the outcome of chasing a patient: contacted / continuing / not_continuing / no_answer; status null clears it)
app.post('/api/packages/:id/followup', requireApprovedAny, ownPkgGuard, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  const allowed = ['contacted', 'continuing', 'not_continuing', 'no_answer'];
  const status = req.body && req.body.status ? String(req.body.status) : null;
  if (status && !allowed.includes(status)) return res.status(400).json({ error: 'Unknown status.' });
  const patch = { followup_status: status, followup_at: status ? new Date().toISOString() : null };
  if (req.body && typeof req.body.note === 'string') patch.followup_note = req.body.note.trim().slice(0, 500) || null;
  if (!status) patch.followup_note = null;
  try {
    const patchRes = await fetch(`${SUPABASE_URL}/rest/v1/packages?id=eq.${encodeURIComponent(req.params.id)}`, {
      method: 'PATCH',
      headers: {
        apikey: SUPABASE_SERVICE_KEY,
        Authorization: `Bearer ${SUPABASE_SERVICE_KEY}`,
        'Content-Type': 'application/json',
        Prefer: 'return=representation',
      },
      body: JSON.stringify(patch),
    });
    const updated = await patchRes.json();
    if (!patchRes.ok) throw new Error(JSON.stringify(updated));
    res.json(Array.isArray(updated) ? updated[0] : updated);
  } catch (err) {
    console.error('Package followup error:', err);
    res.status(500).json({ error: 'Failed: ' + err.message });
  }
});

// ---- GET /api/appointments/undocumented?start=&end= ---- (visits that already started in the given window but have no session note saved for that patient yet — the "documentation reminder")
app.get('/api/appointments/undocumented', requireApprovedDoctor, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  const s = new Date(String(req.query.start || '')), e = new Date(String(req.query.end || ''));
  if (isNaN(s.getTime()) || isNaN(e.getTime()) || e < s || e - s > 8 * 86400000) return res.status(400).json({ error: 'Bad start/end.' });
  try {
    const headers = { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}` };
    const apRes = await fetch(`${SUPABASE_URL}/rest/v1/appointments?start_time=gte.${encodeURIComponent(s.toISOString())}&start_time=lte.${encodeURIComponent(e.toISOString())}&deleted_at=is.null&order=start_time.asc&limit=500`, { headers });
    const appts = await apRes.json();
    if (!apRes.ok) throw new Error(JSON.stringify(appts));
    const seeAll = hasPermission(req.doctor, 'view_other_patients') && !isOwnOnly(req.doctor);
    const myName = String(req.doctor.name || req.doctor.email || '').trim().toLowerCase();
    const myColor = req.doctor.color || null;
    const now = Date.now();
    const due = (Array.isArray(appts) ? appts : []).filter(a => {
      if (a.status === 'cancelled') return false;
      if (new Date(a.start_time).getTime() > now) return false; // hasn't happened yet
      if (seeAll) return true;
      return String(a.doctor_name || '').trim().toLowerCase() === myName || (myColor && a.doctor_color === myColor);
    });
    if (due.length === 0) return res.json([]);
    const sesRes = await fetch(`${SUPABASE_URL}/rest/v1/sessions?select=patient_name,created_at,updated_at&updated_at=gte.${encodeURIComponent(s.toISOString())}&limit=3000`, { headers });
    const ses = sesRes.ok ? await sesRes.json() : [];
    const documented = new Set((Array.isArray(ses) ? ses : []).map(x => String(x.patient_name || '').trim().toLowerCase()));
    res.json(due
      .filter(a => !documented.has(String(a.patient_name || '').trim().toLowerCase()))
      .map(a => ({ id: a.id, patient_name: a.patient_name, start_time: a.start_time, end_time: a.end_time || null, visit_type: a.visit_type || null, doctor_name: a.doctor_name || null, arrived_at: a.arrived_at || null })));
  } catch (err) {
    console.error('Undocumented visits error:', err);
    res.status(500).json({ error: 'Failed: ' + err.message });
  }
});

// ---- POST /api/packages/:id/start-date ---- (correct the package's start date shown to the patient; date null = go back to the automatic one)
app.post('/api/packages/:id/start-date', requireApprovedAny, ownPkgGuard, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  const date = req.body && req.body.date ? String(req.body.date) : null;
  if (date && !/^\d{4}-\d{2}-\d{2}$/.test(date)) return res.status(400).json({ error: 'Date must look like 2026-10-05.' });
  try {
    const patchRes = await fetch(`${SUPABASE_URL}/rest/v1/packages?id=eq.${encodeURIComponent(req.params.id)}`, {
      method: 'PATCH',
      headers: { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}`, 'Content-Type': 'application/json', Prefer: 'return=representation' },
      body: JSON.stringify({ start_date: date }),
    });
    const updated = await patchRes.json();
    if (!patchRes.ok) throw new Error(JSON.stringify(updated));
    res.json(Array.isArray(updated) ? updated[0] : updated);
  } catch (err) {
    console.error('Package start-date error:', err);
    res.status(500).json({ error: 'Failed: ' + err.message });
  }
});

// ---- POST /api/packages/:id/share-link ---- (creates, once, a private link the patient can open to see their own remaining sessions and balance)
app.post('/api/packages/:id/share-link', requireApprovedAny, ownPkgGuard, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  try {
    const headers = { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}`, 'Content-Type': 'application/json' };
    const getRes = await fetch(`${SUPABASE_URL}/rest/v1/packages?id=eq.${encodeURIComponent(req.params.id)}&select=id,share_token`, { headers });
    const rows = await getRes.json();
    if (!getRes.ok) throw new Error(JSON.stringify(rows));
    if (!Array.isArray(rows) || !rows[0]) return res.status(404).json({ error: 'Package not found.' });
    let token = rows[0].share_token;
    const markSent = !!(req.body && req.body.markSent);
    // Short links (8 characters). Older long links are replaced by a short one the next time the button is used.
    if (!token || token.length > 10) {
      const alphabet = 'abcdefghjkmnpqrstuvwxyz23456789';
      token = Array.from(crypto.randomBytes(8)).map(b => alphabet[b % alphabet.length]).join('');
      const patchRes = await fetch(`${SUPABASE_URL}/rest/v1/packages?id=eq.${encodeURIComponent(req.params.id)}`, {
        method: 'PATCH', headers: { ...headers, Prefer: 'return=minimal' }, body: JSON.stringify({ share_token: token }),
      });
      if (!patchRes.ok) throw new Error(await patchRes.text());
    }
    if (markSent) {
      await fetch(`${SUPABASE_URL}/rest/v1/packages?id=eq.${encodeURIComponent(req.params.id)}`, {
        method: 'PATCH', headers: { ...headers, Prefer: 'return=minimal' }, body: JSON.stringify({ share_sent_at: new Date().toISOString() }),
      }).catch(() => {});
    }
    res.json({ url: `${PUBLIC_BASE_URL}/e/${token}` });
  } catch (err) {
    console.error('Package share-link error:', err);
    res.status(500).json({ error: 'Failed: ' + err.message });
  }
});

// ---- GET /p/:token ---- (PUBLIC page for the patient: sessions left + money left on their own package, nothing else)
// Package validity from the clinic policy: 6 sessions = 3 weeks, 9 = 1 month, 12 = 6 weeks, counted from the first session.
function packageValidity(totalSessions, startYmd) {
  if (!startYmd) return null;
  const [y, m, d] = startYmd.split('-').map(Number);
  const start = new Date(Date.UTC(y, m - 1, d));
  let end = null;
  if (totalSessions === 6) end = new Date(start.getTime() + 21 * 86400000);
  else if (totalSessions === 12) end = new Date(start.getTime() + 42 * 86400000);
  else if (totalSessions === 9) {
    end = new Date(Date.UTC(y, m, d));
    if (end.getUTCMonth() !== (m % 12)) end = new Date(Date.UTC(y, m + 1, 0)); // clamp, e.g. 31 Jan + 1 month
  }
  return end ? { endYmd: end.toISOString().slice(0, 10) } : null;
}
// Date (Cairo) of the patient's first non-cancelled visit on or after the day the package was bought.
async function packageStartYmd(p, headers) {
  const cairoYmd = iso => new Date(iso).toLocaleDateString('en-CA', { timeZone: 'Africa/Cairo' });
  try {
    const from = new Date(new Date(p.created_at).getTime() - 12 * 3600000).toISOString();
    const nameLike = String(p.patient_name || '').trim().replace(/[*%_,()]/g, '_');
    const ar = await fetch(`${SUPABASE_URL}/rest/v1/appointments?select=patient_name,start_time,status&patient_name=ilike.${encodeURIComponent(nameLike)}&deleted_at=is.null&start_time=gte.${encodeURIComponent(from)}&order=start_time.asc&limit=30`, { headers });
    const rows = ar.ok ? await ar.json() : [];
    const mine = (Array.isArray(rows) ? rows : []).filter(a => a.status !== 'cancelled' && a.status !== 'no_show' && String(a.patient_name || '').trim().toLowerCase() === String(p.patient_name || '').trim().toLowerCase());
    return mine[0] ? cairoYmd(mine[0].start_time) : cairoYmd(p.created_at);
  } catch (e) {
    return p.created_at ? cairoYmd(p.created_at) : null;
  }
}

const CLINIC_LOGO_PNG = Buffer.from('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', 'base64');
app.get('/clinic-logo.png', async (req, res) => {
  try {
    const c = await getClinicConfig();
    const m = /^data:(image\/(?:png|jpeg|webp));base64,(.+)$/.exec(c.logo || '');
    if (m) return res.set({ 'Content-Type': m[1], 'Cache-Control': 'public, max-age=300' }).send(Buffer.from(m[2], 'base64'));
    if (/empower/i.test(c.name || '')) return res.set({ 'Content-Type': 'image/png', 'Cache-Control': 'public, max-age=300' }).send(CLINIC_LOGO_PNG);
    const nm = clinicEsc(String(c.name || 'Clinic'));
    const fs = Math.max(26, Math.min(64, Math.floor(540 / Math.max(6, nm.length * 0.62))));
    res.set({ 'Content-Type': 'image/svg+xml', 'Cache-Control': 'public, max-age=300' }).send('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 600 160"><text x="300" y="98" text-anchor="middle" font-family="Georgia, serif" font-size="' + fs + '" font-weight="700" fill="#1f5c56">' + nm + '</text></svg>');
  } catch (e) { res.set('Content-Type', 'image/png').send(CLINIC_LOGO_PNG); }
});

app.get(['/e/:token', '/p/:token', '/empower/:token'], async (req, res) => {
  const CL = await getClinicConfig();
  const page = (body, status) => res.status(status || 200).set({ 'Content-Type': 'text/html; charset=utf-8', 'X-Robots-Tag': 'noindex, nofollow', 'Cache-Control': 'no-store' }).send(
    `<!doctype html><html lang="en" dir="ltr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex,nofollow"><title>${clinicEsc(CL.name)} – My Package</title>` +
    `<style>body{margin:0;background:#f6f4ee;color:#12363a;font-family:-apple-system,'Segoe UI',Roboto,Arial,sans-serif;padding:20px}.c{max-width:420px;margin:24px auto;background:#fff;border:1px solid #dad6ca;border-radius:18px;padding:26px;text-align:center}` +
    `.brand{font-size:.78rem;letter-spacing:.14em;text-transform:uppercase;color:#b07a1f;font-weight:700;margin-bottom:10px}h1{font-size:1.15rem;margin:0 0 4px}.big{font-size:3.2rem;font-weight:800;color:#12363a;line-height:1.1;margin:14px 0 2px}.sub{color:#5c7478;font-size:.9rem}.bar{height:12px;background:#e7e3d8;border-radius:99px;overflow:hidden;margin:16px 0}.bar i{display:block;height:100%;background:#e8a33d}` +
    `.row{display:flex;justify-content:space-between;padding:10px 0;border-top:1px solid #eee;font-size:.95rem}.due{color:#b3261e;font-weight:700}.ok{color:#1b8a4a;font-weight:700}.f{margin-top:18px;font-size:.8rem;color:#8a938e}</style></head><body><div class="c"><img src="/clinic-logo.png" alt="${clinicEsc(CL.name)}" style="max-width:240px;width:80%;height:auto;display:block;margin:0 auto 14px">${body}</div></body></html>`);
  const bad = '<h1>Link not valid</h1><div class="sub">Please check the link or contact the clinic.</div>';
  const token = String(req.params.token || '');
  if (!/^[a-z0-9]{8,24}$/.test(token) || !SUPABASE_URL || !SUPABASE_SERVICE_KEY) return page(bad, 404);
  try {
    const pkgHeaders = { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}` };
    let r = await fetch(`${SUPABASE_URL}/rest/v1/packages?share_token=eq.${token}&select=patient_name,total_sessions,used_sessions,total_price,amount_paid,created_at,start_date`, { headers: pkgHeaders });
    if (!r.ok) r = await fetch(`${SUPABASE_URL}/rest/v1/packages?share_token=eq.${token}&select=patient_name,total_sessions,used_sessions,total_price,amount_paid,created_at`, { headers: pkgHeaders });
    const rows = await r.json();
    if (!r.ok || !Array.isArray(rows) || !rows[0]) return page(bad, 404);
    const p = rows[0];
    const esc = s => String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
    const total = Number(p.total_sessions) || 0, used = Math.min(Number(p.used_sessions) || 0, total), left = Math.max(0, total - used);
    const pct = total ? Math.round(used / total * 100) : 0;
    const egp = n => Math.round(n).toLocaleString('en-US') + ' EGP';
    let money = '';
    if (p.total_price != null) {
      const due = Math.max(0, Math.round(Number(p.total_price) - Number(p.amount_paid || 0)));
      money = `<div class="row"><span>Package price</span><span>${egp(Number(p.total_price))}</span></div>` +
        `<div class="row"><span>Paid</span><span>${egp(Number(p.amount_paid || 0))}</span></div>` +
        `<div class="row"><span>Remaining balance</span><span class="${due > 0 ? 'due' : 'ok'}">${due > 0 ? egp(due) : 'Fully paid ✓'}</span></div>`;
    }
    // Start date = the manual date if set, else the first real visit on/after the package was bought. Not started until a session is used.
    let startYmd = null;
    if (p.start_date) startYmd = String(p.start_date).slice(0, 10);
    else if (used > 0) startYmd = await packageStartYmd(p, pkgHeaders);
    const validity = packageValidity(total, startYmd);
    const dfmt = ymd => new Date(ymd + 'T12:00:00Z').toLocaleDateString('en-GB', { day: 'numeric', month: 'short', year: 'numeric', timeZone: 'UTC' });
    let timing = '';
    if (startYmd) timing += `<div class="row"><span>Started</span><span>${dfmt(startYmd)}</span></div>`;
    else timing += `<div class="row"><span>Started</span><span>Not yet — starts with your first session</span></div>`;
    if (validity) {
      const left = Math.ceil((new Date(validity.endYmd + 'T23:59:59Z').getTime() - Date.now()) / 86400000);
      const state = left < 0 ? `<span class="due">Validity ended ${dfmt(validity.endYmd)}</span>` : (left <= 7 ? `<span class="due">${dfmt(validity.endYmd)} · ${left + 1 > 1 ? left + ' days left' : 'last day'}</span>` : `<span>${dfmt(validity.endYmd)} · ${left} days left</span>`);
      timing += `<div class="row"><span>Valid until</span>${state}</div>`;
    } else if (startYmd) {
      // no standard validity for this package size
    }
    const clinicPhone = process.env.CLINIC_PHONE || CL.phone || '';
    page(`<h1>Hello ${esc(p.patient_name)} 🌷</h1><div class="sub">Your package status</div>` +
      (left > 0 ? `<div class="big">${left}</div><div class="sub">${left === 1 ? 'session' : 'sessions'} remaining out of ${total}</div>` : `<div class="big" style="font-size:1.6rem">Package completed ✓</div><div class="sub">You used ${total} of ${total} sessions</div>`) +
      `<div class="bar"><i style="width:${pct}%"></i></div><div class="row"><span>Sessions used</span><span>${used} of ${total}</span></div>${timing}${money}` +
      `<div class="f">To book or ask a question, contact us: ${esc(clinicPhone)}</div>`);
  } catch (err) {
    console.error('Public package page error:', err);
    page('<h1>Something went wrong</h1><div class="sub">Please try again in a moment.</div>', 500);
  }
});

// ---- POST /api/packages/:id/policy-sent ---- (mark the package policy as sent, or pass sent:false to clear it)
app.post('/api/packages/:id/policy-sent', requireApprovedAny, ownPkgGuard, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  const sent = !(req.body && req.body.sent === false);
  try {
    const patchRes = await fetch(`${SUPABASE_URL}/rest/v1/packages?id=eq.${encodeURIComponent(req.params.id)}`, {
      method: 'PATCH',
      headers: {
        apikey: SUPABASE_SERVICE_KEY,
        Authorization: `Bearer ${SUPABASE_SERVICE_KEY}`,
        'Content-Type': 'application/json',
        Prefer: 'return=representation',
      },
      body: JSON.stringify({ policy_sent_at: sent ? new Date().toISOString() : null }),
    });
    const updated = await patchRes.json();
    if (!patchRes.ok) throw new Error(JSON.stringify(updated));
    res.json(Array.isArray(updated) ? updated[0] : updated);
  } catch (err) {
    console.error('Package policy-sent error:', err);
    res.status(500).json({ error: 'Failed: ' + err.message });
  }
});

// ---- POST /api/packages/:id/set-used ---- (correct how many sessions the package has used — e.g. free sessions or a visit that belonged to the previous package were counted by mistake)
app.post('/api/packages/:id/set-used', requireApprovedAny, ownPkgGuard, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  if (req.doctor.role === 'doctor' && !hasPermission(req.doctor, 'register_packages')) {
    return res.status(403).json({ error: 'You don\'t have permission to change a package\'s session count — ask the clinic owner to grant it.' });
  }
  const value = parseInt(req.body && req.body.usedSessions, 10);
  if (!Number.isInteger(value) || value < 0) return res.status(400).json({ error: 'Missing or invalid usedSessions.' });
  try {
    const headers = { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}` };
    const getRes = await fetch(`${SUPABASE_URL}/rest/v1/packages?id=eq.${encodeURIComponent(req.params.id)}`, { headers });
    const rows = await getRes.json();
    const pkg = Array.isArray(rows) && rows[0];
    if (!pkg) return res.status(404).json({ error: 'Package not found.' });
    if (value > pkg.total_sessions) return res.status(400).json({ error: `This package only has ${pkg.total_sessions} sessions.` });
    const patchRes = await fetch(`${SUPABASE_URL}/rest/v1/packages?id=eq.${encodeURIComponent(req.params.id)}`, {
      method: 'PATCH',
      headers: { ...headers, 'Content-Type': 'application/json', Prefer: 'return=representation' },
      body: JSON.stringify({ used_sessions: value }),
    });
    const updated = await patchRes.json();
    if (!patchRes.ok) throw new Error(JSON.stringify(updated));
    res.json(Array.isArray(updated) ? updated[0] : updated);
  } catch (err) {
    console.error('Package set-used error:', err);
    res.status(500).json({ error: 'Failed: ' + err.message });
  }
});

// ---- POST /api/packages/:id/set-paid ---- (correct how much of the package price counts as paid, WITHOUT recording any money — for payments already recorded on an appointment)
app.post('/api/packages/:id/set-paid', requireApprovedAny, ownPkgGuard, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  const value = Number(req.body && req.body.amountPaid);
  if (!isFinite(value) || value < 0) return res.status(400).json({ error: 'Missing or invalid amountPaid.' });
  try {
    const patchRes = await fetch(`${SUPABASE_URL}/rest/v1/packages?id=eq.${encodeURIComponent(req.params.id)}`, {
      method: 'PATCH',
      headers: {
        apikey: SUPABASE_SERVICE_KEY,
        Authorization: `Bearer ${SUPABASE_SERVICE_KEY}`,
        'Content-Type': 'application/json',
        Prefer: 'return=representation',
      },
      body: JSON.stringify({ amount_paid: value }),
    });
    const updated = await patchRes.json();
    if (!patchRes.ok) throw new Error(JSON.stringify(updated));
    if (!Array.isArray(updated) || updated.length === 0) return res.status(404).json({ error: 'Package not found.' });
    res.json(updated[0]);
  } catch (err) {
    console.error('Package set-paid error:', err);
    res.status(500).json({ error: 'Failed: ' + err.message });
  }
});

// ---- POST /api/packages/:id/add-payment ---- (record another installment toward this package's total_price)
app.post('/api/packages/:id/add-payment', requireApprovedAny, ownPkgGuard, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  const { amount } = req.body || {};
  const add = Number(amount);
  if (!add || add <= 0) return res.status(400).json({ error: 'Missing or invalid amount.' });
  try {
    const getUrl = `${SUPABASE_URL}/rest/v1/packages?id=eq.${encodeURIComponent(req.params.id)}`;
    const getRes = await fetch(getUrl, { headers: { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}` } });
    const rows = await getRes.json();
    const pkg = Array.isArray(rows) && rows[0];
    if (!pkg) return res.status(404).json({ error: 'Package not found.' });
    const newPaid = Number(pkg.amount_paid || 0) + add;
    const patchRes = await fetch(getUrl, {
      method: 'PATCH',
      headers: {
        apikey: SUPABASE_SERVICE_KEY,
        Authorization: `Bearer ${SUPABASE_SERVICE_KEY}`,
        'Content-Type': 'application/json',
        Prefer: 'return=representation',
      },
      body: JSON.stringify({ amount_paid: newPaid }),
    });
    const updated = await patchRes.json();
    if (!patchRes.ok) throw new Error(JSON.stringify(updated));
    res.json(Array.isArray(updated) ? updated[0] : updated);
  } catch (err) {
    console.error('Package add-payment error:', err);
    res.status(500).json({ error: 'Failed: ' + err.message });
  }
});

// ---- POST /api/packages/:id/use-session ---- (consume one session from the package)
app.post('/api/packages/:id/use-session', requireApprovedAny, ownPkgGuard, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  if (req.doctor.role === 'doctor' && !hasPermission(req.doctor, 'view_payments')) {
    return res.status(403).json({ error: 'You don\'t have permission to record payments — ask the clinic owner to grant it.' });
  }
  try {
    const getUrl = `${SUPABASE_URL}/rest/v1/packages?id=eq.${encodeURIComponent(req.params.id)}`;
    const getRes = await fetch(getUrl, { headers: { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}` } });
    const rows = await getRes.json();
    const pkg = Array.isArray(rows) && rows[0];
    if (!pkg) return res.status(404).json({ error: 'Package not found.' });
    const newUsed = pkg.used_sessions + 1;
    const patchRes = await fetch(getUrl, {
      method: 'PATCH',
      headers: {
        apikey: SUPABASE_SERVICE_KEY,
        Authorization: `Bearer ${SUPABASE_SERVICE_KEY}`,
        'Content-Type': 'application/json',
        Prefer: 'return=representation',
      },
      body: JSON.stringify({ used_sessions: newUsed }),
    });
    const updated = await patchRes.json();
    if (!patchRes.ok) throw new Error(JSON.stringify(updated));
    res.json(Array.isArray(updated) ? updated[0] : updated);
  } catch (err) {
    console.error('Use-session error:', err);
    res.status(500).json({ error: 'Failed to update package: ' + err.message });
  }
});

// ---- GET /api/appointments/search-by-patient ----
// Free-text patient search across ALL dates (not scoped to a month) —
// powers the calendar's "find a patient" search box, letting the owner
// jump straight to whichever day their appointment is on.
app.get('/api/appointments/search-by-patient', requireApprovedAny, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  const { q } = req.query;
  if (!q || q.trim().length < 2) return res.status(400).json({ error: 'Search term must be at least 2 characters.' });
  try {
    const url = `${SUPABASE_URL}/rest/v1/appointments?patient_name=ilike.*${encodeURIComponent(q.trim())}*&deleted_at=is.null${isOwnOnly(req.doctor) ? '&doctor_name=eq.' + encodeURIComponent(ownDoctorName(req.doctor)) : ''}&order=start_time.desc&limit=30`;
    const upstream = await fetch(url, { headers: { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}` } });
    const data = await upstream.text();
    res.status(upstream.status).type('application/json').send(data);
  } catch (err) {
    console.error('Search-by-patient error:', err);
    res.status(500).json({ error: 'Search failed: ' + err.message });
  }
});

app.get('/api/appointments/unpaid-by-patient', requireApprovedAny, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  const { patientName } = req.query;
  if (!patientName) return res.status(400).json({ error: 'Missing patientName.' });
  try {
    const url = `${SUPABASE_URL}/rest/v1/appointments?patient_name=eq.${encodeURIComponent(patientName)}&paid=eq.false&status=neq.cancelled&deleted_at=is.null${isOwnOnly(req.doctor) ? '&doctor_name=eq.' + encodeURIComponent(ownDoctorName(req.doctor)) : ''}&order=start_time.desc&limit=20`;
    const upstream = await fetch(url, { headers: { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}` } });
    const data = await upstream.text();
    res.status(upstream.status).type('application/json').send(data);
  } catch (err) {
    console.error('Unpaid-by-patient GET error:', err);
    res.status(500).json({ error: 'Failed to load unpaid appointments: ' + err.message });
  }
});

// ---- DELETE /api/appointments/delete-day ---- (?start=ISO&end=ISO) owner-only.
// SOFT delete: sets deleted_at instead of removing rows, so it can be
// undone from the trash within 7 days.
app.delete('/api/appointments/delete-day', requireOwnerDoctor, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  const { start, end } = req.query;
  if (!start || !end) return res.status(400).json({ error: 'Missing start or end.' });
  try {
    const url = `${SUPABASE_URL}/rest/v1/appointments?start_time=gte.${encodeURIComponent(start)}&start_time=lte.${encodeURIComponent(end)}&deleted_at=is.null`;
    const delRes = await fetch(url, {
      method: 'PATCH',
      headers: {
        apikey: SUPABASE_SERVICE_KEY,
        Authorization: `Bearer ${SUPABASE_SERVICE_KEY}`,
        'Content-Type': 'application/json',
        Prefer: 'return=representation',
      },
      body: JSON.stringify({ deleted_at: new Date().toISOString() }),
    });
    const data = await delRes.json();
    if (!delRes.ok) throw new Error(JSON.stringify(data));
    res.json({ ok: true, deleted: Array.isArray(data) ? data.length : 0 });
  } catch (err) {
    console.error('Delete-day error:', err);
    res.status(500).json({ error: 'Failed to delete: ' + err.message });
  }
});

// ---- GET /api/appointments/trash ---- owner-only, lists soft-deleted
// appointments from the last 7 days, grouped by the day they were on.
app.get('/api/appointments/trash', requireOwnerDoctor, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  try {
    const cutoff = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString();
    const url = `${SUPABASE_URL}/rest/v1/appointments?deleted_at=gte.${encodeURIComponent(cutoff)}&order=deleted_at.desc,start_time.asc`;
    const upstream = await fetch(url, { headers: { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}` } });
    const data = await upstream.text();
    res.status(upstream.status).type('application/json').send(data);
  } catch (err) {
    console.error('Trash GET error:', err);
    res.status(500).json({ error: 'Failed to load trash: ' + err.message });
  }
});

// ---- POST /api/appointments/restore-day ---- (?start=ISO&end=ISO) owner-only,
// undoes a delete-day within the 7-day window.
app.post('/api/appointments/restore-day', requireOwnerDoctor, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  const { start, end } = req.query;
  if (!start || !end) return res.status(400).json({ error: 'Missing start or end.' });
  try {
    const url = `${SUPABASE_URL}/rest/v1/appointments?start_time=gte.${encodeURIComponent(start)}&start_time=lte.${encodeURIComponent(end)}&deleted_at=not.is.null`;
    const restoreRes = await fetch(url, {
      method: 'PATCH',
      headers: {
        apikey: SUPABASE_SERVICE_KEY,
        Authorization: `Bearer ${SUPABASE_SERVICE_KEY}`,
        'Content-Type': 'application/json',
        Prefer: 'return=representation',
      },
      body: JSON.stringify({ deleted_at: null }),
    });
    const data = await restoreRes.json();
    if (!restoreRes.ok) throw new Error(JSON.stringify(data));
    res.json({ ok: true, restored: Array.isArray(data) ? data.length : 0 });
  } catch (err) {
    console.error('Restore-day error:', err);
    res.status(500).json({ error: 'Failed to restore: ' + err.message });
  }
});

app.get('/api/appointments', requireApprovedAny, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  const { start, end } = req.query;
  if (!start || !end) return res.status(400).json({ error: 'Missing start or end query params.' });
  try {
    const url = `${SUPABASE_URL}/rest/v1/appointments?start_time=gte.${encodeURIComponent(start)}&start_time=lte.${encodeURIComponent(end)}&deleted_at=is.null${isOwnOnly(req.doctor) ? '&doctor_name=eq.' + encodeURIComponent(ownDoctorName(req.doctor)) : ''}&order=start_time.asc`;
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
  const { patientName, startTime, endTime, doctorColor, doctorName, patientPhone, visitType } = req.body || {};
  if (!patientName || !startTime || !endTime) return res.status(400).json({ error: 'Missing patientName, startTime, or endTime.' });
  // Secretaries manage the whole schedule as their job; a plain doctor
  // needs the manage_other_appointments permission to book under someone
  // else's name — otherwise it's silently forced back to their own.
  let effectiveDoctorName = doctorName || req.doctor.name || req.doctor.email;
  const ownName = req.doctor.name || req.doctor.email;
  if (doctorName && doctorName !== ownName && req.doctor.role === 'doctor' && !hasPermission(req.doctor, 'manage_other_appointments')) {
    effectiveDoctorName = ownName;
  }
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
        doctor_name: effectiveDoctorName,
        patient_phone: patientPhone || null,
        visit_type: visitType || 'session',
      }),
    });
    const data = await upstream.text();
    res.status(upstream.status).type('application/json').send(data);

    // Give the patient a ready Documentation "file" under their assigned
    // doctor as soon as they're booked — best-effort, never blocks the
    // booking response above.
    if (upstream.ok) {
      try {
        const finalDoctorName = effectiveDoctorName;
        const checkUrl = `${SUPABASE_URL}/rest/v1/sessions?patient_name=eq.${encodeURIComponent(patientName)}&doctor_name=eq.${encodeURIComponent(finalDoctorName)}&select=id&limit=1`;
        const checkRes = await fetch(checkUrl, { headers: { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}` } });
        const existing = await checkRes.json();
        if (!Array.isArray(existing) || existing.length === 0) {
          await fetch(`${SUPABASE_URL}/rest/v1/sessions`, {
            method: 'POST',
            headers: {
              apikey: SUPABASE_SERVICE_KEY,
              Authorization: `Bearer ${SUPABASE_SERVICE_KEY}`,
              'Content-Type': 'application/json',
            },
            body: JSON.stringify({
              id: crypto.randomUUID(),
              patient_name: patientName,
              doctor_name: finalDoctorName,
              session_date: new Date(startTime).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' }),
              session_type: 'assessment',
              updated_at: new Date().toISOString(),
            }),
          });
        }
      } catch (fileErr) {
        console.error('Auto-create documentation file failed (non-fatal):', fileErr);
      }
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
app.patch('/api/appointments/:id', requireApprovedAny, ownApptGuard, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  const { patientName, patientPhone, startTime, endTime, doctorColor, doctorName, status, paid, visitType, isFree, arrived } = req.body || {};
  const ownName = req.doctor.name || req.doctor.email;

  // Cancelling / restoring / no-show requires edit_cancel_appointments
  // (owner and secretary always allowed — cancelling is core to running
  // the schedule day-to-day).
  if (status !== undefined && req.doctor.role === 'doctor' && !hasPermission(req.doctor, 'edit_cancel_appointments')) {
    return res.status(403).json({ error: 'You don\'t have permission to cancel/restore appointments — ask the clinic owner to grant it.' });
  }
  // Marking paid/unpaid/free requires view_payments (owner/secretary exempt).
  if ((paid !== undefined || isFree !== undefined) && req.doctor.role === 'doctor' && !hasPermission(req.doctor, 'view_payments')) {
    return res.status(403).json({ error: 'You don\'t have permission to record payments — ask the clinic owner to grant it.' });
  }
  // Reassigning to a different doctor requires manage_other_appointments.
  let effectiveDoctorName = doctorName;
  if (doctorName !== undefined && doctorName !== ownName && req.doctor.role === 'doctor' && !hasPermission(req.doctor, 'manage_other_appointments')) {
    effectiveDoctorName = ownName;
  }

  const patch = {};
  if (patientName !== undefined) patch.patient_name = patientName;
  if (patientPhone !== undefined) patch.patient_phone = patientPhone || null;
  if (startTime !== undefined) patch.start_time = startTime;
  if (endTime !== undefined) patch.end_time = endTime;
  if (doctorColor !== undefined) patch.doctor_color = doctorColor || null;
  if (effectiveDoctorName !== undefined) patch.doctor_name = effectiveDoctorName || null;
  if (status !== undefined) patch.status = status;
  if (status === 'cancelled') patch.cancelled_at = new Date().toISOString();
  else if (status !== undefined) patch.cancelled_at = null; // restoring or any other status clears it
  if (paid !== undefined) patch.paid = paid;
  if (visitType !== undefined) patch.visit_type = visitType;
  if (isFree !== undefined){ patch.is_free = isFree; if(isFree) patch.paid = true; }
  // Check-in: anyone signed in can mark a patient as arrived (or undo it) — no extra permission, the secretary does this all day.
  if (arrived !== undefined) patch.arrived_at = arrived ? new Date().toISOString() : null;
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

    if (upstream.ok && arrived === true) {
      try {
        const rows = JSON.parse(data);
        const updatedAppt = Array.isArray(rows) ? rows[0] : rows;
        notifyDoctorArrivalTelegram(updatedAppt).catch(e => console.error('Telegram arrival alert failed:', e.message));
      } catch (e) { /* the alert is optional */ }
    }

    if (upstream.ok && (doctorName !== undefined || patientName !== undefined)) {
      try {
        const rows = JSON.parse(data);
        const updated = Array.isArray(rows) ? rows[0] : rows;
        if (updated && updated.patient_name && updated.doctor_name) {
          const checkUrl = `${SUPABASE_URL}/rest/v1/sessions?patient_name=eq.${encodeURIComponent(updated.patient_name)}&doctor_name=eq.${encodeURIComponent(updated.doctor_name)}&select=id&limit=1`;
          const checkRes = await fetch(checkUrl, { headers: { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}` } });
          const existing = await checkRes.json();
          if (!Array.isArray(existing) || existing.length === 0) {
            await fetch(`${SUPABASE_URL}/rest/v1/sessions`, {
              method: 'POST',
              headers: {
                apikey: SUPABASE_SERVICE_KEY,
                Authorization: `Bearer ${SUPABASE_SERVICE_KEY}`,
                'Content-Type': 'application/json',
              },
              body: JSON.stringify({
                id: crypto.randomUUID(),
                patient_name: updated.patient_name,
                doctor_name: updated.doctor_name,
                session_date: updated.start_time ? new Date(updated.start_time).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' }) : null,
                session_type: 'assessment',
                updated_at: new Date().toISOString(),
              }),
            });
          }
        }
      } catch (fileErr) {
        console.error('Auto-create documentation file failed on edit (non-fatal):', fileErr);
      }
    }
  } catch (err) {
    console.error('Appointment PATCH error:', err);
    res.status(500).json({ error: 'Failed to update appointment: ' + err.message });
  }
});

// ---- DELETE /api/appointments/:id ----
app.delete('/api/appointments/:id', requireApprovedAny, ownApptGuard, async (req, res) => {
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
function normalizeEgyptPhone(raw){
  const trimmed = String(raw || '').trim();
  const digits = trimmed.replace(/[^\d]/g, '');
  if(!digits) return digits;
  // Explicit international format ("+44…" or "0044…") — keep the country code as typed.
  if(trimmed.startsWith('+')) return digits;
  if(digits.startsWith('00')) return digits.slice(2);
  // Egyptian local format (01xxxxxxxxx, or a landline like 02xxxxxxxx).
  if(digits.startsWith('0')) return '20' + digits.slice(1);
  // Already Egyptian international (20 + 10 digits).
  if(digits.startsWith('20') && digits.length === 12) return digits;
  // Egyptian mobile typed without the leading 0 (1[0125] + 8 digits).
  if(/^1[0125]\d{8}$/.test(digits)) return '20' + digits;
  // Long enough to already carry a country code (e.g. 447762863623 typed without "+") — leave it alone.
  if(digits.length >= 11) return digits;
  // Short leftover: assume Egyptian.
  return '20' + digits;
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

// ---- Sends "appointment_confirmation" to everyone booked on a given day ----
// Shared by the (currently disabled) midnight auto-scheduler and the
// manual "send now" button — same logic either way, just triggered
// differently. Returns a summary instead of just logging, so the manual
// trigger can show the owner exactly what happened.
async function sendConfirmationsForDate(targetDate, templateName) {
  const finalTemplate = templateName || 'appointment_confirmation';
  const noVariableTemplates = ['package_policy', 'recovery_session_policy'];
  const start = new Date(targetDate.getFullYear(), targetDate.getMonth(), targetDate.getDate(), 0, 0, 0);
  const end = new Date(targetDate.getFullYear(), targetDate.getMonth(), targetDate.getDate(), 23, 59, 59);
  const url = `${SUPABASE_URL}/rest/v1/appointments?start_time=gte.${encodeURIComponent(start.toISOString())}&start_time=lte.${encodeURIComponent(end.toISOString())}&status=neq.cancelled&deleted_at=is.null`;
  const res = await fetch(url, { headers: { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}` } });
  const appointments = await res.json();
  const summary = { total: 0, sent: 0, skippedNoPhone: 0, failed: [] };
  if (!Array.isArray(appointments)) return summary;
  summary.total = appointments.length;
  for (const appt of appointments) {
    if (!appt.patient_phone) { summary.skippedNoPhone++; continue; }
    const apptDate = new Date(appt.start_time);
    const dateLabel = apptDate.toLocaleDateString('en-GB', { timeZone: 'Africa/Cairo', weekday: 'long', day: 'numeric', month: 'long' });
    const timeLabel = apptDate.toLocaleTimeString('en-US', { timeZone: 'Africa/Cairo', hour: 'numeric', minute: '2-digit', hour12: true });
    const params = noVariableTemplates.includes(finalTemplate) ? [] : [appt.patient_name || '', dateLabel, timeLabel];
    try {
      await sendWhatsAppTemplate(appt.patient_phone, finalTemplate, params);
      summary.sent++;
    } catch (err) {
      summary.failed.push({ patient: appt.patient_name, error: err.message });
    }
    await new Promise(r => setTimeout(r, 1200)); // gentle pacing, avoid tripping Meta's rate limits
  }
  return summary;
}

// ---- POST /api/whatsapp/send-confirmations-now ----
// The manual "press whenever you need it" alternative to the disabled
// midnight scheduler. Defaults to tomorrow's appointments if no date is
// given (matches what the scheduler would have sent).
app.post('/api/whatsapp/send-confirmations-now', requireOwnerOrPermission('send_whatsapp'), async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  try {
    const { date, templateName } = req.body || {};
    let targetDate;
    if (date) {
      const [y, m, d] = date.split('-').map(Number);
      targetDate = new Date(y, m - 1, d);
    } else {
      const nowCairo = new Date(new Date().toLocaleString('en-US', { timeZone: 'Africa/Cairo' }));
      targetDate = new Date(nowCairo.getFullYear(), nowCairo.getMonth(), nowCairo.getDate() + 1);
    }
    const summary = await sendConfirmationsForDate(targetDate, templateName);
    res.json(summary);
  } catch (err) {
    console.error('Manual send-confirmations error:', err);
    res.status(500).json({ error: 'Failed to send: ' + err.message });
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
    const summary = await sendConfirmationsForDate(tomorrow);
    console.log(`[auto-confirm] Done — ${summary.sent}/${summary.total} sent, ${summary.failed.length} failed.`);
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
app.get('/api/appointments/:id/notes', requireApprovedAny, ownApptGuard, async (req, res) => {
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
app.delete('/api/appointments/:id/notes', requireApprovedAny, ownApptGuard, async (req, res) => {
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
app.post('/api/appointments/:id/notes', requireApprovedAny, ownApptGuard, async (req, res) => {
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
// ---- POST /api/sessions/merge ---- combine two session "files" into one
app.post('/api/sessions/merge', requireApprovedDoctor, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  const { keepId, removeId } = req.body || {};
  if (!keepId || !removeId) return res.status(400).json({ error: 'Missing keepId or removeId.' });
  try {
    const headers = { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}` };
    const [keepRes, removeRes] = await Promise.all([
      fetch(`${SUPABASE_URL}/rest/v1/sessions?id=eq.${encodeURIComponent(keepId)}`, { headers }),
      fetch(`${SUPABASE_URL}/rest/v1/sessions?id=eq.${encodeURIComponent(removeId)}`, { headers }),
    ]);
    const [keepRows, removeRows] = await Promise.all([keepRes.json(), removeRes.json()]);
    const keepSession = Array.isArray(keepRows) && keepRows[0];
    const removeSession = Array.isArray(removeRows) && removeRows[0];
    if (!keepSession || !removeSession) return res.status(404).json({ error: 'One or both sessions not found.' });

    const mergedNote = [keepSession.note, removeSession.note].filter(Boolean).join('\n\n---\n\n');
    const mergedTranscript = [...(keepSession.transcript || []), ...(removeSession.transcript || [])];

    const patchRes = await fetch(`${SUPABASE_URL}/rest/v1/sessions?id=eq.${encodeURIComponent(keepId)}`, {
      method: 'PATCH',
      headers: { ...headers, 'Content-Type': 'application/json', Prefer: 'return=representation' },
      body: JSON.stringify({ note: mergedNote, transcript: mergedTranscript, updated_at: new Date().toISOString() }),
    });
    if (!patchRes.ok) throw new Error(await patchRes.text());

    await fetch(`${SUPABASE_URL}/rest/v1/sessions?id=eq.${encodeURIComponent(removeId)}`, {
      method: 'DELETE',
      headers,
    });

    const updated = await patchRes.json();
    res.json(Array.isArray(updated) ? updated[0] : updated);
  } catch (err) {
    console.error('Session merge error:', err);
    res.status(500).json({ error: 'Failed to merge sessions: ' + err.message });
  }
});

// ---- PATCH /api/sessions/rename-patient ---- merges a misspelled patient
// name's sessions into the correct one (same trimmed-match approach as
// rename-doctor above).
app.patch('/api/sessions/rename-patient', requireApprovedDoctor, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  const { fromName, toName } = req.body || {};
  if (!fromName || !toName) return res.status(400).json({ error: 'Missing fromName or toName.' });
  try {
    const allRes = await fetch(`${SUPABASE_URL}/rest/v1/sessions?select=id,patient_name`, {
      headers: { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}` },
    });
    const allSessions = await allRes.json();
    if (!allRes.ok) {
      console.error('Session rename-patient: could not list sessions', allRes.status, allSessions);
      return res.status(500).json({ error: 'Could not read sessions to merge.' });
    }
    const target = fromName.trim().toLowerCase();
    const matchingIds = (allSessions || [])
      .filter(s => (s.patient_name || '').trim().toLowerCase() === target)
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
      body: JSON.stringify({ patient_name: toName.trim() }),
    });
    const data = await updateRes.json();
    if (!updateRes.ok) {
      console.error('Session rename-patient failed:', updateRes.status, data);
      return res.status(500).json({ error: 'Failed to merge sessions.' });
    }
    res.json({ ok: true, count: Array.isArray(data) ? data.length : 0 });
  } catch (err) {
    console.error('Session rename-patient error:', err);
    res.status(500).json({ error: 'Failed to merge sessions: ' + err.message });
  }
});

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
    const target = fromName.trim().toLowerCase();
    const matchingIds = (allSessions || [])
      .filter(s => (s.doctor_name || '').trim().toLowerCase() === target)
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
    // If this note already exists, keep its original author: someone else
    // editing it must not move it to their own list.
    let keepDoctor = null;
    try {
      const er = await fetch(`${SUPABASE_URL}/rest/v1/sessions?id=eq.${encodeURIComponent(id)}&select=doctor_name&limit=1`, { headers: { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}` } });
      const er2 = await er.json();
      if (Array.isArray(er2) && er2[0] && er2[0].doctor_name) keepDoctor = er2[0].doctor_name;
    } catch (e) { /* fall back to the editor's name */ }
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
        doctor_name: keepDoctor || req.doctor.name || req.doctor.email,
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
    // Without view_other_patients, a doctor only sees their OWN patients'
    // files — not the whole clinic's.
    const sbHeaders = { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}` };
    if (!hasPermission(req.doctor, 'view_other_patients') || isOwnOnly(req.doctor)) {
      // A patient's file belongs to the PATIENT, not to whoever typed the note.
      // So a doctor sees (a) notes they wrote, plus (b) EVERY note, by anyone,
      // for patients they have appointments with.
      const me = req.doctor.name || req.doctor.email;
      const ar = await fetch(`${SUPABASE_URL}/rest/v1/appointments?select=patient_name&deleted_at=is.null&doctor_name=eq.${encodeURIComponent(me)}&limit=10000`, { headers: sbHeaders });
      const arows = await ar.json();
      const myPatients = new Set((Array.isArray(arows) ? arows : []).map(r => String(r.patient_name || '').trim().toLowerCase()).filter(Boolean));
      const lr = await fetch(`${SUPABASE_URL}/rest/v1/sessions?select=id,patient_name,doctor_name&limit=20000`, { headers: sbHeaders });
      const lrows = await lr.json();
      if (!lr.ok || !Array.isArray(lrows)) return res.status(500).json({ error: 'Failed to load sessions.' });
      const ids = lrows
        .filter(r => r.doctor_name === me || myPatients.has(String(r.patient_name || '').trim().toLowerCase()))
        .filter(r => !patientName || String(r.patient_name || '').toLowerCase().includes(String(patientName).toLowerCase()))
        .map(r => r.id);
      const out = [];
      for (let i = 0; i < ids.length; i += 40) {
        const chunk = ids.slice(i, i + 40).map(x => '"' + String(x).replace(/"/g, '') + '"').join(',');
        const cr = await fetch(`${SUPABASE_URL}/rest/v1/sessions?id=in.(${encodeURIComponent(chunk)})&order=${order === 'asc' ? 'created_at.asc' : 'created_at.desc'}`, { headers: sbHeaders });
        const crows = await cr.json();
        if (!cr.ok || !Array.isArray(crows)) return res.status(500).json({ error: 'Failed to load sessions.' });
        out.push(...crows);
      }
      out.sort((a, b) => (order === 'asc' ? 1 : -1) * (new Date(a.created_at) - new Date(b.created_at)));
      return res.json(out);
    }
    const upstream = await fetch(url, { headers: sbHeaders });
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

// Videos go in the same private bucket as the images (so the existing gallery,
// signed links and delete all work for them). The browser sends the raw file;
// 50 MB is Supabase's default per-file limit on the free plan.
const VIDEO_MAX_BYTES = 50 * 1024 * 1024;
const VIDEO_EXT = { 'video/mp4': 'mp4', 'video/quicktime': 'mov', 'video/webm': 'webm', 'video/x-m4v': 'm4v', 'video/3gpp': '3gp', 'video/x-matroska': 'mkv' };
app.post('/api/sessions/:id/videos', requireApprovedDoctor, express.raw({ type: () => true, limit: VIDEO_MAX_BYTES }), async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  const mimeType = String(req.headers['content-type'] || '').split(';')[0].trim().toLowerCase();
  if (!mimeType.startsWith('video/')) return res.status(400).json({ error: 'That file is not a video.' });
  if (!Buffer.isBuffer(req.body) || req.body.length === 0) return res.status(400).json({ error: 'Empty video.' });
  try {
    const ext = VIDEO_EXT[mimeType] || 'mp4';
    const base = String(req.query.filename || 'video').replace(/\.[^.]+$/, '').replace(/[^a-zA-Z0-9_-]/g, '_').slice(0, 60) || 'video';
    const path = `${req.params.id}/${Date.now()}_${base}.${ext}`;
    const upstream = await fetch(`${SUPABASE_URL}/storage/v1/object/${IMAGE_BUCKET}/${path}`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${SUPABASE_SERVICE_KEY}`, 'Content-Type': mimeType, 'x-upsert': 'false' },
      body: req.body,
    });
    const data = await upstream.json().catch(() => ({}));
    if (!upstream.ok) {
      console.error('Video upload failed:', data);
      return res.status(500).json({ error: data.message || 'Failed to upload video (check the storage bucket allows video files and the size limit).' });
    }
    res.json({ ok: true, path });
  } catch (err) {
    console.error('Video upload error:', err);
    res.status(500).json({ error: 'Failed to upload video: ' + err.message });
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
  logActivity(req, existingSession ? 'open' : 'google', email);
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
      logActivity(req, 'failed', email.trim().toLowerCase(), 'wrong password');
      return res.status(401).json({ error: 'Wrong email or password.' });
    }
    logActivity(req, 'login', doctor.email);
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

app.post('/api/doctors/manual', requireOwnerOrPermission('manage_team'), async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  const { name, color, email, role } = req.body || {};
  if (!name || !name.trim()) return res.status(400).json({ error: 'Missing doctor name.' });
  const finalRole = role === 'secretary' ? 'secretary' : 'doctor';
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
        role: finalRole,
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
app.post('/api/doctors/merge', requireOwnerOrPermission('manage_team'), async (req, res) => {
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

app.get('/api/doctors', requireOwnerOrPermission('manage_team'), async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  try {
    const url = `${SUPABASE_URL}/rest/v1/doctors?order=requested_at.desc`;
    const upstream = await fetch(url, { headers: { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}` } });
    const rows = await upstream.json();
    if (!upstream.ok) return res.status(upstream.status).json(rows);
    res.json((Array.isArray(rows) ? rows : []).map(({ password_hash, ...rest }) => rest));
  } catch (err) {
    console.error('Doctors GET error:', err);
    res.status(500).json({ error: 'Failed to load doctors: ' + err.message });
  }
});

// Lighter-weight roster for color assignment — owner OR secretary, and
// only exposes approved doctors/owners (not pending/removed accounts).
app.get('/api/doctors/colors', requireApprovedAny, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  try {
    const url = `${SUPABASE_URL}/rest/v1/doctors?status=eq.approved&role=in.(doctor,owner)&order=name.asc&select=name,email,color,role`;
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
// ---- Telegram arrival alerts ----
// When the secretary marks a patient as arrived, the assigned doctor gets a
// Telegram message automatically (works with the phone locked and the app
// closed). Uses plain HTTPS calls to the Telegram Bot API — no extra
// package, so nothing new can break the server at startup.
//
// One-time setup: create a bot with @BotFather, set TELEGRAM_BOT_TOKEN on
// the server, then press "Connect Telegram bot" in Manage Doctors (owner).
// Each doctor then opens their own link once and taps Start.
const TELEGRAM_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN || '';
const PUBLIC_BASE_URL = (process.env.PUBLIC_BASE_URL || 'https://pt-script-backend.onrender.com').replace(/\/+$/, '');
let telegramBotUsername = '';

function telegramWebhookSecret() {
  return crypto.createHash('sha256').update('tg-webhook:' + TELEGRAM_BOT_TOKEN).digest('hex').slice(0, 32);
}
// A doctor's personal link code is derived from their email — nothing to store.
function telegramLinkCode(email) {
  return crypto.createHmac('sha256', TELEGRAM_BOT_TOKEN).update(String(email).trim().toLowerCase()).digest('hex').slice(0, 12);
}

async function telegramApi(method, body) {
  const r = await fetch(`https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/${method}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body || {}),
  });
  const j = await r.json().catch(() => ({}));
  if (!j.ok) throw new Error(j.description || `Telegram error ${r.status}`);
  return j.result;
}
function telegramSend(chatId, text) { return telegramApi('sendMessage', { chat_id: chatId, text }); }
async function getTelegramBotUsername() {
  if (telegramBotUsername) return telegramBotUsername;
  const me = await telegramApi('getMe');
  telegramBotUsername = me.username || '';
  return telegramBotUsername;
}

const ARRIVAL_AR_NAMES = { youssef: 'يوسف', yousef: 'يوسف', marwa: 'مروة', mostafa: 'مصطفى', mustafa: 'مصطفى', omnia: 'أمنية', omnya: 'أمنية', menna: 'منة', zeinab: 'زينب' };
const ARRIVAL_FEMALE = new Set(['marwa','omnia','omnya','menna','zeinab','vara','nada','mona','sara','salma','nour','hana','doaa','dina','rana','yara','mariam','maryam','eman','asmaa','esraa','aya','heba','nermin','noha','rania','shaimaa','shahd','rawan']);
const ARRIVAL_MALE = new Set(['mostafa','mustafa','youssef','yousef','joseph','ahmed','mohamed','mahmoud','omar','ali','ibrahim','hassan','khaled','karim','amr','tarek','sherif','hesham','osama']);

function buildArrivalMessage(appt, doctorName) {
  const rawName = String(doctorName || appt.doctor_name || '').trim();
  const tokens = rawName.split(/\s+/).filter(t => !/^(dr\.?|doctor|د\.?|دكتور|دكتورة)$/i.test(t));
  const first = (tokens[0] || rawName).trim();
  const key = first.toLowerCase();
  const title = ARRIVAL_FEMALE.has(key) ? 'دكتورة' : (ARRIVAL_MALE.has(key) ? 'دكتور' : 'د.');
  const nameAr = ARRIVAL_AR_NAMES[key] || first;
  const fmt = iso => new Date(iso).toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', timeZone: 'Africa/Cairo' });
  const typeAr = appt.visit_type === 'checkup' ? 'كشف' : (appt.visit_type === 'recovery' ? 'ريكفري' : 'جلسة');
  return `${title} ${nameAr} 👋\nالعيان ${appt.patient_name || ''} وصل العيادة دلوقتي (${fmt(appt.arrived_at)}) ✅\nالموعد: ${appt.start_time ? fmt(appt.start_time) : ''} · ${typeAr}`;
}

async function notifyDoctorArrivalTelegram(appt) {
  if (!TELEGRAM_BOT_TOKEN || !appt || !appt.arrived_at) return;
  const r = await fetch(`${SUPABASE_URL}/rest/v1/doctors?status=eq.approved&telegram_chat_id=not.is.null`, {
    headers: { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}` },
  });
  const docs = await r.json();
  if (!Array.isArray(docs) || docs.length === 0) return;
  const nm = String(appt.doctor_name || '').trim().toLowerCase();
  const byName = docs.find(d => String(d.name || '').trim().toLowerCase() === nm);
  const byColor = appt.doctor_color ? docs.filter(d => d.color === appt.doctor_color) : [];
  const doc = byName || (byColor.length === 1 ? byColor[0] : null);
  if (!doc) return;
  await telegramSend(doc.telegram_chat_id, buildArrivalMessage(appt, doc.name));
}

app.post('/api/telegram/setup', requireOwnerDoctor, async (req, res) => {
  if (!TELEGRAM_BOT_TOKEN) return res.status(400).json({ error: 'TELEGRAM_BOT_TOKEN is not set on the server yet.' });
  try {
    const username = await getTelegramBotUsername();
    await telegramApi('setWebhook', { url: `${PUBLIC_BASE_URL}/api/telegram/webhook/${telegramWebhookSecret()}`, allowed_updates: ['message'] });
    res.json({ ok: true, botUsername: username });
  } catch (err) {
    console.error('Telegram setup error:', err);
    res.status(500).json({ error: 'Telegram setup failed: ' + err.message });
  }
});

app.get('/api/telegram/link/:email', requireOwnerOrPermission('manage_team'), async (req, res) => {
  if (!TELEGRAM_BOT_TOKEN) return res.status(400).json({ error: 'TELEGRAM_BOT_TOKEN is not set on the server yet.' });
  try {
    const username = await getTelegramBotUsername();
    res.json({ botUsername: username, url: `https://t.me/${username}?start=${telegramLinkCode(req.params.email)}` });
  } catch (err) {
    res.status(500).json({ error: 'Could not reach Telegram: ' + err.message });
  }
});

app.post('/api/telegram/test/:email', requireOwnerOrPermission('manage_team'), async (req, res) => {
  if (!TELEGRAM_BOT_TOKEN) return res.status(400).json({ error: 'TELEGRAM_BOT_TOKEN is not set on the server yet.' });
  try {
    const r = await fetch(`${SUPABASE_URL}/rest/v1/doctors?email=eq.${encodeURIComponent(req.params.email)}&select=name,telegram_chat_id`, {
      headers: { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}` },
    });
    const rows = await r.json();
    const doc = Array.isArray(rows) && rows[0];
    if (!doc || !doc.telegram_chat_id) return res.status(400).json({ error: 'This doctor has not linked Telegram yet.' });
    await telegramSend(doc.telegram_chat_id, '✅ رسالة تجربة من عيادة ' + (await getClinicConfig()).name + ' — تنبيهات وصول العيانين شغّالة.');
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: 'Could not send the test message: ' + err.message });
  }
});

// Telegram calls this when someone messages the bot. The secret in the path
// is derived from the bot token, so only Telegram (which we gave the URL to)
// can reach it.
app.post('/api/telegram/webhook/:secret', async (req, res) => {
  if (!TELEGRAM_BOT_TOKEN || req.params.secret !== telegramWebhookSecret()) return res.sendStatus(404);
  res.sendStatus(200);
  try {
    const msg = req.body && req.body.message;
    if (!msg || !msg.chat || msg.chat.type !== 'private' || typeof msg.text !== 'string') return;
    const m = msg.text.trim().match(/^\/start(?:@\w+)?(?:\s+(\S+))?$/);
    if (!m) return;
    const code = m[1];
    if (!code) {
      await telegramSend(msg.chat.id, 'أهلاً 👋 اطلب من العيادة لينك الربط الخاص بيك، وادوس عليه عشان توصلك تنبيهات وصول العيانين.');
      return;
    }
    const headers = { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}` };
    const r = await fetch(`${SUPABASE_URL}/rest/v1/doctors?status=eq.approved&select=email,name`, { headers });
    const docs = await r.json();
    const doc = (Array.isArray(docs) ? docs : []).find(d => telegramLinkCode(d.email) === code);
    if (!doc) {
      await telegramSend(msg.chat.id, 'اللينك ده مش صح أو قديم ❌ اطلب من العيادة لينك جديد.');
      return;
    }
    await fetch(`${SUPABASE_URL}/rest/v1/doctors?email=eq.${encodeURIComponent(doc.email)}`, {
      method: 'PATCH',
      headers: { ...headers, 'Content-Type': 'application/json' },
      body: JSON.stringify({ telegram_chat_id: msg.chat.id }),
    });
    await telegramSend(msg.chat.id, `تم الربط ✅ يا ${doc.name || 'دكتور'}\nهتوصلك هنا رسالة أول ما عيان من عيانينك يوصل العيادة.`);
  } catch (err) {
    console.error('Telegram webhook error:', err.message);
  }
});

// ---- POST /api/doctors/:email/phone ----
// Saves a team member's WhatsApp number (used for the "patient arrived" message).
app.post('/api/doctors/:email/phone', requireOwnerOrPermission('manage_team'), async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  const raw = String((req.body && req.body.phone) || '').trim();
  if (raw && !/^[+\d][\d\s\-()]{6,20}$/.test(raw)) return res.status(400).json({ error: 'That does not look like a phone number.' });
  try {
    const patchRes = await fetch(`${SUPABASE_URL}/rest/v1/doctors?email=eq.${encodeURIComponent(req.params.email)}`, {
      method: 'PATCH',
      headers: {
        apikey: SUPABASE_SERVICE_KEY,
        Authorization: `Bearer ${SUPABASE_SERVICE_KEY}`,
        'Content-Type': 'application/json',
        Prefer: 'return=representation',
      },
      body: JSON.stringify({ phone: raw || null }),
    });
    const updated = await patchRes.json();
    if (!patchRes.ok) throw new Error(JSON.stringify(updated));
    if (!Array.isArray(updated) || updated.length === 0) return res.status(404).json({ error: 'Doctor not found.' });
    res.json({ ok: true, phone: updated[0].phone });
  } catch (err) {
    console.error('Set-phone error:', err);
    res.status(500).json({ error: 'Failed to save the number: ' + err.message });
  }
});

// ---- POST /api/doctors/:email/permissions ----
// Owner sets the granular permissions object for a team member. Body is
// the full set of booleans, e.g. { view_payments: true, send_whatsapp:
// false, ... } — always replaces the whole object (simpler than partial
// patches, and the frontend always sends the complete checklist anyway).
app.post('/api/doctors/:email/permissions', requireOwnerDoctor, async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is missing SUPABASE_URL or SUPABASE_SERVICE_KEY.' });
  const { permissions } = req.body || {};
  if (!permissions || typeof permissions !== 'object') return res.status(400).json({ error: 'Missing permissions object.' });
  try {
    const url = `${SUPABASE_URL}/rest/v1/doctors?email=eq.${encodeURIComponent(req.params.email)}`;
    const upstream = await fetch(url, {
      method: 'PATCH',
      headers: {
        apikey: SUPABASE_SERVICE_KEY,
        Authorization: `Bearer ${SUPABASE_SERVICE_KEY}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ permissions }),
    });
    res.status(upstream.status).json({ ok: upstream.ok });
  } catch (err) {
    console.error('Set-permissions error:', err);
    res.status(500).json({ error: 'Failed to update permissions: ' + err.message });
  }
});

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

app.post('/api/doctors/:email/approve', requireOwnerOrPermission('manage_team'), async (req, res) => {
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

app.post('/api/doctors/:email/reject', requireOwnerOrPermission('manage_team'), async (req, res) => {
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

// =====================================================================
// ---- Training applicants (public application form + owner-only list) ----
// Public:  GET /apply (the form page)   POST /api/apply (submit, no login)
// Owner:   GET /api/applicants, PATCH /api/applicants/:id, GET /api/applicants/:id/cv, DELETE /api/applicants/:id
// CV files live in a PRIVATE Supabase storage bucket "applicant-cvs".
// =====================================================================
const APPLICANT_BUCKET = 'applicant-cvs';
const CV_MAX_BYTES = 6 * 1024 * 1024;
const CV_TYPES = { 'application/pdf': 'pdf', 'application/msword': 'doc', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document': 'docx', 'image/jpeg': 'jpg', 'image/png': 'png' };
const applyHits = new Map(); // ip -> [timestamps]
function applyRateLimited(ip) {
  const now = Date.now();
  const arr = (applyHits.get(ip) || []).filter(t => now - t < 3600 * 1000);
  if (arr.length >= 8) { applyHits.set(ip, arr); return true; }
  arr.push(now); applyHits.set(ip, arr); return false;
}
const APPLY_AREAS = ['Rehab', 'Tagamoa', 'Shorouk', 'Madinaty', 'Other'];

const APPLY_PAGE = String.raw`<!doctype html><html lang="en" dir="ltr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex,nofollow"><title>Empower - Training Application</title>
<style>
*{box-sizing:border-box}body{margin:0;background:#f6f4ee;color:#12363a;font-family:-apple-system,'Segoe UI',Roboto,Arial,sans-serif;padding:16px}
.c{max-width:560px;margin:12px auto;background:#fff;border:1px solid #e4dfd0;border-radius:14px;padding:22px}
.brand{font-size:.78rem;letter-spacing:.14em;text-transform:uppercase;color:#b07a1f;font-weight:700;margin-bottom:8px}
h1{font-size:1.25rem;margin:0 0 6px}.sub{color:#5b6863;font-size:.9rem;margin-bottom:18px;line-height:1.6}
label{display:block;font-weight:600;font-size:.9rem;margin:16px 0 6px}label small{font-weight:400;color:#7a857f}
input[type=text],input[type=tel],select,textarea{width:100%;padding:11px 12px;border:1px solid #cfd6d2;border-radius:10px;font-size:1rem;background:#fff;color:#12363a;font-family:inherit}
textarea{min-height:80px;resize:vertical}.opts{display:flex;flex-wrap:wrap;gap:8px}
.opt{display:flex;align-items:center;gap:6px;border:1px solid #cfd6d2;border-radius:10px;padding:9px 12px;font-weight:500;cursor:pointer;margin:0}
.opt input{margin:0}button{margin-top:22px;width:100%;padding:14px;border:0;border-radius:10px;background:#12363a;color:#fff;font-size:1rem;font-weight:700;cursor:pointer}
button:disabled{opacity:.6}.err{color:#b3261e;font-size:.85rem;margin-top:10px;min-height:1.2em}.ok{text-align:center;padding:30px 0}
.warn{background:#fff6e0;border:1px solid #e8cf8a;border-radius:10px;padding:12px 14px;font-size:.92rem;line-height:1.7;margin-bottom:6px}
.logo{display:block;max-width:220px;width:60%;height:auto;margin:0 auto 14px}
.hp{position:absolute;left:-9999px;height:0;overflow:hidden}.hide{display:none}
</style></head><body><div class="c" id="card">
<img class="logo" src="/clinic-logo.png" alt="Empower">
<h1>Training Application</h1>
<div class="sub">Fill in your details and upload your CV. We review every application and contact shortlisted candidates on WhatsApp.</div>
<div class="warn"><strong>Important before you apply:</strong> the training is <strong>intensive: one full week, 6 days in a row with no rest day in between</strong>. Apply only if you can commit to all of those days.</div>
<form id="f" novalidate>
<div class="hp"><label>Website<input type="text" id="website" tabindex="-1" autocomplete="off"></label></div>
<label>Full name *</label><input type="text" id="fullName" maxlength="120" autocomplete="name">
<label>WhatsApp number *</label><input type="tel" id="phone" maxlength="20" inputmode="tel" autocomplete="tel">
<label>Graduation year *</label><select id="gradYear"><option value="">Select</option></select>
<label>University</label><input type="text" id="university" maxlength="120">
<label>Where do you live? *</label>
<div class="opts" id="areaOpts"></div>
<div id="areaOtherWrap" class="hide"><label>Write your area</label><input type="text" id="areaOther" maxlength="80"></div>
<label>Can you easily reach the training location? <small>(it is located between Rehab, Tagamoa, Shorouk and Madinaty)</small></label>
<select id="commute"><option value="">Select</option><option value="yes">Yes, easily</option><option value="hard">Possible, but difficult</option><option value="no">No</option></select>
<label>Do you currently work at another clinic or center? *</label>
<div class="opts"><label class="opt"><input type="radio" name="works" value="yes"> Yes</label><label class="opt"><input type="radio" name="works" value="no"> No</label></div>
<div id="worksWrap" class="hide"><label>Where, and what are your working days and hours?</label><textarea id="worksDetails" maxlength="500"></textarea></div>
<label>Years of experience in physical therapy</label>
<select id="experience"><option value="">Select</option><option>Less than 1 year</option><option>1 - 2 years</option><option>3 - 5 years</option><option>More than 5 years</option></select>
<label>Can you commit to the training <strong>6 days in a row for one week</strong>? *</label>
<div class="opts"><label class="opt"><input type="radio" name="commit6" value="yes"> Yes, I can commit to all the days</label><label class="opt"><input type="radio" name="commit6" value="no"> No, I cannot</label></div>
<label>Your preferred hours, and anything that might prevent you <small>(optional)</small></label><textarea id="availability" maxlength="500"></textarea>
<label>Upload your CV * <small>(PDF, Word or image - max 6 MB)</small></label>
<input type="file" id="cv" accept=".pdf,.doc,.docx,.jpg,.jpeg,.png,application/pdf,image/jpeg,image/png">
<div class="err" id="err"></div>
<button type="submit" id="btn">Submit application</button>
</form></div>
<script>
(function(){
  var $=function(i){return document.getElementById(i)};
  var AREAS=[['Rehab','Rehab'],['Tagamoa','Tagamoa'],['Shorouk','Shorouk'],['Madinaty','Madinaty'],['Other','Somewhere else']];
  var y=new Date().getFullYear();for(var i=y;i>=y-30;i--){var o=document.createElement('option');o.value=i;o.textContent=i;$('gradYear').appendChild(o);}
  AREAS.forEach(function(a){var l=document.createElement('label');l.className='opt';l.innerHTML='<input type="radio" name="area" value="'+a[0]+'"> '+a[1];$('areaOpts').appendChild(l);});
  function sel(n){var e=document.querySelector('input[name='+n+']:checked');return e?e.value:'';}
  document.addEventListener('change',function(){$('areaOtherWrap').className=sel('area')==='Other'?'':'hide';$('worksWrap').className=sel('works')==='yes'?'':'hide';});
  function fail(m){$('err').textContent=m;$('btn').disabled=false;$('btn').textContent='Submit application';}
  $('f').addEventListener('submit',function(ev){
    ev.preventDefault();$('err').textContent='';
    var name=$('fullName').value.trim(),phone=$('phone').value.replace(/[^0-9+]/g,''),grad=$('gradYear').value,area=sel('area'),works=sel('works'),commit=sel('commit6'),file=$('cv').files[0];
    if(name.length<3)return fail('Please enter your full name.');
    if(phone.replace(/\D/g,'').length<10)return fail('Please enter a valid WhatsApp number.');
    if(!grad)return fail('Please select your graduation year.');
    if(!area)return fail('Please select where you live.');
    if(area==='Other'&&!$('areaOther').value.trim())return fail('Please write your area.');
    if(!works)return fail('Please tell us if you work at another clinic.');
    if(!commit)return fail('Please answer the 6-day commitment question.');
    if(!file)return fail('Please upload your CV.');
    if(file.size>6*1024*1024)return fail('The file is larger than 6 MB.');
    $('btn').disabled=true;$('btn').textContent='Sending...';
    var rd=new FileReader();
    rd.onerror=function(){fail('Could not read the file. Try another file.')};
    rd.onload=function(){
      var b64=String(rd.result).split(',')[1]||'';
      var body={fullName:name,phone:phone,graduationYear:grad,university:$('university').value.trim(),area:area,areaOther:$('areaOther').value.trim(),commute:$('commute').value,worksElsewhere:works==='yes',commit6:commit==='yes',worksDetails:$('worksDetails').value.trim(),experience:$('experience').value,availability:$('availability').value.trim(),website:$('website').value,cvName:file.name,cvType:file.type,cvBase64:b64};
      fetch('/api/apply',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)})
      .then(function(r){return r.json().catch(function(){return{}}).then(function(j){return{ok:r.ok,j:j}})})
      .then(function(x){if(!x.ok)return fail(x.j.error||'Something went wrong. Please try again.');
        $('card').innerHTML='<div class="ok"><img class="logo" src="/clinic-logo.png" alt="Empower"><h1>We received your application. Thank you!</h1><div class="sub">We will review all applications and contact shortlisted candidates on WhatsApp.</div></div>';})
      .catch(function(){fail('No internet connection. Please try again.')});
    };
    rd.readAsDataURL(file);
  });
})();
</script></body></html>`;

app.get('/apply', async (req, res) => {
  logActivity(req, 'page', null, 'apply');
  res.set({ 'Content-Type': 'text/html; charset=utf-8', 'X-Robots-Tag': 'noindex, nofollow', 'Cache-Control': 'no-store' }).send(renderClinicPage(APPLY_PAGE, await getClinicConfig()));
});

app.post('/api/apply', async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Server is not ready. Please try later.' });
  const ip = String(req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();
  if (applyRateLimited(ip)) return res.status(429).json({ error: 'Too many attempts. Please try again later.' });
  const b = req.body || {};
  if (b.website) return res.json({ ok: true }); // honeypot: pretend success
  const clean = (v, n) => String(v == null ? '' : v).replace(/[\u0000-\u001f]/g, ' ').trim().slice(0, n);
  const fullName = clean(b.fullName, 120);
  const phone = clean(b.phone, 20).replace(/[^0-9+]/g, '');
  const gradYear = parseInt(b.graduationYear, 10);
  const area = APPLY_AREAS.includes(b.area) ? b.area : '';
  if (fullName.length < 3 || phone.replace(/\D/g, '').length < 10 || !gradYear || gradYear < 1990 || gradYear > new Date().getFullYear() + 1 || !area || typeof b.worksElsewhere !== 'boolean' || typeof b.commit6 !== 'boolean')
    return res.status(400).json({ error: 'Some details are missing or wrong. Please check the form.' });
  const ext = CV_TYPES[String(b.cvType || '').toLowerCase()];
  if (!ext || !b.cvBase64) return res.status(400).json({ error: 'File type not accepted. Upload a PDF, Word file or image.' });
  const bytes = Buffer.from(String(b.cvBase64), 'base64');
  if (bytes.length < 200 || bytes.length > CV_MAX_BYTES) return res.status(400).json({ error: 'File size is not valid (max 6 MB).' });
  try {
    const headers = { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}` };
    const cvPath = `${Date.now()}_${Math.random().toString(36).slice(2, 10)}/cv.${ext}`;
    const up = await fetch(`${SUPABASE_URL}/storage/v1/object/${APPLICANT_BUCKET}/${cvPath}`, { method: 'POST', headers: { ...headers, 'Content-Type': String(b.cvType), 'x-upsert': 'false' }, body: bytes });
    if (!up.ok) { console.error('Applicant CV upload failed:', up.status, await up.text().catch(() => '')); return res.status(500).json({ error: 'Could not save the file. Please try again.' }); }
    const row = {
      full_name: fullName, phone, graduation_year: gradYear, university: clean(b.university, 120) || null,
      area, area_other: clean(b.areaOther, 80) || null, commute: ['yes', 'hard', 'no'].includes(b.commute) ? b.commute : null,
      works_elsewhere: b.worksElsewhere, can_commit_6_days: b.commit6, works_details: clean(b.worksDetails, 500) || null, experience: clean(b.experience, 40) || null,
      availability: clean(b.availability, 500) || null,
      cv_path: cvPath, cv_name: clean(b.cvName, 150) || null,
    };
    const ins = await fetch(`${SUPABASE_URL}/rest/v1/training_applicants`, { method: 'POST', headers: { ...headers, 'Content-Type': 'application/json', Prefer: 'return=minimal' }, body: JSON.stringify(row) });
    if (!ins.ok) { console.error('Applicant insert failed:', ins.status, await ins.text().catch(() => '')); return res.status(500).json({ error: 'Could not save your application. Please try again.' }); }
    res.json({ ok: true });
  } catch (err) {
    console.error('Apply error:', err);
    res.status(500).json({ error: 'Something went wrong. Please try again.' });
  }
});

app.get('/api/applicants', requireOwnerOrPermission('view_applicants'), async (req, res) => {
  try {
    const r = await fetch(`${SUPABASE_URL}/rest/v1/training_applicants?order=created_at.desc&limit=2000`, { headers: { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}` } });
    const data = await r.json();
    if (!r.ok) return res.status(500).json({ error: (data && data.message) || 'Failed to load applicants.' });
    res.json(data);
  } catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});

app.patch('/api/applicants/:id', requireOwnerOrPermission('view_applicants'), async (req, res) => {
  const b = req.body || {};
  const patch = {};
  if (b.status !== undefined) { if (!['new', 'shortlisted', 'interview', 'accepted', 'rejected'].includes(b.status)) return res.status(400).json({ error: 'Bad status.' }); patch.status = b.status; }
  if (b.rating !== undefined) { const n = b.rating === null ? null : parseInt(b.rating, 10); if (n !== null && !(n >= 1 && n <= 5)) return res.status(400).json({ error: 'Bad rating.' }); patch.rating = n; }
  if (b.owner_notes !== undefined) patch.owner_notes = String(b.owner_notes || '').slice(0, 2000);
  if (b.train_slot !== undefined) {
    if (b.train_slot === null || b.train_slot === '') { patch.train_start = null; patch.train_end = null; patch.train_shift = null; patch.train_days = null; patch.confirm_sent_at = null; patch.remind_for = null; }
    else {
      const m = /^(\d{4}-\d{2}-\d{2})\|(\d{4}-\d{2}-\d{2})\|(morning|evening)$/.exec(String(b.train_slot));
      if (!m) return res.status(400).json({ error: 'Bad slot.' });
      patch.train_start = m[1]; patch.train_end = m[2]; patch.train_shift = m[3];
    }
  }
  if (b.train_days !== undefined) {
    if (b.train_days === null || b.train_days === '') patch.train_days = null;
    else if (/^[0-6](,[0-6]){0,6}$/.test(String(b.train_days))) patch.train_days = String(b.train_days);
    else return res.status(400).json({ error: 'Bad days.' });
  }
  if (b.confirm_sent === true) patch.confirm_sent_at = new Date().toISOString();
  if (b.remind_for !== undefined) { if (b.remind_for !== null && !/^\d{4}-\d{2}-\d{2}$/.test(String(b.remind_for))) return res.status(400).json({ error: 'Bad date.' }); patch.remind_for = b.remind_for; }
  if (!Object.keys(patch).length) return res.status(400).json({ error: 'Nothing to update.' });
  try {
    const r = await fetch(`${SUPABASE_URL}/rest/v1/training_applicants?id=eq.${encodeURIComponent(req.params.id)}`, { method: 'PATCH', headers: { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}`, 'Content-Type': 'application/json', Prefer: 'return=minimal' }, body: JSON.stringify(patch) });
    if (!r.ok) return res.status(500).json({ error: 'Update failed.' });
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});

app.get('/api/applicants/:id/cv', requireOwnerOrPermission('view_applicants'), async (req, res) => {
  try {
    const headers = { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}` };
    const r = await fetch(`${SUPABASE_URL}/rest/v1/training_applicants?id=eq.${encodeURIComponent(req.params.id)}&select=cv_path&limit=1`, { headers });
    const rows = await r.json();
    const p = rows && rows[0] && rows[0].cv_path;
    if (!p) return res.status(404).json({ error: 'No CV.' });
    const s = await fetch(`${SUPABASE_URL}/storage/v1/object/sign/${APPLICANT_BUCKET}/${p}`, { method: 'POST', headers: { ...headers, 'Content-Type': 'application/json' }, body: JSON.stringify({ expiresIn: 900 }) });
    const j = await s.json();
    if (!s.ok || !j.signedURL) return res.status(500).json({ error: 'Could not open the CV.' });
    res.json({ url: `${SUPABASE_URL}/storage/v1${j.signedURL}` });
  } catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});

app.delete('/api/applicants/:id', requireOwnerDoctor, async (req, res) => {
  try {
    const headers = { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}` };
    const r = await fetch(`${SUPABASE_URL}/rest/v1/training_applicants?id=eq.${encodeURIComponent(req.params.id)}&select=cv_path&limit=1`, { headers });
    const rows = await r.json();
    const p = rows && rows[0] && rows[0].cv_path;
    if (p) await fetch(`${SUPABASE_URL}/storage/v1/object/${APPLICANT_BUCKET}`, { method: 'DELETE', headers: { ...headers, 'Content-Type': 'application/json' }, body: JSON.stringify({ prefixes: [p] }) }).catch(() => {});
    const d = await fetch(`${SUPABASE_URL}/rest/v1/training_applicants?id=eq.${encodeURIComponent(req.params.id)}`, { method: 'DELETE', headers });
    if (!d.ok) return res.status(500).json({ error: 'Delete failed.' });
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});


// =====================================================================
// ---- Friday event duty: who covers the Friday event, + Telegram reminder 3 days before ----
// Table: friday_duty (duty_date date PK, doctor_email, doctor_name, reminder_sent_at, reminder_error)
// The reminder goes out once, 3 days before (Tuesday for a Friday), from 9 AM Cairo time.
// If the server was asleep then, it sends as soon as it wakes (any time up to the duty day).
// =====================================================================
function cairoTodayYmd() { return new Date().toLocaleDateString('en-CA', { timeZone: 'Africa/Cairo' }); }
function cairoHourNow() { return parseInt(new Date().toLocaleString('en-US', { timeZone: 'Africa/Cairo', hour: 'numeric', hour12: false }), 10) % 24; }
function ymdDiffDays(aYmd, bYmd) { return Math.round((Date.parse(bYmd + 'T00:00:00Z') - Date.parse(aYmd + 'T00:00:00Z')) / 86400000); }
function isFridayYmd(ymd) { return /^\d{4}-\d{2}-\d{2}$/.test(ymd) && new Date(ymd + 'T00:00:00Z').getUTCDay() === 5; }
const DUTY_HEADERS = () => ({ apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}` });

function buildDutyReminderMessage(doctorName, dutyYmd, daysLeft) {
  const rawName = String(doctorName || '').trim();
  const tokens = rawName.split(/\s+/).filter(t => !/^(dr\.?|doctor|د\.?|دكتور|دكتورة)$/i.test(t));
  const first = (tokens[0] || rawName).trim();
  const key = first.toLowerCase();
  const title = ARRIVAL_FEMALE.has(key) ? 'دكتورة' : (ARRIVAL_MALE.has(key) ? 'دكتور' : 'د.');
  const nameAr = ARRIVAL_AR_NAMES[key] || first;
  const dateAr = new Date(dutyYmd + 'T12:00:00Z').toLocaleDateString('ar-EG', { weekday: 'long', day: 'numeric', month: 'long', timeZone: 'UTC' });
  const when = daysLeft <= 0 ? 'النهاردة' : (daysLeft === 1 ? 'بكرة' : `كمان ${daysLeft} أيام`);
  return `${title} ${nameAr} 👋\nتذكير: ${when} (${dateAr}) دورك تغطي الإيفنت بتاع الجمعة ✅\nلو في أي ظرف يمنعك، قول لدكتور مصطفى من دلوقتي عشان نظبط البديل.`;
}

async function sendDutyReminder(duty) {
  if (!TELEGRAM_BOT_TOKEN) throw new Error('Telegram bot is not set up on the server.');
  const r = await fetch(`${SUPABASE_URL}/rest/v1/doctors?email=eq.${encodeURIComponent(duty.doctor_email)}&select=name,telegram_chat_id&limit=1`, { headers: DUTY_HEADERS() });
  const rows = await r.json();
  const doc = Array.isArray(rows) && rows[0];
  if (!doc || !doc.telegram_chat_id) throw new Error('This doctor has not linked Telegram yet.');
  const daysLeft = ymdDiffDays(cairoTodayYmd(), String(duty.duty_date).slice(0, 10));
  await telegramSend(doc.telegram_chat_id, buildDutyReminderMessage(doc.name || duty.doctor_name, String(duty.duty_date).slice(0, 10), daysLeft));
}
async function markDuty(date, patch) {
  await fetch(`${SUPABASE_URL}/rest/v1/friday_duty?duty_date=eq.${date}`, { method: 'PATCH', headers: { ...DUTY_HEADERS(), 'Content-Type': 'application/json', Prefer: 'return=minimal' }, body: JSON.stringify(patch) });
}

let dutyRunnerBusy = false;
async function runFridayDutyReminders() {
  if (dutyRunnerBusy || !SUPABASE_URL || !SUPABASE_SERVICE_KEY || !TELEGRAM_BOT_TOKEN) return;
  if (cairoHourNow() < 9) return;
  dutyRunnerBusy = true;
  try {
    const today = cairoTodayYmd();
    const r = await fetch(`${SUPABASE_URL}/rest/v1/friday_duty?duty_date=gte.${today}&duty_date=lte.${new Date(Date.parse(today + 'T00:00:00Z') + 3 * 86400000).toISOString().slice(0, 10)}&order=duty_date.asc`, { headers: DUTY_HEADERS() });
    const rows = await r.json();
    if (!r.ok || !Array.isArray(rows)) return;
    for (const duty of rows) {
      const date = String(duty.duty_date).slice(0, 10);
      let tgOk = !!duty.reminder_sent_at;
      if (!duty.reminder_sent_at && !(duty.reminder_error && duty.reminder_error.startsWith('tried:' + today))) {
        try {
          await sendDutyReminder(duty);
          await markDuty(date, { reminder_sent_at: new Date().toISOString(), reminder_error: null });
          tgOk = true;
          console.log(`[friday-duty] reminder sent for ${date} to ${duty.doctor_email}`);
        } catch (err) {
          await markDuty(date, { reminder_error: `tried:${today} ${String(err.message || err).slice(0, 200)}` });
          console.error('[friday-duty] reminder failed:', err.message);
        }
      }
      // Nudge the owner(s) once on Telegram to also send the WhatsApp message by hand.
      if (!duty.owner_nudged_at && !duty.whatsapp_sent_at) {
        try {
          const orows = await (await fetch(`${SUPABASE_URL}/rest/v1/doctors?role=eq.owner&status=eq.approved&telegram_chat_id=not.is.null&select=telegram_chat_id`, { headers: DUTY_HEADERS() })).json();
          const dateAr = new Date(date + 'T12:00:00Z').toLocaleDateString('ar-EG', { weekday: 'long', day: 'numeric', month: 'long', timeZone: 'UTC' });
          let sent = 0;
          for (const o of (Array.isArray(orows) ? orows : [])) {
            await telegramSend(o.telegram_chat_id, `📌 فكّر ${duty.doctor_name || 'الدكتور'} على واتساب كمان: دوره في إيفنت ${dateAr}.\n${tgOk ? 'التليجرام اتبعت له ✅' : 'التليجرام ماوصلوش ⚠ (يمكن مش رابط)'}\nافتح مساعد ← Dashboard ← Team ← Friday event duty ← "Send on WhatsApp".`);
            sent++;
          }
          if (sent) await markDuty(date, { owner_nudged_at: new Date().toISOString() });
        } catch (err) { console.error('[friday-duty] owner nudge failed:', err.message); }
      }
    }
  } catch (err) {
    console.error('[friday-duty] runner error:', err.message);
  } finally {
    dutyRunnerBusy = false;
  }
}
setInterval(runFridayDutyReminders, 10 * 60 * 1000);
setTimeout(runFridayDutyReminders, 45 * 1000);

app.get('/api/friday-duty', requireOwnerDoctor, async (req, res) => {
  try {
    const since = new Date(Date.now() - 7 * 86400000).toISOString().slice(0, 10);
    const [dr, pr] = await Promise.all([
      fetch(`${SUPABASE_URL}/rest/v1/friday_duty?duty_date=gte.${since}&order=duty_date.asc&limit=200`, { headers: DUTY_HEADERS() }),
      fetch(`${SUPABASE_URL}/rest/v1/doctors?status=eq.approved&role=in.(doctor,owner)&select=email,name,phone,telegram_chat_id&order=name.asc`, { headers: DUTY_HEADERS() }),
    ]);
    const duties = await dr.json();
    const docs = await pr.json();
    if (!dr.ok) return res.status(500).json({ error: 'Could not load duties. Did you run the friday_duty SQL?' });
    res.json({
      telegram_ready: !!TELEGRAM_BOT_TOKEN,
      duties: (Array.isArray(duties) ? duties : []).map(d => {
        const date = String(d.duty_date).slice(0, 10);
        return { ...d, whatsapp_text: buildDutyReminderMessage(d.doctor_name, date, Math.max(0, ymdDiffDays(cairoTodayYmd(), date))) };
      }),
      doctors: (Array.isArray(docs) ? docs : []).map(d => ({ email: d.email, name: d.name, phone: d.phone || null, telegram_linked: !!d.telegram_chat_id })),
    });
  } catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});

app.put('/api/friday-duty/:date', requireOwnerDoctor, async (req, res) => {
  const date = String(req.params.date || '');
  if (!isFridayYmd(date)) return res.status(400).json({ error: 'That date is not a Friday.' });
  const email = String((req.body && req.body.doctorEmail) || '').trim().toLowerCase();
  if (!email) return res.status(400).json({ error: 'Pick a doctor.' });
  try {
    const pr = await fetch(`${SUPABASE_URL}/rest/v1/doctors?email=eq.${encodeURIComponent(email)}&status=eq.approved&select=email,name&limit=1`, { headers: DUTY_HEADERS() });
    const rows = await pr.json();
    const doc = Array.isArray(rows) && rows[0];
    if (!doc) return res.status(400).json({ error: 'Doctor not found.' });
    const up = await fetch(`${SUPABASE_URL}/rest/v1/friday_duty?on_conflict=duty_date`, {
      method: 'POST',
      headers: { ...DUTY_HEADERS(), 'Content-Type': 'application/json', Prefer: 'resolution=merge-duplicates,return=minimal' },
      body: JSON.stringify({ duty_date: date, doctor_email: doc.email, doctor_name: doc.name, reminder_sent_at: null, reminder_error: null, owner_nudged_at: null, whatsapp_sent_at: null }),
    });
    if (!up.ok) { console.error('friday_duty upsert failed', up.status, await up.text().catch(() => '')); return res.status(500).json({ error: 'Could not save. Did you run the friday_duty SQL?' }); }
    res.json({ ok: true });
    setTimeout(runFridayDutyReminders, 1500); // if it is already inside the 3-day window, remind right away
  } catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});

app.delete('/api/friday-duty/:date', requireOwnerDoctor, async (req, res) => {
  const date = String(req.params.date || '');
  if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) return res.status(400).json({ error: 'Bad date.' });
  try {
    const d = await fetch(`${SUPABASE_URL}/rest/v1/friday_duty?duty_date=eq.${date}`, { method: 'DELETE', headers: DUTY_HEADERS() });
    if (!d.ok) return res.status(500).json({ error: 'Delete failed.' });
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});

app.post('/api/friday-duty/:date/whatsapp-sent', requireOwnerDoctor, async (req, res) => {
  const date = String(req.params.date || '');
  if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) return res.status(400).json({ error: 'Bad date.' });
  try { await markDuty(date, { whatsapp_sent_at: new Date().toISOString() }); res.json({ ok: true }); }
  catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});

app.post('/api/friday-duty/:date/send-reminder', requireOwnerDoctor, async (req, res) => {
  const date = String(req.params.date || '');
  if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) return res.status(400).json({ error: 'Bad date.' });
  try {
    const r = await fetch(`${SUPABASE_URL}/rest/v1/friday_duty?duty_date=eq.${date}&limit=1`, { headers: DUTY_HEADERS() });
    const rows = await r.json();
    const duty = Array.isArray(rows) && rows[0];
    if (!duty) return res.status(404).json({ error: 'Nobody is assigned that Friday.' });
    await sendDutyReminder(duty);
    await markDuty(date, { reminder_sent_at: new Date().toISOString(), reminder_error: null });
    res.json({ ok: true });
  } catch (err) { res.status(400).json({ error: String(err.message || err) }); }
});


// =====================================================================
// ---- Online booking (public page /book) ----
// Patients pick a doctor + time from the doctor's open hours, pay half the
// fee as a non-refundable InstaPay deposit (upload the screenshot) and the
// visit lands in the calendar straight away. Patients who already have an
// active package skip the deposit. Tables: booking_settings, booking_deposits.
// =====================================================================
const BOOKING_BUCKET = 'booking-deposits';
const SHOT_TYPES = { 'image/jpeg': 'jpg', 'image/png': 'png', 'image/webp': 'webp' };
const SHOT_MAX_BYTES = 4 * 1024 * 1024;
const BOOKING_DEFAULTS = {
  enabled: false, instapay: '', note: '', slot_minutes: 30, min_lead_hours: 2, max_days_ahead: 30,
  types: [
    { key: 'checkup', label: 'Check-up', label_ar: 'Check-up — كشف (جلسة تقييمية)', price: 0, visit_type: 'checkup' },
    { key: 'session1', label: 'Session - 1 body part', label_ar: 'جلسة — على مكان واحد (عضو واحد)', price: 500, visit_type: 'session' },
    { key: 'session2', label: 'Session - 2 body parts', label_ar: 'جلسة — على أكتر من مكان (عضوين)', price: 750, visit_type: 'session' },
    { key: 'recovery_half', label: 'Recovery - Half Body', label_ar: 'Recovery - Half Body', price: 900, visit_type: 'recovery' },
    { key: 'recovery_full', label: 'Recovery - Full Body', label_ar: 'Recovery - Full Body', price: 1500, visit_type: 'recovery' },
  ],
  hours: {},
  docs: {},
};
const bookHits = new Map();
function bookRateLimited(ip, kind, max, windowMs) {
  const k = kind + '|' + ip, now = Date.now();
  const arr = (bookHits.get(k) || []).filter(t => now - t < windowMs);
  if (arr.length >= max) { bookHits.set(k, arr); return true; }
  arr.push(now); bookHits.set(k, arr); return false;
}
const bookHeaders = () => ({ apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}` });
// ---- Clinic settings (name, address, links, message texts, payroll rules) ----
// Stored in booking_settings row id=2 so no new table is needed. Every clinic
// that installs the app fills these in from Settings > Clinic.
const CLINIC_DEFAULTS = { name: 'Your Clinic', name_ar: '', address: '', address_ar: '', map_url: '', phone: '', instapay_url: '', instapay_handle: '', review_url: '', intake_url: '', tagline: '', logo: '', stamp: '', fixed_costs: [], hr_staff: [], hr_start: '', links: [], templates: {}, payroll_rules: [] };
let clinicCache = null, clinicCacheAt = 0;
async function getClinicConfig(force) {
  if (!force && clinicCache && Date.now() - clinicCacheAt < 60000) return clinicCache;
  let data = {};
  try {
    const r = await fetch(`${SUPABASE_URL}/rest/v1/booking_settings?id=eq.2&select=data&limit=1`, { headers: { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}` } });
    const rows = await r.json();
    if (Array.isArray(rows) && rows[0] && rows[0].data) data = rows[0].data;
  } catch (e) { if (clinicCache) return clinicCache; }
  const c = { ...CLINIC_DEFAULTS, ...data };
  c.templates = data.templates && typeof data.templates === 'object' ? data.templates : {};
  c.payroll_rules = Array.isArray(data.payroll_rules) ? data.payroll_rules : [];
  c.links = Array.isArray(data.links) ? data.links : [];
  c.fixed_costs = cleanFixedCosts(data.fixed_costs);
  c.hr_staff = cleanHrStaff(data.hr_staff);
  c.hr_start = /^\d{4}-\d{2}-\d{2}$/.test(String(data.hr_start || '')) ? data.hr_start : '';
  if (!String(c.name || '').trim()) c.name = CLINIC_DEFAULTS.name;
  clinicCache = c; clinicCacheAt = Date.now();
  PAYROLL_RULES = c.payroll_rules;
  return c;
}
const clinicEsc = (v) => String(v == null ? '' : v).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
const clinicJs = (v) => JSON.stringify(String(v == null ? '' : v)).slice(1, -1).replace(/</g, '\\u003c').replace(/'/g, "\\'");
function renderClinicPage(html, c) {
  return html.replace(/__ADDR_EN__/g, clinicJs(clinicEsc(c.address))).replace(/__ADDR_AR__/g, clinicJs(clinicEsc(c.address_ar || c.address)))
    .replace(/__MAP_URL__/g, clinicEsc(c.map_url || '#')).replace(/Empower/g, clinicEsc(c.name));
}
const safeLinkUrl = (u) => { const t = String(u == null ? '' : u).trim().slice(0, 300); return /^(https?:\/\/|tel:|mailto:)/i.test(t) ? t : ''; };
const cleanLinks = (arr) => (Array.isArray(arr) ? arr : []).slice(0, 12).map((l) => ({ label: clinicText(l && l.label, 60).trim(), url: safeLinkUrl(l && l.url) })).filter((l) => l.label && l.url);
const clinicText = (v, n) => String(v == null ? '' : v).replace(/[\u0000-\u0009\u000b-\u001f]/g, ' ').slice(0, n);
app.get('/api/clinic-config', requireApprovedAny, async (req, res) => {
  try {
    const c = await getClinicConfig(true);
    const out = { ...c };
    if (!req.doctor || (req.doctor.role !== 'owner' && !(req.doctor.permissions && req.doctor.permissions.view_payroll))) { delete out.payroll_rules; }
    res.json(out);
  } catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});
const cleanFixedCosts = (arr) => (Array.isArray(arr) ? arr : []).slice(0, 30).map((f) => {
  const name = clinicText(f && f.name, 60).trim(); const amount = parseFloat(f && f.amount);
  if (!name || !Number.isFinite(amount) || amount <= 0) return null;
  return { name, amount: Math.round(amount * 100) / 100, method: f.method === 'instapay' ? 'instapay' : 'cash' };
}).filter(Boolean);
const cleanHrStaff = (arr) => (Array.isArray(arr) ? arr : []).slice(0, 40).map((x) => {
  const label = clinicText(x && x.label, 60).trim(), keyword = clinicText(x && x.keyword, 40).trim().toLowerCase();
  if (!label || !keyword) return null;
  const days = [...new Set((Array.isArray(x.days) ? x.days : []).map((d) => parseInt(d, 10)).filter((d) => d >= 0 && d <= 6))].sort();
  const allowance = Math.max(0, Math.min(366, parseFloat(x.allowance) || 0));
  return { label, keyword, days, allowance };
}).filter(Boolean);
const cleanDataImg = (v) => { const t = String(v || ''); return t.length <= 400000 && /^data:image\/(png|jpeg|webp);base64,[A-Za-z0-9+\/=]+$/.test(t) ? t : ''; };
app.put('/api/clinic-config', requireOwnerDoctor, async (req, res) => {
  const b = req.body || {};
  const num = (v, lo, hi) => { const n = parseFloat(v); return Number.isFinite(n) ? Math.min(hi, Math.max(lo, n)) : null; };
  const rules = (Array.isArray(b.payroll_rules) ? b.payroll_rules : []).slice(0, 40).map((r) => {
    const kind = ['partner', 'revenue_share', 'fixed_plus_rate'].includes(r.kind) ? r.kind : null;
    const keyword = clinicText(r.keyword, 40).trim().toLowerCase(); const label = clinicText(r.label, 60).trim();
    if (!kind || !keyword || !label) return null;
    const out = { keyword, kind, label };
    if (kind === 'fixed_plus_rate') { out.fixed = num(r.fixed, 0, 10000000) || 0; out.rate = num(r.rate, 0, 1000000) || 0; }
    else { const sh = num(r.share, 0, 1); if (sh != null) out.share = sh; }
    return out;
  }).filter(Boolean);
  const templates = {};
  for (const k of ['confirmation', 'elevator', 'package_policy', 'recovery_session_policy', 'instapay_payment', 'intake_form', 'package_last_session']) {
    const t = clinicText(b.templates && b.templates[k], 4000).trim();
    if (t) templates[k] = t;
  }
  const data = {
    name: clinicText(b.name, 80).trim() || CLINIC_DEFAULTS.name, name_ar: clinicText(b.name_ar, 80).trim(),
    address: clinicText(b.address, 200).trim(), address_ar: clinicText(b.address_ar, 200).trim(), map_url: clinicText(b.map_url, 300).trim(),
    phone: clinicText(b.phone, 30).trim(), instapay_url: clinicText(b.instapay_url, 300).trim(), instapay_handle: clinicText(b.instapay_handle, 100).trim(),
    review_url: clinicText(b.review_url, 300).trim(), intake_url: clinicText(b.intake_url, 300).trim(), tagline: clinicText(b.tagline, 120).trim(), logo: cleanDataImg(b.logo), stamp: cleanDataImg(b.stamp), fixed_costs: cleanFixedCosts(b.fixed_costs), hr_staff: cleanHrStaff(b.hr_staff), hr_start: /^\d{4}-\d{2}-\d{2}$/.test(String(b.hr_start || '')) ? b.hr_start : '', links: cleanLinks(b.links), templates, payroll_rules: rules,
  };
  try {
    const r = await fetch(`${SUPABASE_URL}/rest/v1/booking_settings?on_conflict=id`, { method: 'POST', headers: { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}`, 'Content-Type': 'application/json', Prefer: 'resolution=merge-duplicates,return=minimal' }, body: JSON.stringify({ id: 2, data, updated_at: new Date().toISOString() }) });
    if (!r.ok) { console.error('clinic config save failed', r.status, await r.text().catch(() => '')); return res.status(500).json({ error: 'Could not save.' }); }
    await getClinicConfig(true);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});

const bookClean = (v, n) => String(v == null ? '' : v).replace(/[\u0000-\u001f]/g, ' ').trim().slice(0, n);

async function getBookingSettings() {
  let data = {};
  try {
    const r = await fetch(`${SUPABASE_URL}/rest/v1/booking_settings?id=eq.1&select=data&limit=1`, { headers: bookHeaders() });
    const rows = await r.json();
    if (Array.isArray(rows) && rows[0] && rows[0].data) data = rows[0].data;
  } catch (e) { /* defaults */ }
  return {
    ...BOOKING_DEFAULTS, ...data,
    types: Array.isArray(data.types) && data.types.length ? data.types : BOOKING_DEFAULTS.types,
    hours: data.hours && typeof data.hours === 'object' ? data.hours : {},
    docs: data.docs && typeof data.docs === 'object' ? data.docs : {},
  };
}

function cairoWall(ms) {
  const p = new Intl.DateTimeFormat('en-CA', { timeZone: 'Africa/Cairo', hourCycle: 'h23', year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' })
    .formatToParts(new Date(ms)).reduce((a, x) => (a[x.type] = x.value, a), {});
  return Date.UTC(+p.year, +p.month - 1, +p.day, +p.hour, +p.minute);
}
function cairoToDate(ymd, hm) {
  const [y, m, d] = ymd.split('-').map(Number), [h, mi] = hm.split(':').map(Number);
  const target = Date.UTC(y, m - 1, d, h, mi);
  let ms = target;
  for (let i = 0; i < 3; i++) ms += target - cairoWall(ms);
  return new Date(ms);
}
const hmToMin = hm => { const [h, m] = hm.split(':').map(Number); return h * 60 + m; };
const minToHm = n => String(Math.floor(n / 60)).padStart(2, '0') + ':' + String(n % 60).padStart(2, '0');
const bookDocToken = email => crypto.createHmac('sha256', SUPABASE_SERVICE_KEY || 'x').update(String(email).toLowerCase()).digest('hex').slice(0, 12);

async function bookableDoctors(settings) {
  const r = await fetch(`${SUPABASE_URL}/rest/v1/doctors?status=eq.approved&role=in.(doctor,owner)&select=email,name,color,telegram_chat_id&order=name.asc`, { headers: bookHeaders() });
  const rows = await r.json();
  return (Array.isArray(rows) ? rows : []).filter(d => {
    const h = settings.hours[d.email];
    return h && Object.values(h).some(v => Array.isArray(v) && v.length);
  });
}

async function computeBookingSlots(settings, doc, ymd) {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(ymd)) return [];
  const diff = ymdDiffDays(cairoTodayYmd(), ymd);
  if (diff < 0 || diff > settings.max_days_ahead) return [];
  const wd = String(new Date(ymd + 'T12:00:00Z').getUTCDay());
  const ranges = ((settings.hours[doc.email] || {})[wd]) || [];
  if (!ranges.length) return [];
  const step = settings.slot_minutes;
  const dayStart = cairoToDate(ymd, '00:00');
  const dayEnd = new Date(dayStart.getTime() + 25 * 3600000);
  const r = await fetch(`${SUPABASE_URL}/rest/v1/appointments?doctor_name=eq.${encodeURIComponent(doc.name)}&start_time=gte.${encodeURIComponent(dayStart.toISOString())}&start_time=lt.${encodeURIComponent(dayEnd.toISOString())}&deleted_at=is.null&select=start_time,end_time,status`, { headers: bookHeaders() });
  const appts = await r.json();
  const busy = (Array.isArray(appts) ? appts : []).filter(a => a.status !== 'cancelled').map(a => [new Date(a.start_time).getTime(), new Date(a.end_time || new Date(a.start_time).getTime() + 30 * 60000).getTime()]);
  const earliest = Date.now() + settings.min_lead_hours * 3600000;
  const out = [];
  for (const [from, to] of ranges) {
    for (let t = hmToMin(from); t + step <= hmToMin(to); t += step) {
      const hm = minToHm(t);
      const s = cairoToDate(ymd, hm).getTime(), e = s + step * 60000;
      if (s < earliest) continue;
      if (busy.some(([bs, be]) => s < be && e > bs)) continue;
      if (!out.includes(hm)) out.push(hm);
    }
  }
  return out.sort();
}

const bookRule = (settings, email) => (settings.docs && settings.docs[email]) || {};
const bookBlockedByGender = (settings, email, gender) => bookRule(settings, email).gender === 'female' && gender === 'male';
const bookPhoneKey = p => String(p || '').replace(/\D/g, '').slice(-10);
async function hasActivePackageByPhone(phone) {
  const key = bookPhoneKey(phone);
  if (key.length < 10) return false;
  const pr = await fetch(`${SUPABASE_URL}/rest/v1/packages?select=patient_name,total_sessions,used_sessions&order=created_at.desc&limit=2000`, { headers: bookHeaders() });
  const pk = await pr.json();
  const names = new Set((Array.isArray(pk) ? pk : []).filter(p => p.used_sessions < p.total_sessions).map(p => String(p.patient_name || '').trim().toLowerCase()));
  if (!names.size) return false;
  const ar = await fetch(`${SUPABASE_URL}/rest/v1/appointments?select=patient_name,patient_phone&patient_phone=not.is.null&deleted_at=is.null&order=start_time.desc&limit=5000`, { headers: bookHeaders() });
  const rows = await ar.json();
  return (Array.isArray(rows) ? rows : []).some(a => names.has(String(a.patient_name || '').trim().toLowerCase()) && bookPhoneKey(a.patient_phone) === key);
}

app.get('/api/book/config', async (req, res) => {
  try {
    const s = await getBookingSettings();
    const docs = s.enabled ? await bookableDoctors(s) : [];
    const pg = ['male', 'female'].includes(String(req.query.gender || '')) ? String(req.query.gender) : '';
    const gotInfo = !!pg && bookClean(req.query.name, 120).length >= 3 && String(req.query.phone || '').replace(/\D/g, '').length >= 10;
    if (!gotInfo) return res.set('Cache-Control', 'no-store').json({ enabled: !!s.enabled && docs.length > 0, locked: true });
    if (s.enabled && docs.length) {
      const ip = String(req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();
      if (!bookRateLimited(ip, 'lead', 15, 3600000)) {
        fetch(`${SUPABASE_URL}/rest/v1/booking_leads?on_conflict=phone_key`, {
          method: 'POST', headers: { ...bookHeaders(), 'Content-Type': 'application/json', Prefer: 'resolution=merge-duplicates,return=minimal' },
          body: JSON.stringify({ phone_key: bookPhoneKey(req.query.phone), name: bookClean(req.query.name, 120), phone: bookClean(req.query.phone, 20).replace(/[^0-9+]/g, ''), last_seen: new Date().toISOString() }),
        }).catch(() => {});
      }
    }
    res.set('Cache-Control', 'no-store').json({
      enabled: !!s.enabled && docs.length > 0, instapay: s.instapay, note: s.note, max_days_ahead: s.max_days_ahead,
      types: s.types.filter(t => t.price > 0).map(t => ({ key: t.key, label: t.label, label_ar: t.label_ar || '', visit_type: t.visit_type || 'session', price: t.price, deposit: Math.round(t.price / 2) })),
      doctors: docs.filter(d => !bookBlockedByGender(s, d.email, pg)).map(d => ({ id: bookDocToken(d.email), name: d.name, checkups: bookRule(s, d.email).checkups !== false })),
    });
  } catch (err) { res.status(500).json({ error: 'Booking is not available right now.' }); }
});

app.get('/api/book/slots', async (req, res) => {
  const ip = String(req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();
  if (bookRateLimited(ip, 'slots', 120, 600000)) return res.status(429).json({ error: 'Too many requests. Please wait a moment.' });
  try {
    if (String(req.query.phone || '').replace(/\D/g, '').length < 10) return res.json({ times: [] });
    const s = await getBookingSettings();
    if (!s.enabled) return res.json({ times: [] });
    const doc = (await bookableDoctors(s)).find(d => bookDocToken(d.email) === String(req.query.doctor || ''));
    if (!doc || bookBlockedByGender(s, doc.email, String(req.query.gender || ''))) return res.json({ times: [] });
    res.set('Cache-Control', 'no-store').json({ times: await computeBookingSlots(s, doc, String(req.query.date || '')) });
  } catch (err) { res.status(500).json({ error: 'Could not load times.' }); }
});

app.get('/api/book/availability', async (req, res) => {
  const ip = String(req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();
  if (bookRateLimited(ip, 'avail', 40, 600000)) return res.status(429).json({ error: 'Too many requests. Please wait a moment.' });
  try {
    if (String(req.query.phone || '').replace(/\D/g, '').length < 10) return res.json({ days: [] });
    const s = await getBookingSettings();
    if (!s.enabled) return res.json({ days: [] });
    const doc = (await bookableDoctors(s)).find(d => bookDocToken(d.email) === String(req.query.doctor || ''));
    if (!doc || bookBlockedByGender(s, doc.email, String(req.query.gender || ''))) return res.json({ days: [] });
    const base = new Date(cairoTodayYmd() + 'T12:00:00Z');
    const n = Math.min(Number(s.max_days_ahead) || 14, 14);
    const list = [];
    for (let i = 0; i <= n; i++) list.push(new Date(base.getTime() + i * 86400000).toISOString().slice(0, 10));
    const all = await Promise.all(list.map(async d => ({ date: d, times: await computeBookingSlots(s, doc, d).catch(() => []) })));
    res.set('Cache-Control', 'no-store').json({ days: all.filter(x => x.times.length) });
  } catch (err) { res.status(500).json({ error: 'Could not load times.' }); }
});

app.post('/api/book', async (req, res) => {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return res.status(500).json({ error: 'Booking is not available right now.' });
  const ip = String(req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();
  if (bookRateLimited(ip, 'book', 6, 3600000)) return res.status(429).json({ error: 'Too many attempts. Please try again later.' });
  const b = req.body || {};
  if (b.website) return res.json({ ok: true }); // honeypot
  try {
    const s = await getBookingSettings();
    if (!s.enabled) return res.status(400).json({ error: 'Online booking is closed right now.' });
    const name = bookClean(b.name, 120), phone = bookClean(b.phone, 20).replace(/[^0-9+]/g, '');
    if (name.length < 3 || phone.replace(/\D/g, '').length < 10) return res.status(400).json({ error: 'Please enter your full name and a valid phone number.' });
    const type = s.types.find(t => t.key === b.type && t.price > 0);
    const doc = (await bookableDoctors(s)).find(d => bookDocToken(d.email) === String(b.doctor || ''));
    if (!type || !doc) return res.status(400).json({ error: 'Please choose a visit type and a doctor.' });
    const gender = ['male', 'female'].includes(String(b.gender || '')) ? String(b.gender) : '';
    if (!gender) return res.status(400).json({ error: 'Please choose your gender.' });
    if (bookBlockedByGender(s, doc.email, gender)) return res.status(400).json({ error: 'This doctor is not available for your booking. Please choose another doctor.' });
    if (type.visit_type === 'checkup' && bookRule(s, doc.email).checkups === false) return res.status(400).json({ error: 'This doctor does not take check-ups. Please choose another doctor.' });
    const date = String(b.date || ''), time = String(b.time || '');
    const times = await computeBookingSlots(s, doc, date);
    if (!/^\d{2}:\d{2}$/.test(time) || !times.includes(time)) return res.status(409).json({ error: 'Sorry, that time is no longer available. Please pick another one.' });

    const pkg = await hasActivePackageByPhone(phone);
    const deposit = pkg ? 0 : Math.round(type.price / 2);
    let shotPath = null;
    if (!pkg) {
      const ext = SHOT_TYPES[String(b.shotType || '').toLowerCase()];
      if (!ext || !b.shotBase64) return res.status(400).json({ error: 'Please upload the InstaPay transfer screenshot to confirm your booking.' });
      const bytes = Buffer.from(String(b.shotBase64), 'base64');
      if (bytes.length < 500 || bytes.length > SHOT_MAX_BYTES) return res.status(400).json({ error: 'The screenshot is not valid (max 4 MB).' });
      shotPath = `${Date.now()}_${Math.random().toString(36).slice(2, 10)}/deposit.${ext}`;
      const up = await fetch(`${SUPABASE_URL}/storage/v1/object/${BOOKING_BUCKET}/${shotPath}`, { method: 'POST', headers: { ...bookHeaders(), 'Content-Type': String(b.shotType), 'x-upsert': 'false' }, body: bytes });
      if (!up.ok) { console.error('Deposit upload failed:', up.status, await up.text().catch(() => '')); return res.status(500).json({ error: 'Could not save the screenshot. Please try again.' }); }
    }

    const start = cairoToDate(date, time), end = new Date(start.getTime() + s.slot_minutes * 60000);
    const noteText = pkg
      ? 'Online booking - patient has an active package, no deposit needed.'
      : `Online booking - deposit of ${deposit} EGP received by InstaPay (non-refundable). Deduct it from the fee. Screenshot is in Dashboard > Booking.`;
    const ins = await fetch(`${SUPABASE_URL}/rest/v1/appointments`, {
      method: 'POST', headers: { ...bookHeaders(), 'Content-Type': 'application/json', Prefer: 'return=representation' },
      body: JSON.stringify({
        patient_name: name, patient_phone: phone, start_time: start.toISOString(), end_time: end.toISOString(),
        doctor_name: doc.name, doctor_color: doc.color || null, visit_type: type.visit_type || 'session',
        notes: [{ text: noteText, author: 'Online booking', at: new Date().toISOString() }],
      }),
    });
    const created = await ins.json();
    if (!ins.ok || !Array.isArray(created) || !created[0]) { console.error('Online booking insert failed:', ins.status, JSON.stringify(created)); return res.status(500).json({ error: 'Could not save your booking. Please try again.' }); }
    const appt = created[0];

    // Two people tapping the same slot at the same moment: the earlier one keeps it.
    try {
      const same = await (await fetch(`${SUPABASE_URL}/rest/v1/appointments?doctor_name=eq.${encodeURIComponent(doc.name)}&start_time=eq.${encodeURIComponent(start.toISOString())}&deleted_at=is.null&status=neq.cancelled&select=id,created_at&order=created_at.asc`, { headers: bookHeaders() })).json();
      if (Array.isArray(same) && same.length > 1 && String(same[0].id) !== String(appt.id)) {
        await fetch(`${SUPABASE_URL}/rest/v1/appointments?id=eq.${encodeURIComponent(appt.id)}`, { method: 'PATCH', headers: { ...bookHeaders(), 'Content-Type': 'application/json' }, body: JSON.stringify({ status: 'cancelled' }) });
        return res.status(409).json({ error: 'Sorry, someone just took that time. Please pick another one. (Your screenshot was not used.)' });
      }
    } catch (e) { /* best effort */ }

    await fetch(`${SUPABASE_URL}/rest/v1/booking_deposits`, {
      method: 'POST', headers: { ...bookHeaders(), 'Content-Type': 'application/json', Prefer: 'return=minimal' },
      body: JSON.stringify({ appointment_id: String(appt.id), patient_name: name, phone, doctor_name: doc.name, visit_label: type.label, start_time: start.toISOString(), amount: deposit, package_booking: !!pkg, screenshot_path: shotPath }),
    }).catch(e => console.error('Deposit row insert failed:', e.message));

    fetch(`${SUPABASE_URL}/rest/v1/booking_leads?phone_key=eq.${bookPhoneKey(phone)}`, { method: 'PATCH', headers: { ...bookHeaders(), 'Content-Type': 'application/json' }, body: JSON.stringify({ completed: true }) }).catch(() => {});
    res.json({ ok: true, doctor: doc.name, date, time, label: type.label, deposit, package: !!pkg });

    // Tell the owner(s) and the doctor on Telegram (best effort).
    try {
      const dateAr = new Date(date + 'T12:00:00Z').toLocaleDateString('ar-EG', { weekday: 'long', day: 'numeric', month: 'long', timeZone: 'UTC' });
      const msg = `📅 حجز أونلاين جديد\n${name} · ${phone}\n${dateAr} الساعة ${time}\nمع ${doc.name} — ${type.label}\n${pkg ? 'عنده باكدج — من غير deposit' : `Deposit ${deposit} جنيه (InstaPay) — راجع الصورة من Dashboard ← Booking`}`;
      const owners = await (await fetch(`${SUPABASE_URL}/rest/v1/doctors?role=eq.owner&status=eq.approved&telegram_chat_id=not.is.null&select=telegram_chat_id`, { headers: bookHeaders() })).json();
      const chats = new Set((Array.isArray(owners) ? owners : []).map(o => o.telegram_chat_id));
      if (doc.telegram_chat_id) chats.add(doc.telegram_chat_id);
      for (const c of chats) await telegramSend(c, msg).catch(() => {});
    } catch (e) { /* ignore */ }
  } catch (err) {
    console.error('Online booking error:', err);
    res.status(500).json({ error: 'Something went wrong. Please try again.' });
  }
});

// ---- Owner side ----
app.get('/api/booking/settings', requireOwnerDoctor, async (req, res) => {
  try {
    const s = await getBookingSettings();
    const dr = await (await fetch(`${SUPABASE_URL}/rest/v1/doctors?status=eq.approved&role=in.(doctor,owner)&select=email,name&order=name.asc`, { headers: bookHeaders() })).json();
    res.json({ settings: s, doctors: Array.isArray(dr) ? dr : [] });
  } catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});

app.put('/api/booking/settings', requireOwnerDoctor, async (req, res) => {
  const b = req.body || {};
  const num = (v, lo, hi, d) => { const n = parseInt(v, 10); return Number.isFinite(n) ? Math.min(hi, Math.max(lo, n)) : d; };
  const types = (Array.isArray(b.types) ? b.types : []).slice(0, 8).map((t, i) => ({
    key: bookClean(t.key, 30).replace(/[^a-z0-9_-]/gi, '') || ('type' + (i + 1)),
    label: bookClean(t.label, 60), label_ar: bookClean(t.label_ar, 90), price: num(t.price, 0, 100000, 0),
    visit_type: ['session', 'checkup', 'recovery'].includes(t.visit_type) ? t.visit_type : 'session',
  })).filter(t => t.label);
  const hours = {};
  for (const [email, days] of Object.entries(b.hours && typeof b.hours === 'object' ? b.hours : {})) {
    if (typeof email !== 'string' || email.length > 120 || !days || typeof days !== 'object') continue;
    for (const wd of ['0', '1', '2', '3', '4', '5', '6']) {
      const ranges = (Array.isArray(days[wd]) ? days[wd] : []).slice(0, 3)
        .filter(r => Array.isArray(r) && /^\d{2}:\d{2}$/.test(r[0]) && /^\d{2}:\d{2}$/.test(r[1]) && hmToMin(r[0]) < hmToMin(r[1]))
        .map(r => [r[0], r[1]]);
      if (ranges.length) { (hours[email] = hours[email] || {})[wd] = ranges; }
    }
  }
  const docsRules = {};
  for (const [email, r] of Object.entries(b.docs && typeof b.docs === 'object' ? b.docs : {})) {
    if (typeof email !== 'string' || email.length > 120 || !r || typeof r !== 'object') continue;
    docsRules[email] = { gender: ['male', 'female'].includes(r.gender) ? r.gender : '', checkups: r.checkups !== false };
  }
  const data = { enabled: !!b.enabled, docs: docsRules, instapay: bookClean(b.instapay, 200), note: bookClean(b.note, 600), slot_minutes: num(b.slot_minutes, 15, 120, 30), min_lead_hours: num(b.min_lead_hours, 0, 72, 2), max_days_ahead: num(b.max_days_ahead, 1, 90, 30), types, hours };
  try {
    const r = await fetch(`${SUPABASE_URL}/rest/v1/booking_settings?on_conflict=id`, { method: 'POST', headers: { ...bookHeaders(), 'Content-Type': 'application/json', Prefer: 'resolution=merge-duplicates,return=minimal' }, body: JSON.stringify({ id: 1, data, updated_at: new Date().toISOString() }) });
    if (!r.ok) { console.error('booking_settings save failed', r.status, await r.text().catch(() => '')); return res.status(500).json({ error: 'Could not save. Did you run the booking SQL?' }); }
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});

app.get('/api/login-log', requireOwnerDoctor, async (req, res) => {
  try {
    const r = await fetch(`${SUPABASE_URL}/rest/v1/login_log?order=created_at.desc&limit=300`, { headers: { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}` } });
    const rows = await r.json();
    if (!r.ok) return res.status(500).json({ error: 'Could not load. Did you run the login log SQL?' });
    res.json(rows);
  } catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});
app.get('/api/booking/leads', requireOwnerOrSecretary, async (req, res) => {
  try {
    const r = await fetch(`${SUPABASE_URL}/rest/v1/booking_leads?completed=eq.false&order=last_seen.desc&limit=100`, { headers: bookHeaders() });
    const rows = await r.json();
    if (!r.ok) return res.status(500).json({ error: 'Could not load. Did you run the leads SQL?' });
    res.json(rows);
  } catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});
app.delete('/api/booking/leads/:id', requireOwnerOrSecretary, async (req, res) => {
  try {
    await fetch(`${SUPABASE_URL}/rest/v1/booking_leads?id=eq.${encodeURIComponent(req.params.id)}`, { method: 'DELETE', headers: bookHeaders() });
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});

app.get('/api/booking/deposits', requireOwnerOrSecretary, async (req, res) => {
  try {
    const r = await fetch(`${SUPABASE_URL}/rest/v1/booking_deposits?order=created_at.desc&limit=150`, { headers: bookHeaders() });
    const rows = await r.json();
    if (!r.ok) return res.status(500).json({ error: 'Could not load. Did you run the booking SQL?' });
    res.json(rows);
  } catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});

app.get('/api/booking/deposits/:id/shot', requireOwnerOrSecretary, async (req, res) => {
  try {
    const rows = await (await fetch(`${SUPABASE_URL}/rest/v1/booking_deposits?id=eq.${encodeURIComponent(req.params.id)}&select=screenshot_path&limit=1`, { headers: bookHeaders() })).json();
    const p = rows && rows[0] && rows[0].screenshot_path;
    if (!p) return res.status(404).json({ error: 'No screenshot.' });
    const s = await fetch(`${SUPABASE_URL}/storage/v1/object/sign/${BOOKING_BUCKET}/${p}`, { method: 'POST', headers: { ...bookHeaders(), 'Content-Type': 'application/json' }, body: JSON.stringify({ expiresIn: 600 }) });
    const j = await s.json();
    if (!s.ok || !j.signedURL) return res.status(500).json({ error: 'Could not open the screenshot.' });
    res.json({ url: `${SUPABASE_URL}/storage/v1${j.signedURL}` });
  } catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});

app.post('/api/booking/deposits/:id/review', requireOwnerOrSecretary, async (req, res) => {
  const status = req.body && req.body.status;
  if (!['ok', 'rejected'].includes(status)) return res.status(400).json({ error: 'Bad status.' });
  try {
    const rows = await (await fetch(`${SUPABASE_URL}/rest/v1/booking_deposits?id=eq.${encodeURIComponent(req.params.id)}&select=appointment_id&limit=1`, { headers: bookHeaders() })).json();
    const row = Array.isArray(rows) && rows[0];
    if (!row) return res.status(404).json({ error: 'Not found.' });
    await fetch(`${SUPABASE_URL}/rest/v1/booking_deposits?id=eq.${encodeURIComponent(req.params.id)}`, { method: 'PATCH', headers: { ...bookHeaders(), 'Content-Type': 'application/json' }, body: JSON.stringify({ status, reviewed_at: new Date().toISOString() }) });
    if (status === 'rejected' && row.appointment_id) {
      await fetch(`${SUPABASE_URL}/rest/v1/appointments?id=eq.${encodeURIComponent(row.appointment_id)}`, { method: 'PATCH', headers: { ...bookHeaders(), 'Content-Type': 'application/json' }, body: JSON.stringify({ status: 'cancelled' }) });
    }
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});

const BOOK_PAGE = String.raw`<!doctype html><html lang="ar" dir="rtl"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex"><meta name="theme-color" content="#ffffff"><title>Book an appointment - Empower</title>
<link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin><link href="https://fonts.googleapis.com/css2?family=Cairo:wght@400;600;700&display=swap" rel="stylesheet">
<style>
:root{--ink:#12363a;--muted:#667570;--gold:#b07a1f;--bg:#f7f8f6;--line:#e6e9e4;--soft:#eef4f2;--tint:#fbf5e6}
*{box-sizing:border-box;-webkit-tap-highlight-color:transparent}
html{font-size:18px}
html{overflow-x:hidden}body{overflow-x:hidden;margin:0;background:var(--bg);color:var(--ink);font-family:'Cairo',-apple-system,'Segoe UI',Roboto,Arial,sans-serif;line-height:1.55;padding:0 0 40px}
.wrap{max-width:520px;margin:0 auto;padding:18px 16px}
.top{display:flex;align-items:center;justify-content:space-between;margin-bottom:6px}
.lang{border:1px solid var(--line);background:#fff;color:var(--ink);border-radius:999px;padding:6px 16px;font:600 .8rem 'Cairo',sans-serif;cursor:pointer}
.logo{display:block;width:210px;max-width:60%;margin:6px auto 8px}
h1{font-size:1.45rem;text-align:center;margin:6px 0 2px;font-weight:700}
.sub{text-align:center;color:var(--muted);font-size:.9rem;margin-bottom:18px}
.steps{display:flex;justify-content:center;gap:8px;margin:0 0 18px}
.dot{width:34px;height:5px;border-radius:5px;background:var(--line)}.dot.on{background:var(--gold)}
.card{background:#fff;border-radius:18px;padding:20px;box-shadow:0 2px 14px rgba(18,54,58,.06);margin-bottom:14px}
.card h2{font-size:1rem;margin:0 0 12px;font-weight:700}
label{display:block;font-size:.88rem;font-weight:600;margin:14px 0 6px;color:var(--ink)}
label:first-child{margin-top:0}
input[type=text],input[type=tel],input[type=date]{width:100%;padding:14px;border:1.5px solid var(--line);border-radius:12px;font:400 1rem 'Cairo',sans-serif;background:#fff;color:var(--ink);outline:none}
input:focus{border-color:var(--gold)}
.opts{display:grid;gap:10px}
.opt{display:flex;justify-content:space-between;align-items:center;gap:10px;padding:14px 16px;border:1.5px solid var(--line);border-radius:14px;background:#fff;cursor:pointer;font:600 .95rem 'Cairo',sans-serif;color:var(--ink);text-align:start;width:100%}
.opt small{font-weight:400;color:var(--muted);font-size:.78rem;display:block}
.opt .pr{color:var(--gold);font-weight:700;white-space:nowrap}
.opt.on{border-color:var(--ink);background:var(--soft)}
.chips{display:flex;flex-wrap:wrap;gap:8px}
.chip{padding:10px 16px;border:1.5px solid var(--line);border-radius:999px;background:#fff;font:600 .92rem 'Cairo',sans-serif;color:var(--ink);cursor:pointer}
.chip.on{background:var(--ink);border-color:var(--ink);color:#fff}
.days{display:flex;gap:8px;overflow-x:auto;padding-bottom:6px;scrollbar-width:none}.days::-webkit-scrollbar{display:none}
.day{flex:0 0 auto;min-width:64px;padding:10px 8px;text-align:center;border:1.5px solid var(--line);border-radius:14px;background:#fff;cursor:pointer;font-family:'Cairo',sans-serif;color:var(--ink)}
.day b{display:block;font-size:1.15rem;line-height:1.2}.day span{font-size:.72rem;color:var(--muted)}
.day.on{background:var(--ink);border-color:var(--ink);color:#fff}.day.on span{color:#d6e2de}
.slots{display:grid;grid-template-columns:repeat(3,1fr);gap:9px}
.slot{padding:12px 4px;border:1.5px solid var(--line);border-radius:12px;background:#fff;font:600 .95rem 'Cairo',sans-serif;color:var(--ink);cursor:pointer}
.slot.on{background:var(--ink);border-color:var(--ink);color:#fff}
.hint{color:var(--muted);font-size:.85rem;padding:6px 0}
.dep{background:var(--tint);border-radius:14px;padding:16px;font-size:.9rem}
.dep .big{font-size:1.7rem;font-weight:700;color:var(--ink);line-height:1.2}
.dep .acct{display:flex;flex-direction:column;align-items:stretch;gap:10px;background:#fff;border-radius:10px;padding:10px 12px;margin:10px 0;font-weight:700;direction:ltr}
.dep .acct span{word-break:break-all;overflow-wrap:anywhere;font-size:.95rem;line-height:1.5}.dep .acct .copy,.dep .acct .openlink{display:block;width:100%;box-sizing:border-box;text-align:center;padding:11px;border-radius:10px;font-weight:700;font-size:.95rem;font-family:inherit;text-decoration:none;cursor:pointer}.dep .acct .copy{border:1.5px solid #12363a;background:#fff;color:#12363a}.dep .acct .openlink{border:none;background:#12363a;color:#fff}
.dep .copy{border:none;background:var(--ink);color:#fff;border-radius:8px;padding:6px 12px;font:600 .78rem 'Cairo',sans-serif;cursor:pointer}
.up{display:block;border:2px dashed #cfd6d1;border-radius:14px;padding:18px;text-align:center;color:var(--muted);font-size:.92rem;cursor:pointer;background:#fcfdfc}
.up input{display:none}#prev{max-width:100%;max-height:230px;border-radius:10px;margin-top:10px;display:none}
button.go{width:100%;margin-top:6px;padding:16px;border:0;border-radius:14px;background:var(--ink);color:#fff;font:700 1.05rem 'Cairo',sans-serif;cursor:pointer}
button.go:disabled{opacity:.5}
.err{color:#b3261e;font-size:.88rem;min-height:1.3em;margin:8px 0 0}
.hp{position:absolute;top:0;left:0;width:1px;height:1px;overflow:hidden;opacity:0;pointer-events:none}
.ok{text-align:center}.ok .check{width:64px;height:64px;border-radius:50%;background:#e4f4ea;color:#1b7a4a;display:flex;align-items:center;justify-content:center;font-size:2rem;margin:6px auto 10px}
.ok h1{color:#1b7a4a}.sum{background:var(--soft);border-radius:14px;padding:14px;margin:14px 0;font-weight:600}
.where{background:#fff;border-radius:14px;padding:14px;font-size:.88rem;text-align:start;box-shadow:0 2px 14px rgba(18,54,58,.06)}
a{color:var(--gold);font-weight:600}
</style></head><body><div class="wrap" id="app">
<div class="top"><span></span><button type="button" class="lang" id="langBtn">EN</button></div>
<img class="logo" src="/clinic-logo.png" alt="Empower">
<h1 id="title"></h1><div class="sub" id="sub"></div>
<div class="steps"><i class="dot on" id="d1"></i><i class="dot" id="d2"></i><i class="dot" id="d3"></i></div>

<div id="step1" style="display:none"><div class="card">
<input class="hp" id="website" tabindex="-1" autocomplete="off">
<label id="lName"></label><input type="text" id="name" autocomplete="name">
<label id="lPhone"></label><input type="tel" id="phone" inputmode="tel" autocomplete="tel" dir="ltr" style="text-align:start">
<label id="lGender"></label><div class="chips" id="genderBox"><button type="button" class="chip" data-g="male" id="gMale"></button><button type="button" class="chip" data-g="female" id="gFemale"></button></div>
<div class="err" id="err1"></div></div>
<button class="go" id="next"></button></div>

<div id="form" style="display:none">
<div class="card"><h2 id="hType"></h2><div class="opts" id="types"></div></div>
<div class="card"><h2 id="hDoc"></h2><div class="chips" id="docs"></div>
<label id="lDate" style="display:none"></label><div class="days" id="days" style="display:none"></div>
<label id="lOther" style="display:none"></label><input type="date" id="date" style="display:none">
<label id="lTime" style="margin-top:18px"></label><div id="avail"></div><div class="slots" id="slots" style="display:none"></div></div>
<div class="card"><h2 id="hPay"></h2><div class="dep" id="depBox"></div>
<div id="shotWrap" style="margin-top:14px"><label class="up"><span id="upTxt"></span><input type="file" id="shot" accept="image/*"><img id="prev" alt=""></label></div></div>
<div class="err" id="err"></div>
<button class="go" id="go"></button></div>
</div>
<script>
var gender='',cfg=null,chosenTime='',chosenType='',chosenDoc='',shotData=null,shotType='',lang='ar';
try{lang=localStorage.getItem('bl')||((navigator.language||'').toLowerCase().indexOf('en')===0?'en':'ar')}catch(e){}
var T={
 /*docs*/
 en:{title:'Book an appointment',sub0:'Loading…',pickDay:'Choose a day to see the times.',subClosed:'Online booking is not open right now. Please contact the clinic on WhatsApp.',sub1:'Enter your details to start.',sub2:'Choose your visit, doctor and time.',lName:'Full name',lPhone:'Phone number (WhatsApp)',lGender:'Gender',gMale:'Male',gFemale:'Female',eGender:'Please choose your gender.',noDocs:'No doctors are available for this visit type.',next:'Continue',hType:'1. Visit type',hDoc:'2. Doctor & time',lDate:'Day',lOther:'Or pick another date',lTime:'Available times',hPay:'3. Deposit to confirm',go:'Confirm booking',booking:'Booking…',pickDoc:'Choose a doctor and a day to see times.',loading:'Loading…',noTimes:'No available times that day. Try another day.',timesFail:'Could not load times.',
  dep1:'Deposit',dep2:'half of the fee ({p} EGP). It is non-refundable and is deducted from your fee at the clinic.',dep3:'Transfer by InstaPay to:',copy:'Copy',openpay:'Open InstaPay link',copied:'Copied ✓',dep4:'Then upload the transfer screenshot below.',dep5:'Have an active package with us? Skip the screenshot — no deposit needed.',up:'Tap to upload the transfer screenshot',upDone:'Tap to change the screenshot',
  eName:'Please enter your full name.',ePhone:'Please enter a valid phone number.',eDoc:'Please choose a doctor.',eTime:'Please choose a day and a time.',eImg:'Please choose an image file.',eConn:'Connection problem. Please try again.',eNA:'Booking is not available right now.',
  done:'Your booking is confirmed',pkg:'Your active package covers this visit.',depRec:'Deposit received: {d} EGP (non-refundable, deducted from your fee).',addr:'__ADDR_EN__',map:'Open the location on the map',arrive:'Please arrive 5 minutes early. To change the time, contact the clinic on WhatsApp at least 5 hours before.',dr:'Dr. ',egp:'EGP',at:'at',other:'العربية'},
 ar:{title:'احجز ميعادك',sub0:'جاري التحميل…',pickDay:'اختار اليوم عشان تشوف المواعيد.',subClosed:'الحجز الأونلاين مقفول دلوقتي. من فضلك كلّم العيادة على واتساب.',sub1:'اكتب بياناتك عشان تبدأ.',sub2:'اختار نوع الزيارة والدكتور والميعاد.',lName:'الاسم بالكامل',lPhone:'رقم التليفون (واتساب)',lGender:'النوع',gMale:'ذكر',gFemale:'أنثى',eGender:'من فضلك اختار النوع.',noDocs:'مفيش دكاترة متاحين لنوع الزيارة ده.',next:'متابعة',hType:'١. نوع الزيارة',hDoc:'٢. الدكتور والميعاد',lDate:'اليوم',lOther:'أو اختار تاريخ تاني',lTime:'المواعيد المتاحة',hPay:'٣. العربون لتأكيد الحجز',go:'تأكيد الحجز',booking:'جاري الحجز…',pickDoc:'اختار الدكتور واليوم عشان تشوف المواعيد.',loading:'جاري التحميل…',noTimes:'مفيش مواعيد متاحة اليوم ده. جرّب يوم تاني.',timesFail:'مقدرناش نحمّل المواعيد.',
  dep1:'العربون',dep2:'نص السعر ({p} جنيه). العربون غير مسترد ويتخصم من الحساب في العيادة.',dep3:'حوّل بـ InstaPay على:',openpay:'افتح لينك InstaPay',copy:'نسخ',copied:'تم النسخ ✓',dep4:'وبعدين ارفع صورة التحويل تحت.',dep5:'عندك باكدج شغال معانا؟ سيب صورة التحويل فاضية، مش محتاج عربون.',up:'اضغط لرفع صورة التحويل',upDone:'اضغط لتغيير الصورة',
  eName:'من فضلك اكتب اسمك بالكامل.',ePhone:'من فضلك اكتب رقم تليفون صحيح.',eDoc:'من فضلك اختار الدكتور.',eTime:'من فضلك اختار اليوم والميعاد.',eImg:'من فضلك اختار ملف صورة.',eConn:'فيه مشكلة في الاتصال. جرّب تاني.',eNA:'الحجز مش متاح دلوقتي.',
  done:'تم تأكيد حجزك',pkg:'الباكدج بتاعك بيغطي الزيارة دي.',depRec:'تم استلام العربون: {d} جنيه (غير مسترد ويتخصم من الحساب).',addr:'__ADDR_AR__',map:'افتح الموقع على الخريطة',arrive:'من فضلك تعالى قبل الميعاد بـ 5 دقايق. لو عايز تغيّر الميعاد كلّم العيادة على واتساب قبلها بـ 5 ساعات على الأقل.',dr:'Dr. ',egp:'جنيه',at:'الساعة',other:'EN'}
};
var SRV={'Booking is not available right now.':['eNA'],'Please enter your full name and a valid phone number.':['eName'],
 'Sorry, that time is no longer available. Please pick another one.':'عذراً، الميعاد ده اتحجز. اختار ميعاد تاني.',
 'Sorry, someone just took that time. Please pick another one. (Your screenshot was not used.)':'عذراً، حد حجز الميعاد ده دلوقتي. اختار ميعاد تاني. (صورة التحويل ماتستخدمتش.)',
 'Please upload the InstaPay transfer screenshot to confirm your booking.':'من فضلك ارفع صورة تحويل InstaPay عشان نأكد الحجز.',
 'The screenshot is not valid (max 4 MB).':'الصورة مش صالحة (الحد الأقصى 4 ميجا).',
 'Please choose a visit type and a doctor.':'من فضلك اختار نوع الزيارة والدكتور.',
 'Too many attempts. Please try again later.':'محاولات كتير. جرّب تاني بعد شوية.',
 'Too many requests. Please wait a moment.':'طلبات كتير. استنى شوية.',
 'Something went wrong. Please try again.':'حصل خطأ. جرّب تاني.',
 'Could not save your booking. Please try again.':'مقدرناش نسجل الحجز. جرّب تاني.',
 'Could not save the screenshot. Please try again.':'مقدرناش نحفظ الصورة. جرّب تاني.',
 'Online booking is closed right now.':'الحجز الأونلاين مقفول دلوقتي.',
 'Please choose your gender.':'من فضلك اختار النوع.',
 'This doctor is not available for your booking. Please choose another doctor.':'الدكتور ده مش متاح لحجزك. اختار دكتور تاني.',
 'This doctor does not take check-ups. Please choose another doctor.':'الدكتور ده مش بياخد كشوفات. اختار دكتور تاني.'};
function $(i){return document.getElementById(i)}
function dname(n){ n=String(n||'').replace(/^\s*(dr\.?|doctor|د\.?|دكتور|دكتورة)\s+/i,'').replace(/^\s*(dr\.?)\s+/i,'').trim(); n=n.replace(/\S+/g,function(w){ return w.charAt(0).toUpperCase()+w.slice(1).toLowerCase(); }); return 'Dr. '+n; }
function t(k,r){var s=(T[lang]||T.en)[k]; if(s===undefined)s=T.en[k]||''; if(r){for(var x in r)s=s.replace('{'+x+'}',r[x])} return s}
function esc(s){return String(s).replace(/[&<>"]/g,function(c){return{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]})}
function srv(m){ if(lang==='en')return m; var v=SRV[m]; if(!v)return m; return typeof v==='string'?v:t(v[0]); }
function num(n){ return lang==='ar'?String(n).replace(/\d/g,function(d){return '٠١٢٣٤٥٦٧٨٩'[d]}):String(n); }
function fmtTime(hm){ var p=hm.split(':'),h=+p[0],m=p[1],ap=h>=12?(lang==='ar'?'م':'PM'):(lang==='ar'?'ص':'AM'); h=h%12; if(h===0)h=12; return num(h+':'+m)+' '+ap; }
function ymd(d){var m=d.getMonth()+1,dd=d.getDate();return d.getFullYear()+'-'+(m<10?'0':'')+m+'-'+(dd<10?'0':'')+dd}
function typeObj(){return cfg.types.filter(function(x){return x.key===chosenType})[0]}
function setStep(n){ for(var i=1;i<=3;i++)$('d'+i).className='dot'+(i<=n?' on':'') }
function applyLang(){
  document.documentElement.lang=lang; document.documentElement.dir=lang==='ar'?'rtl':'ltr';
  $('langBtn').textContent=t('other'); $('title').textContent=t('title');
  $('lName').textContent=t('lName'); $('lPhone').textContent=t('lPhone'); $('lGender').textContent=t('lGender'); $('gMale').textContent=t('gMale'); $('gFemale').textContent=t('gFemale'); $('next').textContent=t('next');
  $('hType').textContent=t('hType'); $('hDoc').textContent=t('hDoc'); $('lDate').textContent=t('lDate'); $('lOther').textContent=t('lOther'); $('lTime').textContent=t('lTime'); $('hPay').textContent=t('hPay');
  $('go').textContent=$('go').disabled?t('booking'):t('go');
  $('upTxt').textContent=shotData?t('upDone'):t('up');
  if(!cfg){ $('sub').textContent=t('sub0'); } else if(!cfg.enabled){ $('sub').textContent=t('subClosed'); } else if(cfg.locked){ $('sub').textContent=t('sub1'); } else { $('sub').textContent=t('sub2'); }
  if(cfg&&!cfg.locked&&cfg.enabled){ renderTypes(); renderDocs(); renderDays(); depText(); if(chosenDoc) loadSlots(); else $('avail').innerHTML='<div class="hint">'+t('pickDoc')+'</div>'; }
}
$('langBtn').onclick=function(){ lang=lang==='ar'?'en':'ar'; try{localStorage.setItem('bl',lang)}catch(e){} applyLang(); };
function tLabel(x){ if(lang==='ar'){ if(x.label_ar) return x.label_ar; var l=x.label||''; if(/check-?up/i.test(l)) return 'Check-up — كشف (جلسة تقييمية)'; if(/(1|one)\s*body\s*part/i.test(l)) return 'جلسة — على مكان واحد (عضو واحد)'; if(/(2|two)\s*body\s*parts?/i.test(l)) return 'جلسة — على أكتر من مكان (عضوين)'; } return l||x.label; }
function renderTypes(){ $('types').innerHTML=cfg.types.map(function(x){ return '<button type="button" class="opt'+(x.key===chosenType?' on':'')+'" data-k="'+esc(x.key)+'"><span>'+esc(tLabel(x))+'</span><span class="pr">'+num(x.price)+' '+t('egp')+'</span></button>'; }).join('');
  Array.prototype.forEach.call($('types').querySelectorAll('.opt'),function(b){ b.onclick=function(){ chosenType=b.dataset.k; renderTypes(); renderDocs(); depText(); }; }); }
function docList(){ var x=typeObj(); return cfg.doctors.filter(function(d){ return !(x&&x.visit_type==='checkup'&&d.checkups===false); }); }
function renderDocs(){ var L=docList(); if(chosenDoc&&!L.some(function(d){return d.id===chosenDoc})){ chosenDoc=''; loadSlots(); }
  if(!L.length){ $('docs').innerHTML='<div class="hint">'+t('noDocs')+'</div>'; return; }
  $('docs').innerHTML=L.map(function(d){ return '<button type="button" class="chip'+(d.id===chosenDoc?' on':'')+'" data-d="'+esc(d.id)+'">'+esc(dname(d.name))+'</button>'; }).join('');
  Array.prototype.forEach.call($('docs').querySelectorAll('.chip'),function(b){ b.onclick=function(){ chosenDoc=b.dataset.d; renderDocs(); loadSlots(); }; }); }
function renderDays(){ var n=Math.min(cfg.max_days_ahead,14),h='',now=new Date(),cur=$('date').value;
  for(var i=0;i<n;i++){ var d=new Date(now.getFullYear(),now.getMonth(),now.getDate()+i); if(d.getDay()===5)continue; var key=ymd(d);
    h+='<button type="button" class="day'+(key===cur?' on':'')+'" data-y="'+key+'"><span>'+d.toLocaleDateString(lang==='ar'?'ar-EG':'en-GB',{weekday:'short'})+'</span><b>'+num(d.getDate())+'</b><span>'+d.toLocaleDateString(lang==='ar'?'ar-EG':'en-GB',{month:'short'})+'</span></button>'; }
  $('days').innerHTML=h; Array.prototype.forEach.call($('days').querySelectorAll('.day'),function(b){ b.onclick=function(){ $('date').value=b.dataset.y; renderDays(); loadSlots(); }; }); }
function depText(){ var x=typeObj(); if(!x){ $('depBox').innerHTML='<div class="hint">'+t('hType')+'</div>'; return; }
  $('depBox').innerHTML='<div>'+t('dep1')+'</div><div class="big">'+num(x.deposit)+' '+t('egp')+'</div><div>'+t('dep2',{p:num(x.price)})+'</div>'+(cfg.instapay?'<div style="margin-top:10px">'+t('dep3')+'</div><div class="acct"><span>'+esc(cfg.instapay)+'</span>'+(/^https?:\/\//i.test(cfg.instapay)?'<a class="openlink" href="'+esc(cfg.instapay)+'" target="_blank" rel="noopener">'+t('openpay')+'</a>':'')+'<button type="button" class="copy" id="cpy">'+t('copy')+'</button></div>':'')+(cfg.note?'<div>'+esc(cfg.note)+'</div>':'')+'<div style="margin-top:8px">'+t('dep4')+'</div><div class="hint" style="margin-top:6px">'+t('dep5')+'</div>';
  var c=$('cpy'); if(c)c.onclick=function(){ var done=function(){c.textContent=t('copied')}; try{ navigator.clipboard.writeText(cfg.instapay).then(done,function(){ var ta=document.createElement('textarea'); ta.value=cfg.instapay; document.body.appendChild(ta); ta.select(); try{document.execCommand('copy');done()}catch(e){} ta.remove(); }); }catch(e){ var ta=document.createElement('textarea'); ta.value=cfg.instapay; document.body.appendChild(ta); ta.select(); try{document.execCommand('copy');done()}catch(x){} ta.remove(); } }; }
function loadSlots(){ chosenTime=''; $('date').value='';
  if(!chosenDoc){ $('avail').innerHTML='<div class="hint">'+t('pickDoc')+'</div>'; return; }
  var my=chosenDoc; $('avail').innerHTML='<div class="hint">'+t('loading')+'</div>';
  fetch('/api/book/availability?doctor='+encodeURIComponent(chosenDoc)+'&gender='+gender+'&phone='+encodeURIComponent($('phone').value)).then(function(r){return r.json()}).then(function(j){
    if(my!==chosenDoc) return;
    if(!j.days||!j.days.length){ $('avail').innerHTML='<div class="hint">'+t('noTimes')+'</div>'; return; }
    var D=j.days; var cur='';
    function fl(d){ var dt=new Date(d.date+'T12:00:00'),L=lang==='ar'?'ar-EG':'en-GB'; return '<button type="button" class="day'+(d.date===cur?' on':'')+'" data-y="'+d.date+'"><span>'+dt.toLocaleDateString(L,{weekday:'short'})+'</span><b>'+num(dt.getDate())+'</b><span>'+dt.toLocaleDateString(L,{month:'short'})+'</span></button>'; }
    function draw(){ var sel=D.filter(function(d){return d.date===cur})[0];
      $('avail').innerHTML='<div class="days">'+D.map(fl).join('')+'</div><div class="slots" style="margin-top:14px">'+(sel?sel.times.map(function(x){return '<button type="button" class="slot'+(x===chosenTime?' on':'')+'" data-t="'+x+'">'+fmtTime(x)+'</button>'}).join(''):'<div class="hint" style="grid-column:1/-1">'+t('pickDay')+'</div>')+'</div>';
      Array.prototype.forEach.call($('avail').querySelectorAll('.day'),function(b){ b.onclick=function(){ cur=b.dataset.y; $('date').value=cur; chosenTime=''; draw(); }; });
      Array.prototype.forEach.call($('avail').querySelectorAll('.slot'),function(b){ b.onclick=function(){ chosenTime=b.dataset.t; draw(); }; }); }
    draw();
  }).catch(function(){ $('avail').innerHTML='<div class="hint">'+t('timesFail')+'</div>'; }); }
function init(){ applyLang(); fetch('/api/book/config').then(function(r){return r.json()}).then(function(c){ cfg=c; if(!c.enabled){ applyLang(); return; } $('step1').style.display='block'; applyLang(); }).catch(function(){ $('sub').textContent=t('eNA'); }); }
$('next').onclick=function(){ $('err1').textContent='';
  if($('name').value.trim().length<3) return $('err1').textContent=t('eName');
  if($('phone').value.replace(/\D/g,'').length<10) return $('err1').textContent=t('ePhone');
  if(!gender) return $('err1').textContent=t('eGender');
  $('next').disabled=true;
  fetch('/api/book/config?name='+encodeURIComponent($('name').value.trim())+'&gender='+gender+'&phone='+encodeURIComponent($('phone').value)).then(function(r){return r.json()}).then(function(c){
    if(!c.enabled||c.locked){ $('err1').textContent=t('eNA'); $('next').disabled=false; return; }
    cfg=c; chosenType=c.types.length===1?c.types[0].key:''; $('step1').style.display='none'; $('form').style.display='block'; setStep(2); applyLang(); window.scrollTo(0,0);
  }).catch(function(){ $('err1').textContent=t('eConn'); $('next').disabled=false; }); };
$('date').onchange=function(){ renderDays(); loadSlots(); };
Array.prototype.forEach.call(document.querySelectorAll('#genderBox .chip'),function(b){ b.onclick=function(){ gender=b.dataset.g; Array.prototype.forEach.call(document.querySelectorAll('#genderBox .chip'),function(x){ x.classList.toggle('on',x===b); }); }; });
$('shot').onchange=function(){ var f=this.files[0]; shotData=null; $('prev').style.display='none'; $('upTxt').textContent=t('up'); if(!f)return;
  var img=new Image(),url=URL.createObjectURL(f); img.onload=function(){ var s=Math.min(1,1400/Math.max(img.width,img.height)),cv=document.createElement('canvas'); cv.width=Math.round(img.width*s); cv.height=Math.round(img.height*s); cv.getContext('2d').drawImage(img,0,0,cv.width,cv.height);
    var u=cv.toDataURL('image/jpeg',0.82); shotData=u.split(',')[1]; shotType='image/jpeg'; $('prev').src=u; $('prev').style.display='block'; $('upTxt').textContent=t('upDone'); URL.revokeObjectURL(url); setStep(3); };
  img.onerror=function(){ $('err').textContent=t('eImg'); }; img.src=url; };
$('go').onclick=function(){ $('err').textContent='';
  if(!chosenType) return $('err').textContent=srv('Please choose a visit type and a doctor.');
  if(!chosenDoc) return $('err').textContent=t('eDoc');
  if(!$('date').value||!chosenTime) return $('err').textContent=t('eTime');
  $('go').disabled=true; $('go').textContent=t('booking');
  fetch('/api/book',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name:$('name').value,gender:gender,phone:$('phone').value,type:chosenType,doctor:chosenDoc,date:$('date').value,time:chosenTime,shotBase64:shotData,shotType:shotType,website:$('website').value})})
  .then(function(r){return r.json().then(function(j){return{ok:r.ok,j:j}})}).then(function(x){
    if(!x.ok){ $('err').textContent=srv(x.j.error||'Something went wrong. Please try again.'); $('go').disabled=false; $('go').textContent=t('go'); if(/no longer|just took/.test(x.j.error||''))loadSlots(); return; }
    var j=x.j; var dd=new Date(j.date+'T12:00:00'); var dtxt=dd.toLocaleDateString(lang==='ar'?'ar-EG':'en-GB',{weekday:'long',day:'numeric',month:'long'});
    $('app').innerHTML='<div class="top"><span></span><button type="button" class="lang" id="langBtn2">'+t('other')+'</button></div><img class="logo" src="/clinic-logo.png" alt="Empower"><div class="card ok"><div class="check">✓</div><h1>'+t('done')+'</h1><div class="sum">'+esc(dname(j.doctor))+'<br>'+esc(dtxt)+' '+t('at')+' '+fmtTime(j.time)+'<br>'+esc(tLabel(typeObj()||{label:j.label}))+'</div><div class="hint">'+(j.package?t('pkg'):t('depRec',{d:num(j.deposit)}))+'</div></div><div class="where">📍 '+t('addr')+'<br><a href="__MAP_URL__">'+t('map')+'</a><br><br>'+t('arrive')+'</div>';
    $('langBtn2').onclick=function(){ lang=lang==='ar'?'en':'ar'; try{localStorage.setItem('bl',lang)}catch(e){} location.reload(); };
  }).catch(function(){ $('err').textContent=t('eConn'); $('go').disabled=false; $('go').textContent=t('go'); }); };
init();
</script></body></html>
`;
app.get('/b', (req, res) => { res.redirect(302, '/book'); });

app.get('/api/booking/stats', requireOwnerOrSecretary, async (req, res) => {
  try {
    const get = async (path) => { const r = await fetch(`${SUPABASE_URL}/rest/v1/${path}`, { headers: bookHeaders() }); const j = await r.json(); return Array.isArray(j) ? j : []; };
    const [opens, leads, deps] = await Promise.all([
      get('login_log?event=eq.page&detail=eq.book&select=created_at&order=created_at.desc&limit=20000'),
      get('booking_leads?select=created_at&order=created_at.desc&limit=20000'),
      get('booking_deposits?select=created_at&order=created_at.desc&limit=20000'),
    ]);
    const now = Date.now(), cairoDay = cairoTodayYmd();
    const sameCairoDay = (iso) => new Date(iso).toLocaleDateString('en-CA', { timeZone: 'Africa/Cairo' }) === cairoDay;
    const within = (iso, days) => now - new Date(iso).getTime() < days * 86400000;
    const pack = (rows) => ({ today: rows.filter(r => sameCairoDay(r.created_at)).length, d7: rows.filter(r => within(r.created_at, 7)).length, d30: rows.filter(r => within(r.created_at, 30)).length, total: rows.length });
    res.json({ opens: pack(opens), started: pack(leads), booked: pack(deps) });
  } catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});

app.get('/book', async (req, res) => {
  logActivity(req, 'page', null, 'book');
  res.set({ 'Content-Type': 'text/html; charset=utf-8', 'X-Robots-Tag': 'noindex, nofollow', 'Cache-Control': 'no-store' }).send(renderClinicPage(BOOK_PAGE, await getClinicConfig()));
});

const INTAKE_PAGE = String.raw`<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>استمارة استقبال — __CLINIC_AR__</title><meta name="robots" content="noindex,nofollow">
<link href="https://fonts.googleapis.com/css2?family=Noto+Naskh+Arabic:wght@400;500;600;700&family=Aref+Ruqaa:wght@700&display=swap" rel="stylesheet">
<style>
  :root{
    --ink:#1b2b2b;
    --paper:#f6f7f5;
    --panel:#ffffff;
    --line:#dfe3df;
    --maroon:#1f5c56;
    --maroon-deep:#123f3a;
    --gold:#b8894f;
    --radius:12px;
  }
  *{box-sizing:border-box;}
  body{
    margin:0;
    background:var(--paper);
    color:var(--ink);
    font-family:"Noto Naskh Arabic",serif;
    display:flex;
    align-items:center;
    justify-content:center;
    min-height:100vh;
    padding:20px;
  }
  .card{
    background:var(--panel);
    border:2px solid var(--gold);
    border-radius:var(--radius);
    max-width:420px;
    width:100%;
    padding:28px 24px;
  }
  .logo{
    font-family:'Aref Ruqaa',serif;
    font-weight:700;
    font-size:2.2rem;
    color:var(--maroon);
    text-align:center;
    margin-bottom:4px;
  }
  .tag{
    text-align:center;
    color:#5b6863;
    font-size:0.9rem;
    margin-bottom:20px;
  }
  label{
    display:block;
    font-size:0.85rem;
    color:#5b6863;
    margin-bottom:6px;
    margin-top:14px;
  }
  input, textarea, select{
    width:100%;
    padding:12px 14px;
    border:1px solid var(--line);
    border-radius:var(--radius);
    background:var(--paper);
    font-size:0.95rem;
    font-family:inherit;
  }
  textarea{ min-height:90px; resize:vertical; }
  button{
    width:100%;
    margin-top:22px;
    padding:13px;
    border:none;
    border-radius:var(--radius);
    background:var(--maroon);
    color:#fff;
    font-size:1rem;
    font-weight:700;
    cursor:pointer;
    font-family:inherit;
  }
  button:disabled{ background:#a9b6b2; cursor:not-allowed; }
  #status{
    margin-top:14px;
    font-size:0.85rem;
    color:#5b6863;
    text-align:center;
  }
  #successBox{
    display:none;
    text-align:center;
    padding:20px 0;
  }
  #successBox .check{ font-size:3rem; margin-bottom:10px; }
</style>
</head>
<body>

<div class="card">
  <div class="logo">مُساعِد</div>
  <div class="tag">__CLINIC_AR__ — استمارة استقبال قبل الكشف</div>

  <div id="formBox">
    <label for="nameInput">الاسم بالكامل</label>
    <input type="text" id="nameInput" placeholder="مثال: محمد أحمد">

    <label for="phoneInput">رقم الموبايل</label>
    <input type="tel" id="phoneInput" placeholder="مثال: 01012345678">

    <label for="complaintInput">الشكوى الأساسية (السبب اللي جاي عشانه)</label>
    <textarea id="complaintInput" placeholder="مثال: ألم في الركبة اليمين من حوالي أسبوعين"></textarea>

    <label for="referralInput">عرفت عن العيادة إزاي؟</label>
    <input type="text" id="referralInput" placeholder="مثال: صديق قاللي عليها">

    <button type="button" id="submitBtn">إرسال</button>
    <div id="status"></div>
  </div>

  <div id="successBox">
    <div class="check">✅</div>
    <div style="font-size:1.05rem;font-weight:600;color:var(--maroon);">تم الإرسال بنجاح</div>
    <div style="font-size:0.85rem;color:#5b6863;margin-top:6px;">شكرًا ليك، البيانات وصلت للعيادة. نشوفك قريب!</div>
  </div>
</div>

<script>
const BACKEND_URL = '';

document.getElementById('submitBtn').addEventListener('click', async () => {
  const name = document.getElementById('nameInput').value.trim();
  const phone = document.getElementById('phoneInput').value.trim();
  const complaint = document.getElementById('complaintInput').value.trim();
  const referral = document.getElementById('referralInput').value;
  const statusEl = document.getElementById('status');
  const btn = document.getElementById('submitBtn');

  if(!name || !phone){
    statusEl.textContent = 'من فضلك اكتب الاسم ورقم الموبايل.';
    statusEl.style.color = '#a33d3d';
    return;
  }

  btn.disabled = true;
  statusEl.textContent = 'جاري الإرسال…';
  statusEl.style.color = '#5b6863';

  try{
    const res = await fetch(BACKEND_URL + '/api/intake', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ patientName: name, patientPhone: phone, chiefComplaint: complaint, referralSource: referral })
    });
    if(!res.ok) throw new Error('Server error ' + res.status);
    document.getElementById('formBox').style.display = 'none';
    document.getElementById('successBox').style.display = 'block';
  }catch(e){
    console.error(e);
    statusEl.textContent = 'حصل خطأ أثناء الإرسال، حاول تاني.';
    statusEl.style.color = '#a33d3d';
    btn.disabled = false;
  }
});
</script>

</body>
</html>
`;

app.get('/intake', async (req, res) => {
  const c = await getClinicConfig();
  const nm = clinicEsc(c.name_ar || c.name);
  res.set({ 'Content-Type': 'text/html; charset=utf-8', 'X-Robots-Tag': 'noindex, nofollow', 'Cache-Control': 'no-store' }).send(INTAKE_PAGE.replace(/__CLINIC_AR__/g, nm));
});


// ---- Public links page (like Linktree) at /links ----
const LINKS_JS = String.raw`function cp(b){var n=b.getAttribute('data-n');var done=function(){var o=b.textContent;b.textContent='Copied \u2713';setTimeout(function(){b.textContent=o},1500)};function fb(){var t=document.createElement('textarea');t.value=n;document.body.appendChild(t);t.select();try{document.execCommand('copy')}catch(e){}document.body.removeChild(t);done()}if(navigator.clipboard&&navigator.clipboard.writeText){navigator.clipboard.writeText(n).then(done,fb)}else{fb()}}`;
function renderLinksPage(c) {
  const nm = clinicEsc(c.name), tag = clinicEsc(c.tagline || '');
  const btn = (label, url) => '<a class="b" href="' + clinicEsc(url) + '" target="_blank" rel="noopener">' + clinicEsc(label) + '</a>';
  const rows = [];
  rows.push(btn('Book online', '/book'));
  const tel = String(c.phone || '').replace(/[^0-9+]/g, '');
  if (tel) rows.push('<div class="b"><div>For Reservations</div><div class="ph">' + clinicEsc(String(c.phone).trim()) + '</div><div class="act"><a class="ab" href="tel:' + clinicEsc(tel) + '">Call</a><button type="button" class="ab" data-n="' + clinicEsc(String(c.phone).trim()) + '" onclick="cp(this)">Copy number</button></div></div>');
  (Array.isArray(c.links) ? c.links : []).forEach((l) => { const u = safeLinkUrl(l && l.url); if (u && l.label) rows.push(btn(l.label, u)); });
  const addr = c.address || c.address_ar || '';
  const loc = addr ? '<div class="h">&#128205; Our Location</div><a class="b loc" href="' + clinicEsc(safeLinkUrl(c.map_url) || '#') + '" target="_blank" rel="noopener">' + clinicEsc(addr) + '</a>' : '';
  return '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>' + nm + '</title>' +
    '<style>*{box-sizing:border-box}body{margin:0;background:#e9ecef;font-family:-apple-system,Segoe UI,Roboto,Arial,sans-serif;color:#111;min-height:100vh}' +
    '.w{max-width:560px;margin:0 auto;padding:36px 16px 48px;text-align:center}.logo{width:84%;max-width:340px;height:auto;border-radius:18px;display:block;margin:10px auto 22px;box-shadow:0 2px 8px rgba(0,0,0,.12)}' +
    'h1{font-size:1.05rem;margin:0 0 26px;font-weight:600}.tag{font-size:1.15rem;margin:6px 0 30px}.b{display:block;background:#fff;border-radius:12px;padding:20px 16px;margin:0 0 14px;color:#111;text-decoration:none;font-weight:600;box-shadow:0 1px 3px rgba(0,0,0,.08)}' +
    '.ph{display:block;margin-top:6px;font-size:1.25rem;font-weight:700;letter-spacing:.5px;direction:ltr}.act{display:flex;gap:10px;margin-top:14px}.ab{flex:1;background:#eef1f4;border:0;border-radius:10px;padding:12px 8px;font:inherit;font-weight:600;color:#111;text-decoration:none;cursor:pointer;text-align:center}.b:active{transform:scale(.99)}.h{font-weight:700;margin:26px 0 12px}.loc{font-weight:500;text-align:left}</style></head><body><div class="w">' +
    '<img class="logo" src="/clinic-logo.png" alt="' + nm + '">' + (tag ? '<p class="tag">' + tag + '</p>' : '') + rows.join('') + loc + '</div><script>' + LINKS_JS + '</script></body></html>';
}
app.get(['/links', '/l'], async (req, res) => {
  logActivity(req, 'page', null, 'links');
  res.set({ 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' }).send(renderLinksPage(await getClinicConfig()));
});

// ---- Friendly payment page at /pay (opened from the InstaPay WhatsApp message) ----
app.get('/pay', async (req, res) => {
  logActivity(req, 'page', null, 'pay');
  const c = await getClinicConfig();
  const nm = clinicEsc(c.name);
  const q = (k, n) => clinicEsc(clinicText(req.query[k], n).trim());
  const who = q('n', 40).split(' ')[0];
  const amtRaw = String(req.query.a || '').trim();
  const amt = /^[0-9][0-9.,]{0,9}$/.test(amtRaw) ? clinicEsc(amtRaw) : '';
  const why = q('r', 40);
  const payUrl = safeLinkUrl(c.instapay_url);
  const handle = clinicEsc(c.instapay_handle || '');
  const tel = String(c.phone || '').replace(/[^0-9]/g, '');
  const waNum = tel.length === 11 && tel.startsWith('0') ? '2' + tel : tel;
  const addr = clinicEsc(c.address || c.address_ar || '');
  const html = '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex"><title>' + nm + '</title>' +
    '<style>*{box-sizing:border-box}body{margin:0;background:#e9ecef;font-family:-apple-system,Segoe UI,Roboto,Cairo,Arial,sans-serif;color:#111}.w{max-width:520px;margin:0 auto;padding:28px 16px 44px;text-align:center}' +
    '.logo{width:70%;max-width:280px;height:auto;border-radius:16px;display:block;margin:6px auto 18px;box-shadow:0 2px 8px rgba(0,0,0,.12)}h1{font-size:1.35rem;margin:6px 0 4px}.sub{color:#4b5563;margin:0 0 4px;font-size:.98rem;line-height:1.5}' +
    '.card{background:#fff;border-radius:14px;padding:16px;margin:14px 0;box-shadow:0 1px 3px rgba(0,0,0,.08);text-align:left}.amt{text-align:center}.amt .n{font-size:2rem;font-weight:800;color:#1f5c56;direction:ltr}.amt .l{color:#6b7280;font-size:.85rem}' +
    '.st{display:flex;gap:12px;align-items:flex-start;margin:10px 0;line-height:1.45}.st b{flex:0 0 28px;height:28px;border-radius:50%;background:#1f5c56;color:#fff;display:flex;align-items:center;justify-content:center;font-size:.9rem}' +
    '.go{display:block;background:#1f5c56;color:#fff;text-decoration:none;font-weight:700;font-size:1.05rem;padding:16px;border-radius:12px;margin:16px 0 10px}.sec{display:block;background:#fff;color:#111;text-decoration:none;font-weight:600;padding:14px;border-radius:12px;margin:10px 0;box-shadow:0 1px 3px rgba(0,0,0,.08);border:0;width:100%;font:inherit;cursor:pointer}' +
    '.hd{direction:ltr;font-weight:700;font-size:1.1rem;margin:4px 0 10px;word-break:break-all}.ft{color:#6b7280;font-size:.82rem;margin-top:24px;line-height:1.5}</style></head><body><div class="w">' +
    '<img class="logo" src="/clinic-logo.png" alt="' + nm + '">' +
    '<h1>Hi' + (who ? ' ' + who : '') + ' &#128075;</h1><p class="sub">Thank you for choosing ' + nm + '.<br>Paying takes less than a minute.</p>' +
    '<p class="sub" dir="rtl">أهلاً بيك' + (who ? ' ' + who : '') + '، شكراً لاختيارك ' + nm + '. الدفع بياخد أقل من دقيقة.</p>' +
    (amt ? '<div class="card amt"><div class="l">Amount to pay &middot; المبلغ المطلوب</div><div class="n">' + amt + ' EGP</div>' + (why ? '<div class="l">' + why + '</div>' : '') + '</div>' : '') +
    '<div class="card"><div class="st"><b>1</b><div>Tap <b style="display:inline;background:none;color:inherit;width:auto;height:auto">Pay with InstaPay</b> below. Your InstaPay app will open.</div></div>' +
    '<div class="st"><b>2</b><div>Check the details and send the payment' + (amt ? ' (' + amt + ' EGP)' : '') + '.</div></div>' +
    '<div class="st"><b>3</b><div>Send us a screenshot of the receipt on WhatsApp so we can confirm it.</div></div></div>' +
    (payUrl ? '<a class="go" href="' + clinicEsc(payUrl) + '">Pay with InstaPay</a>' : '') +
    (handle ? '<div class="card" style="text-align:center"><div class="l" style="color:#6b7280;font-size:.85rem">Or send to this InstaPay address</div><div class="hd">' + handle + '</div><button type="button" class="sec" style="box-shadow:none;background:#eef1f4;margin:0" data-n="' + handle + '" onclick="cp(this)">Copy address</button></div>' : '') +
    (waNum ? '<a class="sec" href="https://wa.me/' + waNum + '" target="_blank" rel="noopener">Send the receipt on WhatsApp</a>' : '') +
    '<div class="ft">' + nm + (addr ? '<br>' + addr : '') + '</div></div><script>' + LINKS_JS + '</script></body></html>';
  res.set({ 'Content-Type': 'text/html; charset=utf-8', 'X-Robots-Tag': 'noindex, nofollow', 'Cache-Control': 'no-store' }).send(html);
});


// ---- HR: leave decisions (owner only) ----
// "unavailable" days from the calendar count as leave automatically; this table stores what the owner decides
// for scheduled days with no patients: kind = leave | worked | closed.
app.get('/api/hr/leaves', requireOwnerDoctor, async (req, res) => {
  try {
    const { start, end } = req.query;
    let url = `${SUPABASE_URL}/rest/v1/doctor_leaves?order=date.asc&limit=5000`;
    if (start && end) url += `&date=gte.${encodeURIComponent(start)}&date=lte.${encodeURIComponent(end)}`;
    const r = await fetch(url, { headers: bookHeaders() });
    res.status(r.status).type('application/json').send(await r.text());
  } catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});
app.post('/api/hr/leaves', requireOwnerDoctor, async (req, res) => {
  const b = req.body || {};
  const name = clinicText(b.doctorName, 80).trim(), date = String(b.date || '');
  const kind = ['leave', 'worked', 'closed'].includes(b.kind) ? b.kind : '';
  if (!name || !/^\d{4}-\d{2}-\d{2}$/.test(date) || !kind) return res.status(400).json({ error: 'Missing doctor, date or kind.' });
  try {
    const r = await fetch(`${SUPABASE_URL}/rest/v1/doctor_leaves?on_conflict=doctor_name,date`, { method: 'POST', headers: { ...bookHeaders(), 'Content-Type': 'application/json', Prefer: 'return=representation,resolution=merge-duplicates' }, body: JSON.stringify({ doctor_name: name, date, kind, note: clinicText(b.note, 200).trim() || null, created_by: req.doctor.name || req.doctor.email }) });
    const j = await r.json();
    if (!r.ok) throw new Error(JSON.stringify(j));
    res.json(Array.isArray(j) ? j[0] : j);
  } catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});
app.delete('/api/hr/leaves/:id', requireOwnerDoctor, async (req, res) => {
  try {
    await fetch(`${SUPABASE_URL}/rest/v1/doctor_leaves?id=eq.${encodeURIComponent(req.params.id)}`, { method: 'DELETE', headers: bookHeaders() });
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});

// ---- Fixed monthly costs (rent, doorman...) -> added to Expenses once per month ----
// Each cost is added as a normal expense dated the LAST DAY of the month, described "Fixed: <name>".
// Payroll, Net Cash and Net InstaPay then count it like any other expense. Adding twice is safe.
async function applyFixedCostsForMonth(ym, createdBy) {
  const c = await getClinicConfig(true);
  const list = c.fixed_costs || [];
  if (!list.length || !/^\d{4}-\d{2}$/.test(ym)) return { added: 0, total: list.length };
  const [y, m] = ym.split('-').map(Number);
  const first = `${ym}-01`, lastDay = new Date(Date.UTC(y, m, 0)).getUTCDate();
  const last = `${ym}-${String(lastDay).padStart(2, '0')}`;
  const h = { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}`, 'Content-Type': 'application/json' };
  const er = await fetch(`${SUPABASE_URL}/rest/v1/expenses?select=description&expense_date=gte.${first}&expense_date=lte.${last}&description=like.Fixed:*`, { headers: h });
  const existing = new Set((await er.json().catch(() => [])).map((e) => String(e.description || '').toLowerCase()));
  let added = 0;
  for (const f of list) {
    const desc = `Fixed: ${f.name}`;
    if (existing.has(desc.toLowerCase())) continue;
    const ir = await fetch(`${SUPABASE_URL}/rest/v1/expenses`, { method: 'POST', headers: h, body: JSON.stringify({ description: desc, amount: f.amount, expense_date: last, payment_method: f.method === 'instapay' ? 'instapay' : 'cash', created_by: createdBy || 'Fixed costs (auto)' }) });
    if (ir.ok) added++; else console.error('fixed cost insert failed', ir.status, await ir.text().catch(() => ''));
  }
  return { added, total: list.length };
}
app.post('/api/fixed-costs/apply', requireFinanceAccess, async (req, res) => {
  try {
    const ym = String((req.body && req.body.month) || '').slice(0, 7);
    if (!/^\d{4}-\d{2}$/.test(ym)) return res.status(400).json({ error: 'Bad month.' });
    res.json(await applyFixedCostsForMonth(ym, req.doctor.name || req.doctor.email));
  } catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});
async function autoFixedCosts() {
  try {
    const today = cairoTodayYmd();
    const tomorrow = new Date(Date.parse(today + 'T00:00:00Z') + 86400000).toISOString().slice(0, 10);
    if (tomorrow.slice(0, 7) !== today.slice(0, 7)) await applyFixedCostsForMonth(today.slice(0, 7), 'Fixed costs (auto)');
  } catch (e) { console.error('auto fixed costs failed', e.message); }
}
if (SUPABASE_URL && SUPABASE_SERVICE_KEY) { setTimeout(autoFixedCosts, 120000); setInterval(autoFixedCosts, 3 * 3600000); }

// Keep-alive: a tiny daily database request so a free Supabase project is never paused for inactivity
if (SUPABASE_URL && SUPABASE_SERVICE_KEY) {
  const dbKeepAlive = () => fetch(`${SUPABASE_URL}/rest/v1/booking_settings?select=id&limit=1`, { headers: bookHeaders() }).catch(() => {});
  setTimeout(dbKeepAlive, 60000);
  setInterval(dbKeepAlive, 12 * 3600000);
}

app.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`);
});
