// Qalam PT Scribe — backend proxy
//
// This server sits between the app (hosted on GitHub Pages) and the AI
// services (Deepgram, Anthropic, Gemini). The app never sees the real API
// keys — it only talks to this server, and this server holds the real
// keys as environment variables (set in Render's dashboard, never in code).
//
// Two endpoints:
//   POST /api/transcribe   — forwards audio to Deepgram, returns the JSON result
//   POST /api/ai           — forwards a note-generation/correction request to
//                             Claude or Gemini, returns { text: "..." }
//
// A simple shared-secret header protects both endpoints so a stranger who
// finds your app's URL can't rack up usage on your keys. This is NOT full
// per-doctor login — it's one shared password for the whole clinic, good
// enough for a pilot. Real per-doctor Google login is a future upgrade.

const express = require('express');
const cors = require('cors');

const app = express();

// ---- Config from environment variables (set these in Render's dashboard) ----
const DEEPGRAM_API_KEY = process.env.DEEPGRAM_API_KEY || '';
const ANTHROPIC_API_KEY = process.env.ANTHROPIC_API_KEY || '';
const GEMINI_API_KEY = process.env.GEMINI_API_KEY || '';
const CLINIC_SECRET = process.env.CLINIC_SECRET || '';
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || '*';

// ---- Middleware ----
app.use(cors({ origin: ALLOWED_ORIGIN }));

function checkClinicSecret(req, res, next) {
  if (!CLINIC_SECRET) {
    // No secret configured yet — allow through, but this should be set
    // before real use so strangers can't use your keys for free.
    return next();
  }
  const provided = req.header('x-clinic-secret');
  if (provided !== CLINIC_SECRET) {
    return res.status(401).json({ error: 'Invalid or missing clinic secret.' });
  }
  next();
}

// ---- POST /api/transcribe ----
// The app sends the raw audio bytes as the request body, plus the same
// query params it used to send directly to Deepgram (language, keyterm,
// diarize_model, paragraphs, utterances, punctuate, smart_format).
app.post(
  '/api/transcribe',
  checkClinicSecret,
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
        headers: {
          Authorization: `Token ${DEEPGRAM_API_KEY}`,
          'Content-Type': contentType,
        },
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

// ---- POST /api/ai ----
// Body: { systemPrompt, userContent, maxTokens, provider: 'anthropic'|'gemini' }
// Returns: { text: "..." }
app.use(express.json({ limit: '10mb' }));

app.post('/api/ai', checkClinicSecret, async (req, res) => {
  const { systemPrompt, userContent, maxTokens, provider } = req.body || {};
  if (!systemPrompt || !userContent) {
    return res.status(400).json({ error: 'Missing systemPrompt or userContent.' });
  }
  const tokens = maxTokens || 4000;

  try {
    if (provider === 'gemini') {
      if (!GEMINI_API_KEY) {
        return res.status(500).json({ error: 'Server is missing GEMINI_API_KEY.' });
      }
      const url = `https://generativelanguage.googleapis.com/v1beta/models/gemini-3.6-flash:generateContent?key=${encodeURIComponent(
        GEMINI_API_KEY
      )}`;
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
      if (!upstream.ok) {
        return res.status(upstream.status).json({ error: JSON.stringify(data).slice(0, 300) });
      }
      const text = (data?.candidates?.[0]?.content?.parts || []).map((p) => p.text || '').join('');
      return res.json({ text });
    } else {
      if (!ANTHROPIC_API_KEY) {
        return res.status(500).json({ error: 'Server is missing ANTHROPIC_API_KEY.' });
      }
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
      if (!upstream.ok) {
        return res.status(upstream.status).json({ error: JSON.stringify(data).slice(0, 300) });
      }
      const text = (data.content || [])
        .filter((b) => b.type === 'text')
        .map((b) => b.text)
        .join('');
      return res.json({ text });
    }
  } catch (err) {
    console.error('AI proxy error:', err);
    res.status(500).json({ error: 'AI proxy failed: ' + err.message });
  }
});

// ---- Health check (for Render, and for you to confirm it's alive) ----
app.get('/', (req, res) => {
  res.send('Qalam PT Scribe backend is running.');
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`);
});
