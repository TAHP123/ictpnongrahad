const express = require('express');
const cors = require('cors');
const app = express();

app.use(cors({ origin: "*", methods: ["GET","POST","OPTIONS"], allowedHeaders: ["Content-Type"] }));
app.options("*", cors());
app.use(express.json());

const FLAGS = {
  1: "ictp{shift_three_is_the_key}",
  2: "ictp{s0urce_c0de_never_lies}",
  3: "ictp{ascii_then_base64_chain}",
};
const SECRET_PASS = "Are you Robot?";

const attempts = new Map();
function rateLimit(ip) {
  const now = Date.now();
  const entry = attempts.get(ip) || { count: 0, reset: now + 10 * 60 * 1000 };
  if (now > entry.reset) { entry.count = 0; entry.reset = now + 10 * 60 * 1000; }
  entry.count++;
  attempts.set(ip, entry);
  return entry.count > 20;
}

app.post('/api/check', (req, res) => {
  if (rateLimit(req.ip)) return res.status(429).json({ ok: false, msg: 'Too many attempts' });
  const { challenge, answer } = req.body;
  const n = parseInt(challenge);
  if (![1,2,3].includes(n) || typeof answer !== 'string') return res.status(400).json({ ok: false });
  const correct = FLAGS[n].toLowerCase() === answer.trim().toLowerCase();
  res.json({ ok: correct });
});

app.post('/api/complete', (req, res) => {
  const { keys } = req.body;
  if (!keys) return res.status(400).json({ ok: false });
  const allCorrect = [1,2,3].every(n =>
    typeof keys[n] === 'string' && keys[n].trim().toLowerCase() === FLAGS[n].toLowerCase()
  );
  if (allCorrect) return res.json({ ok: true, secret: SECRET_PASS });
  res.status(403).json({ ok: false });
});

app.get('/api/challenges', (req, res) => {
  res.json([
    { id: 1, title: "Caesar's Shift", ciphertext: "WKH VHFUHW LV KLGGHQ LQ WKH YDXOW. IODJ: lfws{vkliw_wkuhh_lv_wkh_nhb}", hint: "ROT3" },
    { id: 2, title: "Hidden in the Source", hint: "trace: _0x3f2a → _decode() → _extract() → _seed" },
    { id: 3, title: "ASCII & Base64 Stack", ciphertext: "97 87 78 48 99 72 116 104 99 50 78 112 97 86 57 48 97 71 86 117 88 50 74 104 99 50 85 50 78 70 57 106 97 71 70 112 98 110 48 61", hint: "decimal → chr() → base64 → decode" }
  ]);
});

module.exports = app;