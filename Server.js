const express = require('express');
const cors = require('cors');
const app = express();

app.use(cors({ origin: "*", methods: ["GET","POST","OPTIONS"], allowedHeaders: ["Content-Type"] }));
app.options("*", cors());
app.use(express.json());

// ---- FLAGS (never sent to client) ----
const FLAGS = {
  1: "ictp{shift_three_is_the_key}",
  2: "ictp{s0urce_c0de_never_lies}",
  3: "ictp{ascii_then_base64_chain}",
};

const SECRET_PASS = "Secretpassword";

// rate limit: 20 tries per IP per 10 min
const attempts = new Map();
function rateLimit(ip) {
  const now = Date.now();
  const entry = attempts.get(ip) || { count: 0, reset: now + 10 * 60 * 1000 };
  if (now > entry.reset) { entry.count = 0; entry.reset = now + 10 * 60 * 1000; }
  entry.count++;
  attempts.set(ip, entry);
  return entry.count > 20;
}

// POST /check  { challenge: 1|2|3, answer: "..." }
app.post('/check', (req, res) => {
  const ip = req.ip;
  if (rateLimit(ip)) {
    return res.status(429).json({ ok: false, msg: 'Too many attempts — wait 10 minutes' });
  }

  const { challenge, answer } = req.body;
  const n = parseInt(challenge);
  if (![1, 2, 3].includes(n) || typeof answer !== 'string') {
    return res.status(400).json({ ok: false, msg: 'Bad request' });
  }

  const correct = FLAGS[n].toLowerCase() === answer.trim().toLowerCase();
  res.json({ ok: correct, msg: correct ? 'correct' : 'wrong' });
});

// POST /complete  { keys: { 1: "flag1", 2: "flag2", 3: "flag3" } }
// ใช้ flag ที่ user กรอกมาเป็น key ตรวจกับ FLAG จริงทั้ง 3 ข้อ
app.post('/complete', (req, res) => {
  const { keys } = req.body;
  if (!keys || typeof keys !== 'object') {
    return res.status(400).json({ ok: false });
  }

  const allCorrect = [1, 2, 3].every(n =>
    typeof keys[n] === 'string' &&
    keys[n].trim().toLowerCase() === FLAGS[n].toLowerCase()
  );

  if (allCorrect) {
    return res.json({ ok: true, secret: SECRET_PASS });
  }
  res.status(403).json({ ok: false, msg: 'Invalid keys' });
});

// GET /challenges → ciphertext only, no flags
app.get('/challenges', (req, res) => {
  res.json([
    {
      id: 1,
      title: "Caesar's Shift",
      tags: ["Caesar Cipher", "100 pts"],
      ciphertext: "WKH VHFUHW LV KLGGHQ LQ WKH YDXOW. IODJ: lfws{vkliw_wkuhh_lv_wkh_nhb}",
      hint: "ROT3"
    },
    {
      id: 2,
      title: "Hidden in the Source",
      tags: ["JS Recon", "100 pts"],
      code: [
        "// internal auth util — do not expose",
        "const _0x3f2a = [102,88,78,108,97,87,120,102,99,109,86,50,90,87,53,102,90,87,81,119,89,49,57,108,89,51,74,49,77,72,78,55,99,72,82,106,97,81,61,61];",
        "function _decode(arr) { return arr.map(c => String.fromCharCode(c)).join(''); }",
        "function _extract(s) { return atob(s).split('').reverse().join(''); }",
        "const _seed = _extract(_decode(_0x3f2a));",
        "function verifyToken(tok) { return tok === _seed; }"
      ],
      hint: "trace: _0x3f2a → _decode() → _extract() → _seed"
    },
    {
      id: 3,
      title: "ASCII & Base64 Stack",
      tags: ["Encoding", "100 pts"],
      ciphertext: "97 87 78 48 99 72 116 104 99 50 78 112 97 86 57 48 97 71 86 117 88 50 74 104 99 50 85 50 78 70 57 106 97 71 70 112 98 110 48 61",
      hint: "decimal → chr() → base64 → decode"
    }
  ]);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`CTF backend running on port ${PORT}`));