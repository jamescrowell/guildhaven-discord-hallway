import 'dotenv/config';
import express from 'express';
import crypto from 'crypto';

const app = express();

// If you want to receive JSON from other routes later, keep this:
app.use(express.json());

// -------------------- ENV --------------------
const {
  PORT = 3000,
  BASE_URL,
  DISCORD_CLIENT_ID,
  DISCORD_CLIENT_SECRET,
  DISCORD_REDIRECT_URI,
  DISCORD_GUILD_ID,
  DISCORD_BOT_TOKEN,
  STATE_SECRET,

  ROLE_FREE,
  ROLE_APPRENTICE,
  ROLE_JOURNEYMAN,
  ROLE_MASTER,
  ROLE_GRANDMASTER,

  ZAPIER_WEBHOOK_URL,
  SUCCESS_REDIRECT_URL
} = process.env;

const REQUIRED = [
  'BASE_URL',
  'DISCORD_CLIENT_ID',
  'DISCORD_CLIENT_SECRET',
  'DISCORD_REDIRECT_URI',
  'DISCORD_GUILD_ID',
  'DISCORD_BOT_TOKEN',
  'STATE_SECRET'
];

for (const k of REQUIRED) {
  if (!process.env[k]) {
    console.error(`Missing env var: ${k}`);
    process.exit(1);
  }
}

// -------------------- ROLE MAP --------------------
const ROLE_MAP = {
  free: ROLE_FREE,
  apprentice: ROLE_APPRENTICE,
  journeyman: ROLE_JOURNEYMAN,
  master: ROLE_MASTER,
  grandmaster: ROLE_GRANDMASTER
};

const TIER_ROLES = [
  ROLE_FREE,
  ROLE_APPRENTICE,
  ROLE_JOURNEYMAN,
  ROLE_MASTER,
  ROLE_GRANDMASTER
].filter(Boolean); // removes undefined if you haven't filled all yet

function normalizeTier(tier) {
  return String(tier || '').trim().toLowerCase();
}

// -------------------- STATE SIGNING (SECURITY) --------------------
// We embed tier/email/etc in "state" and SIGN it with HMAC.
// That means if someone edits tier=grandmaster, the signature breaks.

function base64urlEncode(str) {
  return Buffer.from(str)
    .toString('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
}

function base64urlDecode(b64url) {
  const b64 = b64url.replace(/-/g, '+').replace(/_/g, '/');
  // pad to multiple of 4
  const pad = b64.length % 4 === 0 ? '' : '='.repeat(4 - (b64.length % 4));
  return Buffer.from(b64 + pad, 'base64').toString('utf8');
}

function signState(payloadObj) {
  const payload = base64urlEncode(JSON.stringify(payloadObj));
  const sig = crypto
    .createHmac('sha256', STATE_SECRET)
    .update(payload)
    .digest('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
  return `${payload}.${sig}`;
}

function verifyState(state) {
  if (!state || !state.includes('.')) return null;

  const [payload, sig] = state.split('.');
  const expected = crypto
    .createHmac('sha256', STATE_SECRET)
    .update(payload)
    .digest('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');

  // constant-time compare to avoid timing attacks
  if (sig.length !== expected.length) return null;
  const ok = crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected));
  if (!ok) return null;

  try {
    return JSON.parse(base64urlDecode(payload));
  } catch {
    return null;
  }
}

// -------------------- HTML HELPERS --------------------
function page(title, msg) {
  return `<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>${title}</title>
  <style>
    body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial; padding:40px; line-height:1.5}
    .card{max-width:720px; border:1px solid #ddd; border-radius:16px; padding:24px}
    code{background:#f6f6f6; padding:2px 6px; border-radius:6px}
  </style>
</head>
<body>
  <div class="card">
    <h2>${title}</h2>
    <p>${msg}</p>
  </div>
</body>
</html>`;
}

// -------------------- DISCORD API HELPERS --------------------
async function discordFetch(url, options = {}) {
  const res = await fetch(url, options);
  const text = await res.text();
  let json;
  try { json = text ? JSON.parse(text) : null; } catch { json = null; }

  if (!res.ok) {
    const err = new Error(`Discord API error ${res.status} ${res.statusText}`);
    err.status = res.status;
    err.bodyText = text;
    err.bodyJson = json;
    throw err;
  }
  return json;
}

async function exchangeCodeForToken(code) {
  const params = new URLSearchParams();
