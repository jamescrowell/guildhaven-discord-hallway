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
  params.set('client_id', DISCORD_CLIENT_ID);
  params.set('client_secret', DISCORD_CLIENT_SECRET);
  params.set('grant_type', 'authorization_code');
  params.set('code', code);
  params.set('redirect_uri', DISCORD_REDIRECT_URI);

  const token = await discordFetch('https://discord.com/api/oauth2/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: params
  });

  return token; // { access_token, token_type, expires_in, refresh_token, scope }
}

async function getDiscordUser(accessToken) {
  return await discordFetch('https://discord.com/api/users/@me', {
    headers: { Authorization: `Bearer ${accessToken}` }
  });
}

async function addUserToGuild({ userId, accessToken }) {
  // Requires OAuth scope: guilds.join
  // Requires bot token with permissions to add members via API (it uses bot authorization)
  return await discordFetch(`https://discord.com/api/guilds/${DISCORD_GUILD_ID}/members/${userId}`, {
    method: 'PUT',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bot ${DISCORD_BOT_TOKEN}`
    },
    body: JSON.stringify({ access_token: accessToken })
  });
}

async function addRoleToMember({ userId, roleId }) {
  return await discordFetch(
    `https://discord.com/api/guilds/${DISCORD_GUILD_ID}/members/${userId}/roles/${roleId}`,
    {
      method: 'PUT',
      headers: { Authorization: `Bot ${DISCORD_BOT_TOKEN}` }
    }
  );
}

async function removeRoleFromMember({ userId, roleId }) {
  return await discordFetch(
    `https://discord.com/api/guilds/${DISCORD_GUILD_ID}/members/${userId}/roles/${roleId}`,
    {
      method: 'DELETE',
      headers: { Authorization: `Bot ${DISCORD_BOT_TOKEN}` }
    }
  );
}

async function postToZapier(payload) {
  if (!ZAPIER_WEBHOOK_URL) return;
  try {
    await fetch(ZAPIER_WEBHOOK_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
  } catch (e) {
    // Don't fail the whole auth flow if Zapier logging fails
    console.warn('Zapier webhook failed:', e?.message || e);
  }
}

// -------------------- ROUTES --------------------

// Quick sanity route
app.get('/health', (req, res) => res.json({ ok: true }));

/**
 * START ROUTE
 * Example:
 * /discord/start?tier=apprentice&email=test@email.com
 */
app.get('/discord/start', (req, res) => {
  const tier = normalizeTier(req.query.tier);
  const email = String(req.query.email || '').trim();

  if (!tier || !ROLE_MAP[tier]) {
    return res.status(400).send(page('Missing or invalid tier', 'Use a valid tier like <code>free</code>, <code>apprentice</code>, <code>journeyman</code>, <code>master</code>, <code>grandmaster</code>.'));
  }

  // email is optional but recommended for logging
  // If you want to require it, uncomment:
  // if (!email) return res.status(400).send(page('Missing email', 'You must include <code>email=</code> in the link.'));

  // Prevent replay attacks: include timestamp + nonce
  const statePayload = {
    tier,
    email,
    ts: Date.now(),
    nonce: crypto.randomBytes(16).toString('hex')
  };

  const state = signState(statePayload);

  const auth = new URL('https://discord.com/api/oauth2/authorize');
  auth.searchParams.set('client_id', DISCORD_CLIENT_ID);
  auth.searchParams.set('redirect_uri', DISCORD_REDIRECT_URI);
  auth.searchParams.set('response_type', 'code');
  auth.searchParams.set('scope', 'identify guilds.join');
  auth.searchParams.set('state', state);
  auth.searchParams.set('prompt', 'consent');

  // Send user to Discord
  res.redirect(auth.toString());
});

/**
 * CALLBACK ROUTE
 * Discord redirects here after the user approves.
 */
app.get('/discord/callback', async (req, res) => {
  const { code, state, error } = req.query;

  if (error) {
    return res.status(400).send(page('Discord authorization failed', `Discord returned error: <code>${String(error)}</code>`));
  }

  if (!code || !state) {
    return res.status(400).send(page('Missing code/state', 'This callback is incomplete. Please try again from the email link.'));
  }

  const payload = verifyState(String(state));
  if (!payload) {
    return res.status(400).send(page('Invalid state', 'Security check failed (state signature invalid). Please restart from the email link.'));
  }

  // Optional expiration window for state (ex: 15 minutes)
  const MAX_AGE_MS = 15 * 60 * 1000;
  if (Date.now() - payload.ts > MAX_AGE_MS) {
    return res.status(400).send(page('Link expired', 'This onboarding link expired. Please request a fresh one.'));
  }

  const tier = normalizeTier(payload.tier);
  const email = payload.email || '';
  const roleId = ROLE_MAP[tier];

  if (!roleId) {
    return res.status(400).send(page('Tier not configured', `No role configured for tier <code>${tier}</code>.`));
  }

  try {
    // 1) code -> token
    const token = await exchangeCodeForToken(String(code));
    const accessToken = token.access_token;

    // 2) identify the user
    const user = await getDiscordUser(accessToken);
    const discordUserId = user.id;
    const discordUsername = user.username; // may not include discriminator in newer Discord

    // 3) add to guild (server)
    await addUserToGuild({ userId: discordUserId, accessToken });

    // 4) remove other tier roles (optional but recommended)
    // This prevents someone being "Master" and "Apprentice" at the same time.
    for (const r of TIER_ROLES) {
      if (r && r !== roleId) {
        // ignore errors if they don't have the role
        try {
          await removeRoleFromMember({ userId: discordUserId, roleId: r });
        } catch {}
      }
    }

    // 5) add correct role
    await addRoleToMember({ userId: discordUserId, roleId });

    // 6) Zapier log (optional)
    await postToZapier({
      event: 'discord_onboarded',
      email,
      tier,
      discordUserId,
      discordUsername,
      joinedAt: new Date().toISOString(),
      source: 'oauth_hallway'
    });

    // 7) redirect or show success page
    if (SUCCESS_REDIRECT_URL) {
      const u = new URL(SUCCESS_REDIRECT_URL);
      // Optional: pass info forward
      u.searchParams.set('tier', tier);
      u.searchParams.set('discord', discordUserId);
      return res.redirect(u.toString());
    }

    return res.send(page('Welcome to GuildHaven ✅', `You are in! Discord user <code>${discordUsername}</code> was added and assigned tier <code>${tier}</code>. You can close this page.`));
  } catch (e) {
    console.error('Callback error:', e);

    // Helpful debug info (safe-ish). Avoid leaking secrets.
    const status = e?.status ? `Discord status: <code>${e.status}</code>. ` : '';
    const hint =
      e?.status === 401
        ? '401 usually means your Bot Token is wrong.'
        : e?.status === 403
        ? '403 usually means the bot lacks permissions OR bot role is below the target role.'
        : e?.status === 400
        ? '400 can mean missing OAuth scope or invalid redirect uri/code.'
        : 'Check Render logs for details.';

    return res.status(500).send(page('Something went wrong', `${status}${hint}`));
  }
});

// Root page
app.get('/', (req, res) => {
  res.send(
    page(
      'GuildHaven OAuth Hallway',
      `Use <code>/discord/start?tier=apprentice&email=you@email.com</code> to begin.`
    )
  );
});

app.listen(PORT, () => {
  console.log(`GuildHaven hallway running on port ${PORT}`);
  console.log(`Base URL: ${BASE_URL}`);
});
