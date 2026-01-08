/**
 * GuildHaven Discord Hallway (OAuth) + Auto-Join + Role Assign + Zapier logging
 *
 * Routes:
 *   GET  /                      -> health check
 *   GET  /discord/start         -> begins OAuth flow
 *   GET  /discord/callback      -> handles OAuth callback, joins server, assigns role, logs to Zapier
 *
 * Required ENV vars (Render -> Environment):
 *   DISCORD_CLIENT_ID
 *   DISCORD_CLIENT_SECRET
 *   DISCORD_REDIRECT_URI           (EXACT, e.g. https://YOUR.onrender.com/discord/callback)
 *   DISCORD_GUILD_ID               (server ID)
 *   DISCORD_BOT_TOKEN              (bot token)
 *   STATE_SECRET                   (random long string)
 *   ZAPIER_WEBHOOK_URL             (your Zapier Catch Hook URL)
 *
 * Role IDs (set only the tiers you use):
 *   ROLE_FREE
 *   ROLE_APPRENTICE
 *   ROLE_JOURNEYMAN
 *   ROLE_MASTER
 *   ROLE_GRANDMASTER
 *
 * Optional:
 *   SUCCESS_REDIRECT_URL           (where to send user after success; default = "/success")
 *   FAILURE_REDIRECT_URL           (default = "/error")
 *
 * Node 18+ recommended (Render default is fine).
 */

const express = require("express");
const crypto = require("crypto");

const app = express();
app.use(express.json());

const {
  DISCORD_CLIENT_ID,
  DISCORD_CLIENT_SECRET,
  DISCORD_REDIRECT_URI,
  DISCORD_GUILD_ID,
  DISCORD_BOT_TOKEN,
  STATE_SECRET,
  ZAPIER_WEBHOOK_URL,
  SUCCESS_REDIRECT_URL,
  FAILURE_REDIRECT_URL,

  ROLE_FREE,
  ROLE_APPRENTICE,
  ROLE_JOURNEYMAN,
  ROLE_MASTER,
  ROLE_GRANDMASTER,
} = process.env;

const PORT = process.env.PORT || 3000;

// ---------- Small helpers ----------
function requireEnv(name) {
  if (!process.env[name]) {
    throw new Error(`Missing required env var: ${name}`);
  }
}

function base64url(buf) {
  return buf
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function signState(payloadObj) {
  // payloadObj: {tier,email,ts,nonce}
  const payload = base64url(Buffer.from(JSON.stringify(payloadObj), "utf8"));
  const sig = crypto
    .createHmac("sha256", STATE_SECRET)
    .update(payload)
    .digest("hex");
  return `${payload}.${sig}`;
}

function verifyState(state) {
  const [payload, sig] = String(state || "").split(".");
  if (!payload || !sig) return null;

  const expected = crypto
    .createHmac("sha256", STATE_SECRET)
    .update(payload)
    .digest("hex");

  if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) {
    return null;
  }

  try {
    const json = JSON.parse(Buffer.from(payload, "base64").toString("utf8"));
    return json;
  } catch {
    return null;
  }
}

function tierToRoleId(tierRaw) {
  const tier = String(tierRaw || "").toLowerCase().trim();
  const map = {
    free: ROLE_FREE,
    apprentice: ROLE_APPRENTICE,
    journeyman: ROLE_JOURNEYMAN,
    master: ROLE_MASTER,
    grandmaster: ROLE_GRANDMASTER,
  };
  return map[tier] || null;
}

async function discordTokenExchange(code) {
  const body = new URLSearchParams({
    client_id: DISCORD_CLIENT_ID,
    client_secret: DISCORD_CLIENT_SECRET,
    grant_type: "authorization_code",
    code,
    redirect_uri: DISCORD_REDIRECT_URI,
  });

  const res = await fetch("https://discord.com/api/oauth2/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body,
  });

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Token exchange failed: ${res.status} ${text}`);
  }
  return res.json(); // {access_token, token_type, expires_in, refresh_token, scope}
}

async function discordGetUser(accessToken) {
  const res = await fetch("https://discord.com/api/users/@me", {
    headers: { Authorization: `Bearer ${accessToken}` },
  });

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Get user failed: ${res.status} ${text}`);
  }

  return res.json(); // {id, username, global_name, ...}
}

/**
 * Adds the user to your guild using OAuth access token (requires scope guilds.join)
 */
async function discordJoinGuild(userId, accessToken) {
  const url = `https://discord.com/api/guilds/${DISCORD_GUILD_ID}/members/${userId}`;

  const res = await fetch(url, {
    method: "PUT",
    headers: {
      Authorization: `Bot ${DISCORD_BOT_TOKEN}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ access_token: accessToken }),
  });

  // Discord returns 201 Created or 204 No Content on success (depends)
  if (!(res.status === 201 || res.status === 204)) {
    const text = await res.text();
    throw new Error(`Join guild failed: ${res.status} ${text}`);
  }
}

/**
 * Assign role to a guild member
 */
async function discordAddRole(userId, roleId) {
  const url = `https://discord.com/api/guilds/${DISCORD_GUILD_ID}/members/${userId}/roles/${roleId}`;
  const res = await fetch(url, {
    method: "PUT",
    headers: { Authorization: `Bot ${DISCORD_BOT_TOKEN}` },
  });

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Add role failed: ${res.status} ${text}`);
  }
}

async function zapierLog(payload) {
  if (!ZAPIER_WEBHOOK_URL) return; // optional, but recommended
  const res = await fetch(ZAPIER_WEBHOOK_URL, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });

  // Zapier often returns 200/201. If not, log but don't hard-fail the user flow.
  if (!res.ok) {
    const text = await res.text();
    console.warn(`Zapier log failed: ${res.status} ${text}`);
  }
}

// ---------- Health ----------
app.get("/", (req, res) => {
  res.status(200).send("GuildHaven Hallway is running ✅");
});

// ---------- Start OAuth ----------
app.get("/discord/start", (req, res) => {
  // Example: /discord/start?tier=free&email=james@example.com
  const tier = String(req.query.tier || "").toLowerCase().trim();
  const email = String(req.query.email || "").trim();

  if (!tier) return res.status(400).send("Missing ?tier=");
  if (!email) return res.status(400).send("Missing ?email=");
  if (!tierToRoleId(tier)) {
    return res
      .status(400)
      .send(`Unknown tier "${tier}". Must match your ROLE_* env mapping.`);
  }

  const statePayload = {
    tier,
    email,
    ts: Date.now(),
    nonce: crypto.randomBytes(8).toString("hex"),
  };
  const state = signState(statePayload);

  const params = new URLSearchParams({
    client_id: DISCORD_CLIENT_ID,
    redirect_uri: DISCORD_REDIRECT_URI,
    response_type: "code",
    // IMPORTANT: guilds.join is what lets us add them to your server automatically.
    scope: "identify guilds.join",
    state,
    prompt: "consent",
  });

  const discordAuthorizeUrl = `https://discord.com/oauth2/authorize?${params.toString()}`;
  return res.redirect(discordAuthorizeUrl);
});

// ---------- OAuth Callback ----------
app.get("/discord/callback", async (req, res) => {
  try {
    const { code, state, error } = req.query;

    if (error) throw new Error(`Discord returned error: ${error}`);
    if (!code) throw new Error("Missing code from Discord");
    if (!state) throw new Error("Missing state");

    const verified = verifyState(state);
    if (!verified) throw new Error("Invalid state (security check failed)");

    const tier = verified.tier;
    const email = verified.email;
    const roleId = tierToRoleId(tier);
    if (!roleId) throw new Error(`Tier has no ROLE_* mapping: ${tier}`);

    // Exchange code -> access token
    const tokenData = await discordTokenExchange(code);
    const accessToken = tokenData.access_token;

    // Get user identity
    const user = await discordGetUser(accessToken);
    const discordUserId = user.id;
    const discordUsername =
      user.global_name || user.username || "unknown";

    // Add them to guild (no invite link needed)
    await discordJoinGuild(discordUserId, accessToken);

    // Assign tier role
    await discordAddRole(discordUserId, roleId);

    // Log to Zapier (for Google Sheets)
    await zapierLog({
      email,
      tier,
      discordUserId,
      discordUsername,
      status: "active",
      joinedAt: new Date().toISOString(),
    });

    // Done
    const successUrl = SUCCESS_REDIRECT_URL || "/success";
    return res.redirect(successUrl);
  } catch (err) {
    console.error(err);
    const failUrl = FAILURE_REDIRECT_URL || "/error";
    // Optionally append message for debugging (don’t do this long-term)
    return res.redirect(`${failUrl}?msg=${encodeURIComponent(err.message)}`);
  }
});

// ---------- Simple success/error pages ----------
app.get("/success", (req, res) => {
  res
    .status(200)
    .send(
      "✅ Success! Your Discord is connected and your tier role was assigned. You can close this tab."
    );
});

app.get("/error", (req, res) => {
  res
    .status(200)
    .send(
      `❌ Something went wrong. ${req.query.msg ? `Details: ${req.query.msg}` : ""}`
    );
});

// ---------- Start server ----------
(async () => {
  // Validate required env vars at boot (crashes fast if missing)
  requireEnv("DISCORD_CLIENT_ID");
  requireEnv("DISCORD_CLIENT_SECRET");
  requireEnv("DISCORD_REDIRECT_URI");
  requireEnv("DISCORD_GUILD_ID");
  requireEnv("DISCORD_BOT_TOKEN");
  requireEnv("STATE_SECRET");

  app.listen(PORT, () => {
    console.log(`✅ Hallway running on port ${PORT}`);
    console.log(`✅ Redirect URI should be: ${DISCORD_REDIRECT_URI}`);
  });
})();
