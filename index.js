const express = require("express");
const morgan = require("morgan");
const jwt = require("jsonwebtoken");
const fetch = require("node-fetch");

const app = express();
app.use(express.json({ limit: "1mb" }));
app.use(morgan("combined"));

const {
  PORT = "10000",

  // Ghost
  GHOST_ADMIN_API_URL,     // e.g. https://YOUR-SITE.ghost.io
  GHOST_ADMIN_API_KEY,     // Ghost Admin API key: id:secret

  // Security
  SYNC_SECRET,

  // Public base + start link
  PUBLIC_BASE_URL,         // e.g. https://guildhaven-discord-hallway.onrender.com
  DISCORD_OAUTH_URL,        // e.g. https://guildhaven-discord-hallway.onrender.com/discord/start

  // Discord OAuth + Bot
  DISCORD_CLIENT_ID,
  DISCORD_CLIENT_SECRET,
  DISCORD_REDIRECT_URI,     // MUST match your Discord app redirect (e.g. https://.../discord/callback)
  DISCORD_BOT_TOKEN,
  DISCORD_GUILD_ID,

  // Role IDs (set these to your server role IDs)
  DISCORD_ROLE_FREE_ID,
  DISCORD_ROLE_APPRENTICE_ID,
  DISCORD_ROLE_JOURNEYMAN_ID,
  DISCORD_ROLE_MASTER_ID,

  // Which roles this app is allowed to manage (comma-separated role IDs)
  MANAGED_ROLE_IDS
} = process.env;

function ok(res, payload) {
  return res.status(200).json(payload);
}

function requiredEnvForResolveTier() {
  const missing = [];
  if (!GHOST_ADMIN_API_URL) missing.push("GHOST_ADMIN_API_URL");
  if (!GHOST_ADMIN_API_KEY) missing.push("GHOST_ADMIN_API_KEY");
  if (!SYNC_SECRET) missing.push("SYNC_SECRET");
  if (!DISCORD_OAUTH_URL && !PUBLIC_BASE_URL) missing.push("DISCORD_OAUTH_URL or PUBLIC_BASE_URL");
  return missing;
}

function requiredEnvForDiscord() {
  const missing = [];
  if (!SYNC_SECRET) missing.push("SYNC_SECRET");
  if (!PUBLIC_BASE_URL) missing.push("PUBLIC_BASE_URL");
  if (!DISCORD_CLIENT_ID) missing.push("DISCORD_CLIENT_ID");
  if (!DISCORD_CLIENT_SECRET) missing.push("DISCORD_CLIENT_SECRET");
  if (!DISCORD_REDIRECT_URI) missing.push("DISCORD_REDIRECT_URI");
  if (!DISCORD_BOT_TOKEN) missing.push("DISCORD_BOT_TOKEN");
  if (!DISCORD_GUILD_ID) missing.push("DISCORD_GUILD_ID");
  return missing;
}

function getProvidedSecret(req) {
  return (
    req.get("x-sync-secret") ||
    req.get("X-Sync-Secret") ||
    (req.body && req.body.sync_secret) ||
    (req.query && req.query.sync_secret) ||
    ""
  ).trim();
}

function makeGhostAdminToken() {
  const apiKey = (GHOST_ADMIN_API_KEY || "").trim();
  const parts = apiKey.split(":");
  const id = parts[0];
  const secret = parts[1];
  if (!id || !secret) throw new Error("GHOST_ADMIN_API_KEY must be in format id:secret");

  const now = Math.floor(Date.now() / 1000);
  return jwt.sign(
    { iat: now, exp: now + 5 * 60, aud: "/admin/" },
    Buffer.from(secret, "hex"),
    { algorithm: "HS256", keyid: id }
  );
}

async function ghostFindMemberByEmail(email) {
  const base = GHOST_ADMIN_API_URL.replace(/\/$/, "");
  const token = makeGhostAdminToken();

  const filter = `email:'${String(email).replace(/'/g, "\\'")}'`;
  const url = `${base}/ghost/api/admin/members/?filter=${encodeURIComponent(filter)}&include=labels,subscriptions,tiers`;

  const resp = await fetch(url, {
    method: "GET",
    headers: {
      Authorization: `Ghost ${token}`,
      "Content-Type": "application/json",
      Accept: "application/json"
    }
  });

  const text = await resp.text();
  let data;
  try { data = JSON.parse(text); } catch { data = { raw: text }; }
  return { httpStatus: resp.status, data };
}

// ---------- DISCORD HELPERS ----------
function signState(payload) {
  // short-lived state token
  const now = Math.floor(Date.now() / 1000);
  return jwt.sign(
    { ...payload, iat: now, exp: now + 10 * 60 },
    SYNC_SECRET,
    { algorithm: "HS256" }
  );
}

function verifyState(token) {
  return jwt.verify(token, SYNC_SECRET, { algorithms: ["HS256"] });
}

function discordAuthUrl(state) {
  const u = new URL("https://discord.com/oauth2/authorize");
  u.searchParams.set("client_id", DISCORD_CLIENT_ID);
  u.searchParams.set("redirect_uri", DISCORD_REDIRECT_URI);
  u.searchParams.set("response_type", "code");
  u.searchParams.set("scope", "identify guilds.join");
  u.searchParams.set("state", state);
  u.searchParams.set("prompt", "consent");
  return u.toString();
}

async function discordExchangeCode(code) {
  const body = new URLSearchParams();
  body.set("client_id", DISCORD_CLIENT_ID);
  body.set("client_secret", DISCORD_CLIENT_SECRET);
  body.set("grant_type", "authorization_code");
  body.set("code", code);
  body.set("redirect_uri", DISCORD_REDIRECT_URI);

  const resp = await fetch("https://discord.com/api/oauth2/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body
  });

  const data = await resp.json();
  return { status: resp.status, data };
}

async function discordGetUser(accessToken) {
  const resp = await fetch("https://discord.com/api/users/@me", {
    headers: { Authorization: `Bearer ${accessToken}` }
  });
  const data = await resp.json();
  return { status: resp.status, data };
}

async function discordAddToGuild(userId, accessToken) {
  const url = `https://discord.com/api/guilds/${DISCORD_GUILD_ID}/members/${userId}`;
  const resp = await fetch(url, {
    method: "PUT",
    headers: {
      Authorization: `Bot ${DISCORD_BOT_TOKEN}`,
      "Content-Type": "application/json"
    },
    body: JSON.stringify({ access_token: accessToken })
  });

  const text = await resp.text();
  let data;
  try { data = JSON.parse(text); } catch { data = { raw: text }; }
  return { status: resp.status, data };
}

function managedRoleSet() {
  const s = (MANAGED_ROLE_IDS || "").trim();
  if (!s) return new Set();
  return new Set(s.split(",").map(x => x.trim()).filter(Boolean));
}

async function discordGetMember(userId) {
  const url = `https://discord.com/api/guilds/${DISCORD_GUILD_ID}/members/${userId}`;
  const resp = await fetch(url, {
    headers: { Authorization: `Bot ${DISCORD_BOT_TOKEN}` }
  });
  const data = await resp.json();
  return { status: resp.status, data };
}

async function discordPatchMemberRoles(userId, roles) {
  const url = `https://discord.com/api/guilds/${DISCORD_GUILD_ID}/members/${userId}`;
  const resp = await fetch(url, {
    method: "PATCH",
    headers: {
      Authorization: `Bot ${DISCORD_BOT_TOKEN}`,
      "Content-Type": "application/json"
    },
    body: JSON.stringify({ roles })
  });

  const text = await resp.text();
  let data;
  try { data = JSON.parse(text); } catch { data = { raw: text }; }
  return { status: resp.status, data };
}

function pickRoleIds({ ghost_status, tier_names }) {
  // You can tune this logic. This is the simplest:
  // - If paid & has a tier name, map tier -> role
  // - Otherwise assign FREE role (if provided)

  const tierLower = (tier_names || []).map(t => String(t).toLowerCase());
  const isPaid = String(ghost_status || "").toLowerCase() === "paid";

  // If Ghost tier names contain keywords, map them:
  const hasApprentice = tierLower.some(t => t.includes("apprentice"));
  const hasJourneyman = tierLower.some(t => t.includes("journeyman"));
  const hasMaster = tierLower.some(t => t.includes("master"));

  const roles = [];

  if (isPaid) {
    if (hasMaster && DISCORD_ROLE_MASTER_ID) roles.push(DISCORD_ROLE_MASTER_ID);
    else if (hasJourneyman && DISCORD_ROLE_JOURNEYMAN_ID) roles.push(DISCORD_ROLE_JOURNEYMAN_ID);
    else if (hasApprentice && DISCORD_ROLE_APPRENTICE_ID) roles.push(DISCORD_ROLE_APPRENTICE_ID);
    else if (DISCORD_ROLE_APPRENTICE_ID) roles.push(DISCORD_ROLE_APPRENTICE_ID); // fallback paid role
  } else {
    if (DISCORD_ROLE_FREE_ID) roles.push(DISCORD_ROLE_FREE_ID);
  }

  return roles.filter(Boolean);
}

// ---------- ROUTES ----------

app.get("/health", (req, res) => {
  const missing = requiredEnvForResolveTier();
  if (missing.length) return ok(res, { ok: false, error: "Missing env vars", missing });
  return ok(res, { ok: true });
});

// 1) Called by Zapier to resolve tier + generate link + generate storage_key
app.post("/ghost/resolve-tier", async (req, res) => {
  const missing = requiredEnvForResolveTier();
  if (missing.length) return ok(res, { ok: false, error: "Missing env vars", missing });

  const provided = getProvidedSecret(req);
  if (!provided) return ok(res, { ok: false, error: "Missing sync secret" });
  if (provided !== SYNC_SECRET) return ok(res, { ok: false, error: "Unauthorized (bad sync secret)" });

  const email = (req.body && req.body.email ? String(req.body.email) : "").trim().toLowerCase();
  if (!email) {
    return ok(res, { ok: false, error: "Missing email", hint: "Send JSON body like {\"email\":\"person@example.com\"}" });
  }

  let member = null;
  let ghostError = null;
  let ghostHttp = null;

  try {
    const r = await ghostFindMemberByEmail(email);
    ghostHttp = r.httpStatus;
    member = r.data && r.data.members && r.data.members[0] ? r.data.members[0] : null;
  } catch (e) {
    ghostError = e.message || String(e);
  }

  const memberId = member && member.id ? member.id : null;
  const status = member && member.status ? member.status : "unknown";

  const tierNames = Array.isArray(member && member.tiers)
    ? member.tiers.map(t => t && t.name).filter(Boolean)
    : [];

  const labels = Array.isArray(member && member.labels)
    ? member.labels.map(l => l && l.slug).filter(Boolean)
    : [];

  const tierSig = `${status}|tiers:${tierNames.slice().sort().join(",")}|labels:${labels.slice().sort().join(",")}`;

  const baseId = memberId ? `mid:${memberId}` : `email:${email}`;
  const storage_key = `guildhaven_email_sent:${baseId}:${tierSig}`;

  const startUrl = DISCORD_OAUTH_URL || `${PUBLIC_BASE_URL.replace(/\/$/, "")}/discord/start`;
  const link = new URL(startUrl);
  link.searchParams.set("email", email);

  return ok(res, {
    ok: true,
    email,
    member_found: !!member,
    ghost_http: ghostHttp,
    ghost_error: ghostError,
    ghost_status: status,
    tier_names: tierNames,
    labels,
    tier_sig: tierSig,
    storage_key,
    discord_link: link.toString()
  });
});

// 2) The link in the email goes here
app.get("/discord/start", async (req, res) => {
  const missing = requiredEnvForDiscord();
  if (missing.length) return res.status(200).send(`Missing env vars: ${missing.join(", ")}`);

  const email = String(req.query.email || "").trim().toLowerCase();
  if (!email) return res.status(200).send("Missing email");

  // create signed state that includes email
  const state = signState({ email });

  // redirect user to Discord OAuth consent
  return res.redirect(discordAuthUrl(state));
});

// 3) Discord redirects back here after user authorizes
app.get("/discord/callback", async (req, res) => {
  const missing = requiredEnvForDiscord();
  if (missing.length) return res.status(200).send(`Missing env vars: ${missing.join(", ")}`);

  const code = String(req.query.code || "");
  const stateToken = String(req.query.state || "");
  if (!code) return res.status(200).send("Missing code");
  if (!stateToken) return res.status(200).send("Missing state");

  let state;
  try {
    state = verifyState(stateToken);
  } catch (e) {
    return res.status(200).send("Invalid/expired state. Please click the email link again.");
  }

  const email = String(state.email || "").trim().toLowerCase();
  if (!email) return res.status(200).send("Missing email in state");

  // exchange code for token
  const tok = await discordExchangeCode(code);
  if (tok.status >= 400) {
    console.log("discord token exchange error:", tok);
    return res.status(200).send("Discord auth failed (token exchange). Try again.");
  }

  const accessToken = tok.data.access_token;
  if (!accessToken) return res.status(200).send("Missing Discord access token");

  // get user
  const me = await discordGetUser(accessToken);
  if (me.status >= 400 || !me.data || !me.data.id) {
    console.log("discord get user error:", me);
    return res.status(200).send("Discord auth failed (user lookup). Try again.");
  }

  const userId = me.data.id;

  // add to guild
  const add = await discordAddToGuild(userId, accessToken);
  if (add.status >= 400) {
    console.log("discord add to guild error:", add);
    // still continue — sometimes user is already in guild
  }

  // look up Ghost member again to decide roles
  let ghost_status = "unknown";
  let tier_names = [];
  try {
    const r = await ghostFindMemberByEmail(email);
    const member = r.data && r.data.members && r.data.members[0] ? r.data.members[0] : null;
    ghost_status = member && member.status ? member.status : "unknown";
    tier_names = Array.isArray(member && member.tiers)
      ? member.tiers.map(t => t && t.name).filter(Boolean)
      : [];
  } catch (e) {
    console.log("ghost lookup error:", e);
  }

  const desiredManagedRoles = pickRoleIds({ ghost_status, tier_names });
  const managed = managedRoleSet();

  // fetch current member roles so we only replace “managed” roles
  const current = await discordGetMember(userId);
  const currentRoles = Array.isArray(current.data && current.data.roles) ? current.data.roles : [];

  const kept = currentRoles.filter(rid => !managed.has(rid));
  const nextRoles = Array.from(new Set([...kept, ...desiredManagedRoles]));

  const patch = await discordPatchMemberRoles(userId, nextRoles);
  if (patch.status >= 400) {
    console.log("discord patch roles error:", patch);
    return res.status(200).send("Joined Discord, but role assignment failed. Contact support.");
  }

  return res.status(200).send(`
    <h2>✅ Connected!</h2>
    <p>You can close this tab. Your Discord roles should update shortly.</p>
  `);
});

app.listen(Number(PORT), () => {
  console.log(`Hallway listening on port ${PORT}`);
});
