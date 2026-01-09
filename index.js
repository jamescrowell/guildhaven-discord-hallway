const express = require("express");
const morgan = require("morgan");
const jwt = require("jsonwebtoken");
const fetch = require("node-fetch");
const crypto = require("crypto");

const app = express();
app.use(express.json({ limit: "1mb" }));
app.use(morgan("combined"));

const {
  PORT = "10000",

  // Ghost Admin API
  GHOST_ADMIN_API_URL,     // e.g. https://YOUR-SITE.ghost.io
  GHOST_ADMIN_API_KEY,     // id:secret (Ghost Admin API key)
  SYNC_SECRET,             // random secret shared with Zapier

  // Public link users click in email
  DISCORD_OAUTH_URL,       // e.g. https://guildhaven-discord-hallway.onrender.com/discord/start

  // Discord OAuth + Bot
  DISCORD_CLIENT_ID,
  DISCORD_CLIENT_SECRET,
  DISCORD_REDIRECT_URI,    // MUST be https://guildhaven-discord-hallway.onrender.com/discord/callback
  DISCORD_GUILD_ID,
  DISCORD_BOT_TOKEN,

  // Optional: JSON mapping from tier name -> role id
  // Example:
  // {"Apprentice":"1234567890","Master":"2345678901"}
  DISCORD_ROLE_MAP_JSON
} = process.env;

function ok(res, payload) {
  return res.status(200).json(payload);
}

function envCheck() {
  const missing = [];
  if (!GHOST_ADMIN_API_URL) missing.push("GHOST_ADMIN_API_URL");
  if (!GHOST_ADMIN_API_KEY) missing.push("GHOST_ADMIN_API_KEY");
  if (!SYNC_SECRET) missing.push("SYNC_SECRET");
  if (!DISCORD_OAUTH_URL) missing.push("DISCORD_OAUTH_URL");
  if (!DISCORD_CLIENT_ID) missing.push("DISCORD_CLIENT_ID");
  if (!DISCORD_CLIENT_SECRET) missing.push("DISCORD_CLIENT_SECRET");
  if (!DISCORD_REDIRECT_URI) missing.push("DISCORD_REDIRECT_URI");
  if (!DISCORD_GUILD_ID) missing.push("DISCORD_GUILD_ID");
  if (!DISCORD_BOT_TOKEN) missing.push("DISCORD_BOT_TOKEN");
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

// --- helper: create a Storage key <= 32 chars from ANY input string ---
function shortKeyFromStorageKey(storage_key) {
  // stable 32-char hex
  return crypto.createHash("md5").update(String(storage_key)).digest("hex");
}

// ---------- HEALTH ----------
app.get("/health", (req, res) => {
  const missing = envCheck();
  if (missing.length) return ok(res, { ok: false, error: "Missing env vars", missing });
  return ok(res, { ok: true });
});

// ---------- ZAPIER HOOK ----------
app.post("/ghost/resolve-tier", async (req, res) => {
  const missing = envCheck();
  if (missing.length) return ok(res, { ok: false, error: "Missing env vars", missing });

  const provided = getProvidedSecret(req);
  if (!provided) return ok(res, { ok: false, error: "Missing sync secret" });
  if (provided !== SYNC_SECRET) return ok(res, { ok: false, error: "Unauthorized (bad sync secret)" });

  const email = (req.body && req.body.email ? String(req.body.email) : "").trim().toLowerCase();
  if (!email) {
    return ok(res, {
      ok: false,
      error: "Missing email",
      hint: "Send JSON body like {\"email\":\"person@example.com\"}"
    });
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

  const tierNames = Array.isArray(member && member.tiers) ? member.tiers.map(t => t && t.name).filter(Boolean) : [];
  const labels = Array.isArray(member && member.labels) ? member.labels.map(l => l && l.slug).filter(Boolean) : [];

  const tierSig = `${status}|tiers:${tierNames.slice().sort().join(",")}|labels:${labels.slice().sort().join(",")}`;

  const baseId = memberId ? `mid:${memberId}` : `email:${email}`;
  const storage_key = `guildhaven_email_sent:${baseId}:${tierSig}`;

  // ✅ this is the ONLY key Zapier Storage should use (<=32)
  const storage_key_32 = shortKeyFromStorageKey(storage_key);

  // Email link users click
  const link = new URL(DISCORD_OAUTH_URL);
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

    // send both; Zapier should use storage_key_32 for Storage steps
    storage_key,
    storage_key_32,

    discord_link: link.toString()
  });
});

// ---------- DISCORD OAUTH START ----------
app.get("/discord/start", (req, res) => {
  const missing = envCheck();
  if (missing.length) return res.status(500).send(`Missing env vars: ${missing.join(", ")}`);

  const email = String(req.query.email || "").trim().toLowerCase();
  if (!email) return res.status(400).send("Missing email");

  // state is signed so nobody can forge an email
  const state = jwt.sign(
    { email, iat: Math.floor(Date.now() / 1000) },
    SYNC_SECRET,
    { algorithm: "HS256", expiresIn: "15m" }
  );

  const authorize = new URL("https://discord.com/oauth2/authorize");
  authorize.searchParams.set("client_id", DISCORD_CLIENT_ID);
  authorize.searchParams.set("redirect_uri", DISCORD_REDIRECT_URI);
  authorize.searchParams.set("response_type", "code");
  authorize.searchParams.set("scope", "identify guilds.join");
  authorize.searchParams.set("state", state);
  authorize.searchParams.set("prompt", "consent");

  return res.redirect(authorize.toString());
});

// ---------- DISCORD OAUTH CALLBACK (THIS FIXES YOUR SCREEN) ----------
app.get("/discord/callback", async (req, res) => {
  try {
    const missing = envCheck();
    if (missing.length) return res.status(500).send(`Missing env vars: ${missing.join(", ")}`);

    const code = String(req.query.code || "");
    const state = String(req.query.state || "");
    if (!code) return res.status(400).send("Missing code");
    if (!state) return res.status(400).send("Missing state");

    // verify state and pull email back out
    let payload;
    try {
      payload = jwt.verify(state, SYNC_SECRET);
    } catch (e) {
      return res.status(400).send("Invalid/expired state. Please use the email link again.");
    }

    const email = String(payload.email || "").trim().toLowerCase();
    if (!email) return res.status(400).send("State missing email");

    // Exchange code for access token
    const tokenResp = await fetch("https://discord.com/api/oauth2/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        client_id: DISCORD_CLIENT_ID,
        client_secret: DISCORD_CLIENT_SECRET,
        grant_type: "authorization_code",
        code,
        redirect_uri: DISCORD_REDIRECT_URI
      })
    });

    const tokenData = await tokenResp.json();
    if (!tokenResp.ok) {
      console.error("token exchange failed", tokenData);
      return res.status(500).send("Discord token exchange failed.");
    }

    const access_token = tokenData.access_token;

    // Get the Discord user
    const userResp = await fetch("https://discord.com/api/users/@me", {
      headers: { Authorization: `Bearer ${access_token}` }
    });
    const user = await userResp.json();
    if (!userResp.ok) {
      console.error("get user failed", user);
      return res.status(500).send("Failed to read Discord user.");
    }

    // Add user to guild
    const addResp = await fetch(`https://discord.com/api/guilds/${DISCORD_GUILD_ID}/members/${user.id}`, {
      method: "PUT",
      headers: {
        Authorization: `Bot ${DISCORD_BOT_TOKEN}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ access_token })
    });
    const addData = await addResp.json().catch(() => ({}));
    if (!addResp.ok && addResp.status !== 201 && addResp.status !== 204) {
      console.error("guild join failed", addResp.status, addData);
      return res.status(500).send("Could not add you to the Discord server (bot permissions issue).");
    }

    // OPTIONAL role assignment from Ghost tier
    let roleMap = {};
    try { roleMap = DISCORD_ROLE_MAP_JSON ? JSON.parse(DISCORD_ROLE_MAP_JSON) : {}; } catch {}

    let roleIdToAssign = null;

    // Find tier from Ghost
    const ghost = await ghostFindMemberByEmail(email);
    const member = ghost.data && ghost.data.members && ghost.data.members[0] ? ghost.data.members[0] : null;
    const tierNames = Array.isArray(member && member.tiers) ? member.tiers.map(t => t && t.name).filter(Boolean) : [];

    // pick first tier that exists in map
    for (const tn of tierNames) {
      if (roleMap[tn]) { roleIdToAssign = roleMap[tn]; break; }
    }

    if (roleIdToAssign) {
      const roleResp = await fetch(
        `https://discord.com/api/guilds/${DISCORD_GUILD_ID}/members/${user.id}/roles/${roleIdToAssign}`,
        { method: "PUT", headers: { Authorization: `Bot ${DISCORD_BOT_TOKEN}` } }
      );
      if (!roleResp.ok && roleResp.status !== 204) {
        console.error("role assign failed", await roleResp.text());
        // don't block success page if role fails
      }
    }

    // Success page
    return res.status(200).send(`
      <html>
        <body style="font-family: system-ui; padding: 24px;">
          <h2>✅ Discord Connected</h2>
          <p>You’re connected as <b>${user.username}</b>.</p>
          <p>You can close this tab and return to Discord.</p>
        </body>
      </html>
    `);
  } catch (e) {
    console.error("callback error", e);
    return res.status(500).send("Server error in Discord callback.");
  }
});

app.listen(Number(PORT), () => {
  console.log(`Hallway listening on port ${PORT}`);
});
