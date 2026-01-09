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
  GHOST_ADMIN_API_URL,     // e.g. https://your-site.com  (NOT /ghost/)
  GHOST_ADMIN_API_KEY,     // Ghost Admin API key: "id:secret"

  // Shared secret between Zapier and Render
  SYNC_SECRET,

  // The link base you want to email out (your own endpoint)
  DISCORD_OAUTH_URL,       // e.g. https://guildhaven-discord-hallway.onrender.com/discord/start

  // Discord OAuth + Bot
  DISCORD_CLIENT_ID,
  DISCORD_CLIENT_SECRET,
  DISCORD_REDIRECT_URI,    // e.g. https://guildhaven-discord-hallway.onrender.com/discord/callback
  DISCORD_GUILD_ID,
  DISCORD_BOT_TOKEN,

  // Role mapping
  // Example:
  // {"Apprentice":"123","Master":"456","free":"789"}
  DISCORD_ROLE_MAP_JSON
} = process.env;

/** ---------------- Helpers ---------------- */

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

  if (!DISCORD_ROLE_MAP_JSON) missing.push("DISCORD_ROLE_MAP_JSON");
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

function parseRoleMap() {
  try {
    const obj = JSON.parse(DISCORD_ROLE_MAP_JSON || "{}");
    return obj && typeof obj === "object" ? obj : {};
  } catch {
    return {};
  }
}

// short signature used for both dedupe + role decisions
function buildTierSig(member, email) {
  const memberId = member?.id || null;
  const status = member?.status || "unknown";

  const tierNames = Array.isArray(member?.tiers) ? member.tiers.map(t => t?.name).filter(Boolean) : [];
  const labels = Array.isArray(member?.labels) ? member.labels.map(l => l?.slug).filter(Boolean) : [];

  const tierSig = `${status}|tiers:${tierNames.slice().sort().join(",")}|labels:${labels.slice().sort().join(",")}`;
  const baseId = memberId ? `mid:${memberId}` : `email:${email}`;

  return {
    memberId,
    status,
    tierNames,
    labels,
    tierSig,
    storageKey: `guildhaven_email_sent:${baseId}:${tierSig}`
  };
}

/** --- SIGNED state: prevents tampering of ?email= --- */
function signState(email) {
  const nonce = crypto.randomBytes(8).toString("hex");
  const payload = `${email}|${nonce}`;
  const h = crypto
    .createHmac("sha256", SYNC_SECRET)
    .update(payload)
    .digest("hex");
  // email|nonce|hmac
  const raw = `${email}|${nonce}|${h}`;
  return Buffer.from(raw, "utf8").toString("base64url");
}

function verifyState(stateB64) {
  const raw = Buffer.from(stateB64, "base64url").toString("utf8");
  const parts = raw.split("|");
  if (parts.length !== 3) return { ok: false, error: "bad_state_format" };
  const [email, nonce, h] = parts;

  const payload = `${email}|${nonce}`;
  const expected = crypto
    .createHmac("sha256", SYNC_SECRET)
    .update(payload)
    .digest("hex");

  if (expected !== h) return { ok: false, error: "bad_state_signature" };
  return { ok: true, email: String(email || "").trim().toLowerCase() };
}

/** ---------------- Routes ---------------- */

app.get("/health", (req, res) => {
  const missing = envCheck();
  if (missing.length) return ok(res, { ok: false, error: "Missing env vars", missing });
  return ok(res, { ok: true });
});

/**
 * Zap Step 2 calls this:
 * POST https://.../ghost/resolve-tier
 * Body: { "email": "person@x.com", "sync_secret": "..." }
 */
app.post("/ghost/resolve-tier", async (req, res) => {
  const missing = envCheck();
  if (missing.length) return ok(res, { ok: false, error: "Missing env vars", missing });

  const provided = getProvidedSecret(req);
  if (!provided) return ok(res, { ok: false, error: "Missing sync secret" });
  if (provided !== SYNC_SECRET) return ok(res, { ok: false, error: "Unauthorized (bad sync secret)" });

  const email = (req.body?.email ? String(req.body.email) : "").trim().toLowerCase();
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
    member = r.data?.members?.[0] || null;
  } catch (e) {
    ghostError = e?.message || String(e);
  }

  const sig = buildTierSig(member, email);

  // Build the email link to your /discord/start endpoint
  const link = new URL(DISCORD_OAUTH_URL);
  link.searchParams.set("email", email);

  return ok(res, {
    ok: true,
    email,
    member_found: !!member,
    ghost_http: ghostHttp,
    ghost_error: ghostError,
    ghost_status: sig.status,
    tier_names: sig.tierNames,
    labels: sig.labels,
    tier_sig: sig.tierSig,
    storage_key: sig.storageKey,
    discord_link: link.toString()
  });
});

/**
 * This is the link in the email:
 * GET /discord/start?email=...
 * Redirects to Discord authorize screen.
 */
app.get("/discord/start", (req, res) => {
  const missing = envCheck();
  if (missing.length) {
    return res.status(500).send(`Missing env vars: ${missing.join(", ")}`);
  }

  const email = String(req.query.email || "").trim().toLowerCase();
  if (!email) return res.status(400).send("Missing email");

  const state = signState(email);

  const authorize = new URL("https://discord.com/oauth2/authorize");
  authorize.searchParams.set("client_id", DISCORD_CLIENT_ID);
  authorize.searchParams.set("redirect_uri", DISCORD_REDIRECT_URI);
  authorize.searchParams.set("response_type", "code");
  authorize.searchParams.set("scope", "identify guilds.join");
  authorize.searchParams.set("state", state);

  return res.redirect(authorize.toString());
});

/**
 * Discord redirects back here after user authorizes
 * GET /discord/callback?code=...&state=...
 */
app.get("/discord/callback", async (req, res) => {
  const missing = envCheck();
  if (missing.length) {
    return res.status(500).send(`Missing env vars: ${missing.join(", ")}`);
  }

  const code = String(req.query.code || "");
  const state = String(req.query.state || "");
  if (!code || !state) return res.status(400).send("Missing code or state");

  const v = verifyState(state);
  if (!v.ok) return res.status(400).send(`Invalid state (${v.error})`);

  const email = v.email;

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

  const tokenJson = await tokenResp.json();
  if (!tokenResp.ok) {
    console.error("oauth token error:", tokenJson);
    return res.status(500).send("Discord token exchange failed");
  }

  const accessToken = tokenJson.access_token;

  // Get Discord user
  const userResp = await fetch("https://discord.com/api/users/@me", {
    headers: { Authorization: `Bearer ${accessToken}` }
  });
  const userJson = await userResp.json();
  if (!userResp.ok) {
    console.error("user fetch error:", userJson);
    return res.status(500).send("Discord user fetch failed");
  }

  const discordUserId = userJson.id;

  // Add user to guild (guilds.join)
  const addResp = await fetch(`https://discord.com/api/guilds/${DISCORD_GUILD_ID}/members/${discordUserId}`, {
    method: "PUT",
    headers: {
      Authorization: `Bot ${DISCORD_BOT_TOKEN}`,
      "Content-Type": "application/json"
    },
    body: JSON.stringify({ access_token: accessToken })
  });

  const addJson = await addResp.json().catch(() => ({}));
  if (!addResp.ok && addResp.status !== 201 && addResp.status !== 204) {
    console.error("guild join error:", addResp.status, addJson);
    return res.status(500).send("Failed to add user to Discord server (check bot perms)");
  }

  // Look up Ghost tier to decide role
  let member = null;
  try {
    const r = await ghostFindMemberByEmail(email);
    member = r.data?.members?.[0] || null;
  } catch (e) {
    console.error("Ghost lookup failed:", e);
  }

  const sig = buildTierSig(member, email);
  const roleMap = parseRoleMap();

  // Decide a role name:
  // - If paid tiers exist, we take the first tier name
  // - Else we use status (e.g. "free")
  const roleKey =
    (sig.tierNames && sig.tierNames.length ? sig.tierNames[0] : sig.status || "free");

  const roleId = roleMap[roleKey] || null;

  if (roleId) {
    const roleResp = await fetch(
      `https://discord.com/api/guilds/${DISCORD_GUILD_ID}/members/${discordUserId}/roles/${roleId}`,
      {
        method: "PUT",
        headers: { Authorization: `Bot ${DISCORD_BOT_TOKEN}` }
      }
    );

    if (!roleResp.ok && roleResp.status !== 204) {
      const t = await roleResp.text().catch(() => "");
      console.error("role add failed:", roleResp.status, t);
      return res.status(500).send("Joined, but role assignment failed (check role hierarchy + permissions)");
    }
  } else {
    console.warn("No role matched for:", roleKey, "tiers:", sig.tierNames, "status:", sig.status);
  }

  // Success page (simple)
  return res
    .status(200)
    .send("Success! Your Discord access/role update is complete. You can close this tab.");
});

app.listen(Number(PORT), () => {
  console.log(`Hallway listening on port ${PORT}`);
});
