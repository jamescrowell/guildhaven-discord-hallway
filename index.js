const express = require("express");
const fetch = require("node-fetch");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const morgan = require("morgan");

const app = express();
app.use(express.json({ limit: "1mb" }));
app.use(morgan("combined"));

/* =====================
   ENV VARS (REQUIRED)
===================== */
const {
  PORT = "10000",

  // Ghost
  GHOST_ADMIN_API_URL,
  GHOST_ADMIN_API_KEY,

  // Sync
  SYNC_SECRET,

  // Discord OAuth + Bot
  DISCORD_CLIENT_ID,
  DISCORD_CLIENT_SECRET,
  DISCORD_REDIRECT_URI, // must be .../discord/callback
  DISCORD_BOT_TOKEN,
  DISCORD_GUILD_ID,

  // Tier role IDs (YOUR NAMES)
  ROLE_FREE,
  ROLE_APPRENTICE,
  ROLE_JOURNEYMAN,
  ROLE_MASTER,
  ROLE_GRANDMASTER,

  // State signing secret (use what you already set)
  STATE_SECRET
} = process.env;

/* =====================
   HELPERS
===================== */
function ok(res, data) {
  return res.status(200).json(data);
}

function requireEnv(name) {
  if (!process.env[name] || !String(process.env[name]).trim()) {
    throw new Error(`Missing env var: ${name}`);
  }
}

function hash32(input) {
  return crypto.createHash("sha256").update(String(input)).digest("hex").slice(0, 32);
}

function ghostAdminToken() {
  const apiKey = (GHOST_ADMIN_API_KEY || "").trim();
  const [id, secret] = apiKey.split(":");
  if (!id || !secret) throw new Error("GHOST_ADMIN_API_KEY must be id:secret");

  const now = Math.floor(Date.now() / 1000);
  return jwt.sign(
    { iat: now, exp: now + 300, aud: "/admin/" },
    Buffer.from(secret, "hex"),
    { algorithm: "HS256", keyid: id }
  );
}

async function findGhostMemberByEmail(email) {
  const base = (GHOST_ADMIN_API_URL || "").replace(/\/$/, "");
  const token = ghostAdminToken();

  const filter = `email:'${String(email).replace(/'/g, "\\'")}'`;
  const url =
    `${base}/ghost/api/admin/members/?filter=${encodeURIComponent(filter)}` +
    `&include=tiers,labels,subscriptions`;

  const resp = await fetch(url, {
    method: "GET",
    headers: {
      Authorization: `Ghost ${token}`,
      Accept: "application/json",
      "Content-Type": "application/json"
    }
  });

  const text = await resp.text();
  let data;
  try { data = JSON.parse(text); } catch { data = {}; }

  return (data.members && data.members[0]) ? data.members[0] : null;
}

function signState(payload) {
  const secret = (STATE_SECRET || "").trim();
  if (!secret) throw new Error("STATE_SECRET missing");
  return jwt.sign(payload, secret, { expiresIn: "20m" });
}

function verifyState(state) {
  const secret = (STATE_SECRET || "").trim();
  if (!secret) throw new Error("STATE_SECRET missing");
  return jwt.verify(state, secret);
}

// Normalize tier names for matching
function normalize(s) {
  return String(s || "").trim().toLowerCase();
}

/**
 * Map Ghost tier -> Discord role id (using YOUR env vars)
 * Adjust the keyword checks if your tier names differ.
 */
function roleIdForMember(member) {
  const tierNames = Array.isArray(member?.tiers)
    ? member.tiers.map(t => t?.name).filter(Boolean)
    : [];

  const tiers = tierNames.map(normalize);

  // Example keyword matching:
  // If your Ghost tier names are EXACT like "Apprentice", "Journeyman", etc,
  // these will match perfectly.
  if (tiers.some(t => t.includes("grandmaster"))) return ROLE_GRANDMASTER;
  if (tiers.some(t => t.includes("master"))) return ROLE_MASTER;
  if (tiers.some(t => t.includes("journeyman"))) return ROLE_JOURNEYMAN;
  if (tiers.some(t => t.includes("apprentice"))) return ROLE_APPRENTICE;

  // Optional: If you want free members to still get a role:
  if (ROLE_FREE) return ROLE_FREE;

  return null;
}

function allTierRoleIds() {
  // we remove these before adding the correct one
  return [ROLE_FREE, ROLE_APPRENTICE, ROLE_JOURNEYMAN, ROLE_MASTER, ROLE_GRANDMASTER]
    .map(v => String(v || "").trim())
    .filter(Boolean);
}

/* =====================
   HEALTH
===================== */
app.get("/health", (req, res) => {
  try {
    // only check essentials (don’t block health if optional role envs missing)
    requireEnv("GHOST_ADMIN_API_URL");
    requireEnv("GHOST_ADMIN_API_KEY");
    requireEnv("SYNC_SECRET");
    requireEnv("DISCORD_CLIENT_ID");
    requireEnv("DISCORD_CLIENT_SECRET");
    requireEnv("DISCORD_REDIRECT_URI");
    requireEnv("DISCORD_BOT_TOKEN");
    requireEnv("DISCORD_GUILD_ID");
    requireEnv("STATE_SECRET");
    return ok(res, { ok: true });
  } catch (e) {
    return ok(res, { ok: false, error: e.message });
  }
});

/* =====================
   ZAPIER ENTRY POINT
   KEEP THIS ROUTE NAME
===================== */
app.post("/ghost/resolve-tier", async (req, res) => {
  try {
    const provided = String(req.body?.sync_secret || "").trim();
    if (!provided) return ok(res, { ok: false, error: "Missing sync_secret" });
    if (provided !== String(SYNC_SECRET || "").trim()) return ok(res, { ok: false, error: "Unauthorized" });

    const email = String(req.body?.email || "").trim().toLowerCase();
    if (!email) return ok(res, { ok: false, error: "Missing email" });

    const member = await findGhostMemberByEmail(email);

    const tierNames = Array.isArray(member?.tiers) ? member.tiers.map(t => t?.name).filter(Boolean) : [];
    const tierSig = tierNames.slice().sort().join("|") || "none";

    // ✅ Simple, Zapier-safe storage key (<=32 chars)
    const storage_key = hash32(`${email}|${tierSig}`);

    // Signed state carries the email so callback can re-check Ghost and assign roles
    const state = signState({ email });

    // ✅ THIS is the link you put in the email (from Webhook step output)
    const discord_link =
      `https://discord.com/oauth2/authorize` +
      `?client_id=${encodeURIComponent(DISCORD_CLIENT_ID)}` +
      `&redirect_uri=${encodeURIComponent(DISCORD_REDIRECT_URI)}` +
      `&response_type=code` +
      `&scope=${encodeURIComponent("identify guilds.join")}` +
      `&state=${encodeURIComponent(state)}`;

    return ok(res, {
      ok: true,
      email,
      tier_names: tierNames,
      storage_key,
      discord_link
    });
  } catch (e) {
    return ok(res, { ok: false, error: e.message || String(e) });
  }
});

/* =====================
   DISCORD CALLBACK
   MUST MATCH REDIRECT URI
===================== */
app.get("/discord/callback", async (req, res) => {
  try {
    const code = String(req.query.code || "");
    const state = String(req.query.state || "");

    if (!code) return res.status(400).send("Missing code");
    if (!state) return res.status(400).send("Missing state");

    // 1) Decode email from state
    const decoded = verifyState(state);
    const email = String(decoded?.email || "").trim().toLowerCase();
    if (!email) return res.status(400).send("Invalid state (no email)");

    // 2) Exchange code -> access token
    const tokenRes = await fetch("https://discord.com/api/oauth2/token", {
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

    const tokenData = await tokenRes.json();
    if (!tokenData?.access_token) {
      return res.status(400).send("Discord token exchange failed");
    }

    // 3) Get Discord user
    const userRes = await fetch("https://discord.com/api/users/@me", {
      headers: { Authorization: `Bearer ${tokenData.access_token}` }
    });
    const user = await userRes.json();
    if (!user?.id) return res.status(400).send("Could not read Discord user");

    // 4) Add/update member in guild (guilds.join)
    await fetch(`https://discord.com/api/guilds/${DISCORD_GUILD_ID}/members/${user.id}`, {
      method: "PUT",
      headers: {
        Authorization: `Bot ${DISCORD_BOT_TOKEN}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ access_token: tokenData.access_token })
    });

    // 5) Look up Ghost again to get authoritative tier
    const member = await findGhostMemberByEmail(email);

    // 6) Compute correct role id
    const targetRoleId = roleIdForMember(member);

    // 7) Remove other tier roles first (prevents stacking after upgrades/downgrades)
    const tierRoles = allTierRoleIds();
    for (const rid of tierRoles) {
      // skip removing the role we will add back
      if (targetRoleId && rid === String(targetRoleId).trim()) continue;

      // DELETE role from member (ignore failures)
      await fetch(
        `https://discord.com/api/guilds/${DISCORD_GUILD_ID}/members/${user.id}/roles/${rid}`,
        { method: "DELETE", headers: { Authorization: `Bot ${DISCORD_BOT_TOKEN}` } }
      ).catch(() => {});
    }

    // 8) Add the correct tier role (if we found one)
    if (targetRoleId) {
      await fetch(
        `https://discord.com/api/guilds/${DISCORD_GUILD_ID}/members/${user.id}/roles/${targetRoleId}`,
        { method: "PUT", headers: { Authorization: `Bot ${DISCORD_BOT_TOKEN}` } }
      );
    }

    return res.send(`
      <h2>✅ Discord Connected</h2>
      <p>You're in. You can return to Discord now.</p>
    `);
  } catch (e) {
    return res.status(500).send(`Callback error: ${e.message || String(e)}`);
  }
});

/* =====================
   START
===================== */
app.listen(Number(PORT), () => {
  console.log(`🚀 GuildHaven Hallway running on port ${PORT}`);
});
