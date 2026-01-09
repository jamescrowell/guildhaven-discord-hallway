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
  DISCORD_REDIRECT_URI, // must match Discord Developer Portal redirect URI exactly
  DISCORD_BOT_TOKEN,
  DISCORD_GUILD_ID
} = process.env;

/* =====================
   HELPERS
===================== */
function ok(res, data) {
  return res.status(200).json(data);
}

function hash32(input) {
  // ALWAYS returns 32 chars (safe for Zapier Storage key limit)
  return crypto.createHash("sha256").update(String(input)).digest("hex").slice(0, 32);
}

function requireEnv(name) {
  if (!process.env[name] || !String(process.env[name]).trim()) {
    throw new Error(`Missing env var: ${name}`);
  }
}

function ghostAdminToken() {
  requireEnv("GHOST_ADMIN_API_KEY");
  const parts = String(GHOST_ADMIN_API_KEY).trim().split(":");
  const id = parts[0];
  const secret = parts[1];
  if (!id || !secret) throw new Error("GHOST_ADMIN_API_KEY must be in format id:secret");

  const now = Math.floor(Date.now() / 1000);
  return jwt.sign(
    { iat: now, exp: now + 300, aud: "/admin/" },
    Buffer.from(secret, "hex"),
    { algorithm: "HS256", keyid: id }
  );
}

async function findGhostMemberByEmail(email) {
  requireEnv("GHOST_ADMIN_API_URL");

  const base = String(GHOST_ADMIN_API_URL).replace(/\/$/, "");
  const token = ghostAdminToken();

  // include subscriptions so re-subscribe later can generate a NEW key
  const filter = `email:'${String(email).replace(/'/g, "\\'")}'`;
  const url =
    `${base}/ghost/api/admin/members/` +
    `?filter=${encodeURIComponent(filter)}` +
    `&include=tiers,labels,subscriptions`;

  const resp = await fetch(url, {
    method: "GET",
    headers: {
      Authorization: `Ghost ${token}`,
      Accept: "application/json"
    }
  });

  const text = await resp.text();
  let json;
  try { json = JSON.parse(text); } catch { json = null; }

  if (!resp.ok) {
    throw new Error(`Ghost error ${resp.status}: ${text.slice(0, 200)}`);
  }

  return (json && json.members && json.members[0]) ? json.members[0] : null;
}

function newestSubscriptionFingerprint(member) {
  // Goal: if someone cancels and later re-subscribes, Ghost usually creates a new subscription
  // We use newest subscription id (or created_at). If none, fallback to member.updated_at.
  const subs = Array.isArray(member?.subscriptions) ? member.subscriptions : [];
  const sorted = subs.slice().sort((a, b) =>
    String(b?.created_at || "").localeCompare(String(a?.created_at || ""))
  );

  const newest = sorted[0];
  const subId = newest?.id || "";
  const subCreated = newest?.created_at || "";
  const updated = member?.updated_at || "";

  return subId || subCreated || updated || "none";
}

/* =====================
   HEALTH
===================== */
app.get("/health", (req, res) => {
  const required = [
    "GHOST_ADMIN_API_URL",
    "GHOST_ADMIN_API_KEY",
    "SYNC_SECRET",
    "DISCORD_CLIENT_ID",
    "DISCORD_CLIENT_SECRET",
    "DISCORD_REDIRECT_URI",
    "DISCORD_BOT_TOKEN",
    "DISCORD_GUILD_ID"
  ];
  const missing = required.filter(k => !process.env[k] || !String(process.env[k]).trim());
  return ok(res, { ok: missing.length === 0, missing });
});

/* =====================
   ZAPIER ENTRY POINT
   KEEP THIS ROUTE NAME:
   /ghost/resolve-tier
===================== */
app.post("/ghost/resolve-tier", async (req, res) => {
  try {
    // Auth: allow header OR body (so you can keep your Zapier setup flexible)
    const provided =
      String(req.get("x-sync-secret") || req.get("X-Sync-Secret") || "").trim() ||
      String(req.body?.sync_secret || "").trim();

    if (!provided) return ok(res, { ok: false, error: "missing sync_secret" });
    if (provided !== String(SYNC_SECRET || "").trim()) return ok(res, { ok: false, error: "unauthorized" });

    const email = String(req.body?.email || "").toLowerCase().trim();
    if (!email) return ok(res, { ok: false, error: "missing email" });

    const member = await findGhostMemberByEmail(email);

    const tierNames = Array.isArray(member?.tiers)
      ? member.tiers.map(t => t?.name).filter(Boolean).sort().join("|")
      : "none";

    const memberId = member?.id || "no_member_id";
    const reSubFp = member ? newestSubscriptionFingerprint(member) : "none";

    // ✅ This is the ONLY key you should use in Zapier Storage.
    // It is ALWAYS 32 chars max.
    // It changes when: tier changes OR a new subscription is created later (re-subscribe).
    const storage_key = hash32(`${email}|${memberId}|${tierNames}|${reSubFp}`);

    // ✅ This is the link you should put in the email (or select from webhook output).
    requireEnv("DISCORD_CLIENT_ID");
    requireEnv("DISCORD_REDIRECT_URI");

    const discord_link =
      `https://discord.com/oauth2/authorize` +
      `?client_id=${encodeURIComponent(DISCORD_CLIENT_ID)}` +
      `&redirect_uri=${encodeURIComponent(DISCORD_REDIRECT_URI)}` +
      `&response_type=code` +
      `&scope=identify%20guilds.join` +
      `&state=${encodeURIComponent(storage_key)}`;

    return ok(res, {
      ok: true,
      email,
      member_found: !!member,
      tier_names: tierNames,
      storage_key,   // 👈 USE THIS IN STORAGE (<=32)
      discord_link   // 👈 USE THIS IN EMAIL BODY
    });
  } catch (e) {
    return ok(res, { ok: false, error: String(e?.message || e) });
  }
});

/* =====================
   DISCORD CALLBACK (MUST EXIST)
===================== */
app.get("/discord/callback", async (req, res) => {
  try {
    requireEnv("DISCORD_CLIENT_ID");
    requireEnv("DISCORD_CLIENT_SECRET");
    requireEnv("DISCORD_REDIRECT_URI");
    requireEnv("DISCORD_BOT_TOKEN");
    requireEnv("DISCORD_GUILD_ID");

    const code = String(req.query?.code || "").trim();
    if (!code) return res.status(400).send("Missing code");

    // Exchange code for token
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
      return res.status(400).send("Discord auth failed (no access_token).");
    }

    // Get Discord user
    const userRes = await fetch("https://discord.com/api/users/@me", {
      headers: { Authorization: `Bearer ${tokenData.access_token}` }
    });
    const user = await userRes.json();
    if (!user?.id) return res.status(400).send("Discord user lookup failed.");

    // Add to guild
    const addRes = await fetch(
      `https://discord.com/api/guilds/${DISCORD_GUILD_ID}/members/${user.id}`,
      {
        method: "PUT",
        headers: {
          Authorization: `Bot ${DISCORD_BOT_TOKEN}`,
          "Content-Type": "application/json"
        },
        body: JSON.stringify({ access_token: tokenData.access_token })
      }
    );

    if (!addRes.ok) {
      const t = await addRes.text();
      return res.status(400).send(`Failed to add to server: ${t.slice(0, 300)}`);
    }

    return res.send(`
      <h2>✅ Discord Connected</h2>
      <p>You can close this tab and return to Discord.</p>
    `);
  } catch (e) {
    return res.status(400).send(`Callback error: ${String(e?.message || e)}`);
  }
});

/* =====================
   START
===================== */
app.listen(Number(PORT), () => {
  console.log(`🚀 GuildHaven Hallway running on port ${PORT}`);
});
