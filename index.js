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
  GHOST_ADMIN_API_URL,
  GHOST_ADMIN_API_KEY,
  SYNC_SECRET,
  DISCORD_CLIENT_ID,
  DISCORD_REDIRECT_URI
} = process.env;

/* ---------------- helpers ---------------- */

function ok(res, payload) {
  return res.status(200).json(payload);
}

function envCheck() {
  const missing = [];
  if (!GHOST_ADMIN_API_URL) missing.push("GHOST_ADMIN_API_URL");
  if (!GHOST_ADMIN_API_KEY) missing.push("GHOST_ADMIN_API_KEY");
  if (!SYNC_SECRET) missing.push("SYNC_SECRET");
  if (!DISCORD_CLIENT_ID) missing.push("DISCORD_CLIENT_ID");
  if (!DISCORD_REDIRECT_URI) missing.push("DISCORD_REDIRECT_URI");
  return missing;
}

function getProvidedSecret(req) {
  return (
    req.get("x-sync-secret") ||
    req.body?.sync_secret ||
    req.query?.sync_secret ||
    ""
  ).trim();
}

function makeGhostAdminToken() {
  const [id, secret] = GHOST_ADMIN_API_KEY.split(":");
  const now = Math.floor(Date.now() / 1000);
  return jwt.sign(
    { iat: now, exp: now + 300, aud: "/admin/" },
    Buffer.from(secret, "hex"),
    { algorithm: "HS256", keyid: id }
  );
}

async function ghostFindMemberByEmail(email) {
  const base = GHOST_ADMIN_API_URL.replace(/\/$/, "");
  const token = makeGhostAdminToken();

  const filter = `email:'${email.replace(/'/g, "\\'")}'`;
  const url = `${base}/ghost/api/admin/members/?filter=${encodeURIComponent(filter)}&include=tiers,labels`;

  const resp = await fetch(url, {
    headers: {
      Authorization: `Ghost ${token}`,
      Accept: "application/json"
    }
  });

  const data = await resp.json();
  return data.members?.[0] || null;
}

/* ---------------- routes ---------------- */

app.get("/health", (req, res) => {
  const missing = envCheck();
  if (missing.length) return ok(res, { ok: false, missing });
  return ok(res, { ok: true });
});

app.post("/ghost/resolve-member", async (req, res) => {
  const missing = envCheck();
  if (missing.length) return ok(res, { ok: false, missing });

  if (getProvidedSecret(req) !== SYNC_SECRET) {
    return ok(res, { ok: false, error: "unauthorized" });
  }

  const email = String(req.body.email || "").toLowerCase().trim();
  if (!email) return ok(res, { ok: false, error: "missing email" });

  const member = await ghostFindMemberByEmail(email);

  const tierNames = (member?.tiers || []).map(t => t.name).sort().join(",");
  const status = member?.status || "unknown";

  // 🔑 SHORT, SAFE, 32-CHAR KEY
  const rawKey = `${email}|${tierNames}|${status}`;
  const storage_key = crypto
    .createHash("sha256")
    .update(rawKey)
    .digest("hex")
    .slice(0, 32);

  // 🔐 Discord OAuth link
  const discord_link =
    `https://discord.com/oauth2/authorize` +
    `?client_id=${DISCORD_CLIENT_ID}` +
    `&redirect_uri=${encodeURIComponent(DISCORD_REDIRECT_URI)}` +
    `&response_type=code` +
    `&scope=identify%20guilds.join` +
    `&state=${encodeURIComponent(storage_key)}`;

  return ok(res, {
    ok: true,
    email,
    tier_names: tierNames,
    status,
    storage_key,
    discord_link
  });
});

app.listen(PORT, () => {
  console.log("Hallway running on", PORT);
});
