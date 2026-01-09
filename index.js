const express = require("express");
const fetch = require("node-fetch");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const morgan = require("morgan");

const app = express();
app.use(express.json());
app.use(morgan("combined"));

/* =====================
   ENV VARS (REQUIRED)
===================== */
const {
  PORT = 10000,

  // Ghost
  GHOST_ADMIN_API_URL,
  GHOST_ADMIN_API_KEY,

  // Sync
  SYNC_SECRET,

  // Discord OAuth
  DISCORD_CLIENT_ID,
  DISCORD_CLIENT_SECRET,
  DISCORD_REDIRECT_URI,
  DISCORD_BOT_TOKEN,
  DISCORD_GUILD_ID,

  // Optional: Role IDs (used later if you want auto-role assignment)
  ROLE_FREE,
  ROLE_APPRENTICE,
  ROLE_JOURNEYMAN,
  ROLE_MASTER,
  ROLE_GRANDMASTER,
} = process.env;

/* =====================
   HELPERS
===================== */
function ok(res, data) {
  return res.status(200).json(data);
}

// Always returns EXACTLY 32 hex chars
function hash32(input) {
  return crypto.createHash("sha256").update(String(input)).digest("hex").slice(0, 32);
}

function ghostAdminToken() {
  const [id, secret] = String(GHOST_ADMIN_API_KEY || "").split(":");
  if (!id || !secret) throw new Error("Missing/invalid GHOST_ADMIN_API_KEY");
  return jwt.sign(
    { iat: Math.floor(Date.now() / 1000), exp: Math.floor(Date.now() / 1000) + 300, aud: "/admin/" },
    Buffer.from(secret, "hex"),
    { algorithm: "HS256", keyid: id }
  );
}

async function findGhostMember(email) {
  const token = ghostAdminToken();
  const base = String(GHOST_ADMIN_API_URL || "").replace(/\/$/, "");
  const url = `${base}/ghost/api/admin/members/?filter=email:'${email}'&include=tiers,labels`;

  const r = await fetch(url, { headers: { Authorization: `Ghost ${token}` } });
  const json = await r.json();
  return json.members?.[0] || null;
}

function normalizeTierSig(member) {
  const tiers = (member?.tiers || []).map(t => t?.name).filter(Boolean).sort();
  return tiers.length ? tiers.join("|") : "none";
}

function normalizeLabelSig(member) {
  const labels = (member?.labels || []).map(l => l?.name).filter(Boolean).sort();
  return labels.length ? labels.join("|") : "none";
}

/* =====================
   HEALTH CHECK
===================== */
app.get("/health", (req, res) => ok(res, { ok: true }));

/* =====================
   ZAPIER ENTRY POINT
   (YOU SAID THIS MUST STAY /ghost/resolve-tier)
===================== */
app.post("/ghost/resolve-tier", async (req, res) => {
  try {
    if (req.body.sync_secret !== SYNC_SECRET) {
      return ok(res, { ok: false, error: "unauthorized" });
    }

    const email = String(req.body.email || "").toLowerCase().trim();
    if (!email) return ok(res, { ok: false, error: "missing email" });

    const member = await findGhostMember(email);

    const tierSig = normalizeTierSig(member);
    const labelSig = normalizeLabelSig(member);

    // This is the LONG human-readable key you keep seeing in Zapier (fine as an internal string)
    const raw_key = `guildhaven_email_sent:email:${email}:${tierSig}|labels:${labelSig}`;

    // ✅ This is what Zapier must use: ALWAYS 32 chars
    const storage_key = hash32(raw_key);

    // Discord OAuth link (what goes in the email)
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
      tierSig,
      labelSig,
      storage_key,      // <-- THIS stays "simple storage key" but now always 32 chars
      discord_link
    });
  } catch (e) {
    return ok(res, { ok: false, error: String(e?.message || e) });
  }
});

/* =====================
   DISCORD CALLBACK
===================== */
app.get("/discord/callback", async (req, res) => {
  try {
    const code = req.query.code;
    if (!code) return res.status(400).send("Missing code");

    // Exchange code for token
    const tokenRes = await fetch("https://discord.com/api/oauth2/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        client_id: DISCORD_CLIENT_ID,
        client_secret: DISCORD_CLIENT_SECRET,
        grant_type: "authorization_code",
        code: String(code),
        redirect_uri: DISCORD_REDIRECT_URI
      })
    });

    const tokenData = await tokenRes.json();
    if (!tokenData.access_token) {
      return res.status(400).send("Discord auth failed");
    }

    // Get Discord user
    const userRes = await fetch("https://discord.com/api/users/@me", {
      headers: { Authorization: `Bearer ${tokenData.access_token}` }
    });
    const user = await userRes.json();
    if (!user?.id) return res.status(400).send("Failed to fetch Discord user");

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
      const txt = await addRes.text().catch(() => "");
      return res.status(400).send(`Failed to add to guild: ${txt || addRes.status}`);
    }

    // NOTE: role assignment comes next AFTER this key issue is fixed (we can add it cleanly)

    return res.send(
      `<h2>✅ Discord Connected</h2>
       <p>You can now return to Discord.</p>`
    );
  } catch (e) {
    return res.status(500).send(String(e?.message || e));
  }
});

/* =====================
   START SERVER
===================== */
app.listen(PORT, () => {
  console.log(`🚀 GuildHaven Hallway running on ${PORT}`);
});
