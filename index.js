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

  // Sync secret shared with Zapier
  SYNC_SECRET,

  // Discord OAuth
  DISCORD_CLIENT_ID,
  DISCORD_CLIENT_SECRET,
  DISCORD_REDIRECT_URI,
  DISCORD_BOT_TOKEN,
  DISCORD_GUILD_ID,

  // Used to safely pass email through OAuth "state"
  STATE_SECRET,

  // Discord role IDs (must match your server role IDs)
  ROLE_FREE,
  ROLE_APPRENTICE,
  ROLE_JOURNEYMAN,
  ROLE_MASTER,
  ROLE_GRANDMASTER
} = process.env;

/* =====================
   HELPERS
===================== */
function ok(res, data) {
  return res.status(200).json(data);
}

function hash32(input) {
  return crypto.createHash("sha256").update(input).digest("hex").slice(0, 32);
}

function ghostAdminToken() {
  const [id, secret] = GHOST_ADMIN_API_KEY.split(":");
  return jwt.sign(
    {
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 300,
      aud: "/admin/"
    },
    Buffer.from(secret, "hex"),
    { algorithm: "HS256", keyid: id }
  );
}

async function findGhostMember(email) {
  const token = ghostAdminToken();
  const url =
    `${GHOST_ADMIN_API_URL.replace(/\/$/, "")}` +
    `/ghost/api/admin/members/?filter=email:'${email}'&include=tiers,labels`;

  const res = await fetch(url, {
    headers: { Authorization: `Ghost ${token}` }
  });

  const json = await res.json();
  return json.members?.[0] || null;
}

// Prefer highest tier if multiple
function pickTierName(member) {
  const tiers = (member?.tiers || []).map(t => t.name);
  if (!tiers.length) return null;

  // If you ever have multiple tiers, decide priority here:
  const priority = ["Grandmaster", "Master", "Journeyman", "Apprentice", "Free"];
  tiers.sort((a, b) => priority.indexOf(a) - priority.indexOf(b));
  return tiers[0];
}

function roleIdForTier(tierName) {
  if (!tierName) return null;
  const name = tierName.toLowerCase();

  if (name.includes("grandmaster")) return ROLE_GRANDMASTER;
  if (name.includes("master")) return ROLE_MASTER;
  if (name.includes("journey")) return ROLE_JOURNEYMAN;
  if (name.includes("apprentice")) return ROLE_APPRENTICE;
  if (name.includes("free")) return ROLE_FREE;

  // If tier names differ, add more mappings here
  return null;
}

async function addRole(discordUserId, roleId) {
  if (!roleId) return;

  await fetch(
    `https://discord.com/api/guilds/${DISCORD_GUILD_ID}/members/${discordUserId}/roles/${roleId}`,
    {
      method: "PUT",
      headers: { Authorization: `Bot ${DISCORD_BOT_TOKEN}` }
    }
  );
}

async function removeRole(discordUserId, roleId) {
  if (!roleId) return;

  await fetch(
    `https://discord.com/api/guilds/${DISCORD_GUILD_ID}/members/${discordUserId}/roles/${roleId}`,
    {
      method: "DELETE",
      headers: { Authorization: `Bot ${DISCORD_BOT_TOKEN}` }
    }
  );
}

async function syncRoles(discordUserId, desiredRoleId) {
  // Remove all known tier roles, then add the desired one
  const allRoles = [
    ROLE_FREE,
    ROLE_APPRENTICE,
    ROLE_JOURNEYMAN,
    ROLE_MASTER,
    ROLE_GRANDMASTER
  ].filter(Boolean);

  for (const r of allRoles) {
    if (r !== desiredRoleId) await removeRole(discordUserId, r);
  }
  await addRole(discordUserId, desiredRoleId);
}

/* =====================
   HEALTH CHECK
===================== */
app.get("/health", (req, res) => ok(res, { ok: true }));

/* =====================
   ZAPIER ENTRY POINT
   (You said keep /ghost/resolve-tier)
===================== */
app.post("/ghost/resolve-tier", async (req, res) => {
  if (req.body.sync_secret !== SYNC_SECRET) {
    return ok(res, { ok: false, error: "unauthorized" });
  }

  const email = String(req.body.email || "").toLowerCase().trim();
  if (!email) return ok(res, { ok: false, error: "missing email" });

  const member = await findGhostMember(email);

  const tierNames = member?.tiers?.map(t => t.name).sort().join("|") || "none";
  const labelNames = member?.labels?.map(l => l.name).sort().join("|") || "none";

  // This is ONLY for Zap Storage (must be ≤ 32 chars)
  const storage_key = hash32(`${email}:${tierNames}:${labelNames}`);

  // IMPORTANT: We also pass email safely through OAuth state via JWT.
  // This is what allows the callback to fetch Ghost + assign role.
  const state_token = jwt.sign(
    { email, storage_key },
    STATE_SECRET,
    { algorithm: "HS256", expiresIn: "30m" }
  );

  // Discord OAuth link (THIS is what goes in the email)
  const discord_link =
    `https://discord.com/oauth2/authorize` +
    `?client_id=${DISCORD_CLIENT_ID}` +
    `&redirect_uri=${encodeURIComponent(DISCORD_REDIRECT_URI)}` +
    `&response_type=code` +
    `&scope=identify%20guilds.join` +
    `&state=${encodeURIComponent(state_token)}`;

  ok(res, {
    ok: true,
    email,
    storage_key,
    tier_sig: tierNames === "none" ? "none" : hash32(tierNames),
    label_sig: labelNames === "none" ? "none" : hash32(labelNames),
    discord_link
  });
});

/* =====================
   DISCORD CALLBACK
   - joins user
   - looks up Ghost tier (by email in state token)
   - assigns correct role
===================== */
app.get("/discord/callback", async (req, res) => {
  try {
    const code = req.query.code;
    const state = req.query.state;
    if (!code) return res.status(400).send("Missing code");
    if (!state) return res.status(400).send("Missing state");

    // Verify + decode state token
    let decoded;
    try {
      decoded = jwt.verify(state, STATE_SECRET, { algorithms: ["HS256"] });
    } catch (e) {
      return res.status(400).send("Invalid/expired state token. Please request a new Discord link.");
    }

    const email = String(decoded.email || "").toLowerCase().trim();
    if (!email) return res.status(400).send("State token missing email.");

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
    if (!tokenData.access_token) {
      return res.status(400).send("Discord auth failed");
    }

    // Get Discord user
    const userRes = await fetch("https://discord.com/api/users/@me", {
      headers: { Authorization: `Bearer ${tokenData.access_token}` }
    });
    const user = await userRes.json();
    if (!user?.id) return res.status(400).send("Could not read Discord user.");

    // Add to guild
    await fetch(
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

    // Fetch Ghost member NOW (authoritative), decide tier role, assign
    const member = await findGhostMember(email);
    const tierName = pickTierName(member);
    const desiredRoleId = roleIdForTier(tierName);

    if (!desiredRoleId) {
      // If you want, you can default to ROLE_FREE here:
      // desiredRoleId = ROLE_FREE;
      return res.send(
        `<h2>✅ Discord Connected</h2>
         <p>We added you to the server, but couldn’t match your tier to a Discord role.</p>
         <p>Tier detected: <b>${tierName || "none"}</b></p>`
      );
    }

    await syncRoles(user.id, desiredRoleId);

    return res.send(
      `<h2>✅ Discord Connected</h2>
       <p>You’ve been added and your membership role has been applied.</p>
       <p>Tier detected: <b>${tierName}</b></p>
       <p>You can now return to Discord.</p>`
    );
  } catch (err) {
    console.error("Discord callback error:", err);
    return res.status(500).send("Server error during Discord callback.");
  }
});

/* =====================
   START SERVER
===================== */
app.listen(PORT, () => {
  console.log(`🚀 GuildHaven Hallway running on ${PORT}`);
});
