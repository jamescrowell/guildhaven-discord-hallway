const express = require("express");
const fetch = require("node-fetch");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const morgan = require("morgan");

const app = express();
app.use(express.json({ limit: "1mb" }));
app.use(morgan("combined"));

/* =====================
   ENV VARS
===================== */
const {
  PORT = "10000",

  // Ghost Admin API
  GHOST_ADMIN_API_URL,
  GHOST_ADMIN_API_KEY,

  // Zapier secret
  SYNC_SECRET,

  // JWT secret for Discord state
  STATE_SECRET,

  // Discord OAuth + bot
  DISCORD_CLIENT_ID,
  DISCORD_CLIENT_SECRET,
  DISCORD_REDIRECT_URI, // MUST be https://guildhaven-discord-hallway.onrender.com/discord/callback
  DISCORD_BOT_TOKEN,
  DISCORD_GUILD_ID,

  // Discord Role IDs
  ROLE_FREE,
  ROLE_APPRENTICE,
  ROLE_JOURNEYMAN,
  ROLE_MASTER,
  ROLE_GRANDMASTER
} = process.env;

/* =====================
   UTIL
===================== */
function ok(res, payload) {
  return res.status(200).json(payload);
}

function envMissing() {
  const missing = [];
  const req = [
    ["GHOST_ADMIN_API_URL", GHOST_ADMIN_API_URL],
    ["GHOST_ADMIN_API_KEY", GHOST_ADMIN_API_KEY],
    ["SYNC_SECRET", SYNC_SECRET],
    ["STATE_SECRET", STATE_SECRET],
    ["DISCORD_CLIENT_ID", DISCORD_CLIENT_ID],
    ["DISCORD_CLIENT_SECRET", DISCORD_CLIENT_SECRET],
    ["DISCORD_REDIRECT_URI", DISCORD_REDIRECT_URI],
    ["DISCORD_BOT_TOKEN", DISCORD_BOT_TOKEN],
    ["DISCORD_GUILD_ID", DISCORD_GUILD_ID]
  ];
  for (const [k, v] of req) if (!v) missing.push(k);
  return missing;
}

// ALWAYS 32 chars, no exceptions.
function hash32(input) {
  return crypto.createHash("sha256").update(String(input)).digest("hex").slice(0, 32);
}

function makeGhostAdminToken() {
  const apiKey = String(GHOST_ADMIN_API_KEY || "").trim();
  const [id, secret] = apiKey.split(":");
  if (!id || !secret) throw new Error("GHOST_ADMIN_API_KEY must be in format id:secret");

  const now = Math.floor(Date.now() / 1000);
  return jwt.sign(
    { iat: now, exp: now + 300, aud: "/admin/" },
    Buffer.from(secret, "hex"),
    { algorithm: "HS256", keyid: id }
  );
}

async function ghostFindMemberByEmail(email) {
  const base = String(GHOST_ADMIN_API_URL).replace(/\/$/, "");
  const token = makeGhostAdminToken();

  const filter = `email:'${String(email).replace(/'/g, "\\'")}'`;
  const url =
    `${base}/ghost/api/admin/members/` +
    `?filter=${encodeURIComponent(filter)}` +
    `&include=tiers,labels,subscriptions`;

  const resp = await fetch(url, {
    method: "GET",
    headers: { Authorization: `Ghost ${token}`, Accept: "application/json" }
  });

  const text = await resp.text();
  let data;
  try { data = JSON.parse(text); } catch { data = { raw: text }; }

  const member = data?.members?.[0] || null;
  return { httpStatus: resp.status, member };
}

function getTierNames(member) {
  const tiers = Array.isArray(member?.tiers) ? member.tiers : [];
  return tiers.map(t => t?.name).filter(Boolean);
}

function getLabelSlugs(member) {
  const labels = Array.isArray(member?.labels) ? member.labels : [];
  return labels.map(l => l?.slug).filter(Boolean);
}

// Make a signature that changes on true resubscribe / renewal changes.
// This is what makes your Storage key "reset" logically.
function getLatestSubscriptionSig(member) {
  const subs = Array.isArray(member?.subscriptions) ? member.subscriptions : [];
  if (!subs.length) return "sub:none";

  const scored = subs
    .map(s => {
      const ts =
        Date.parse(s?.updated_at || "") ||
        Date.parse(s?.created_at || "") ||
        Date.parse(s?.current_period_start || "") ||
        Date.parse(s?.start_date || "") ||
        0;
      return { s, ts };
    })
    .sort((a, b) => b.ts - a.ts);

  const last = scored[0]?.s || {};
  return [
    last.id || "noid",
    last.status || "nostatus",
    last.tier_id || "notier",
    last.plan_id || "noplan",
    last.created_at || "nocreated",
    last.updated_at || "noupdated",
    last.current_period_start || "nocps",
    last.current_period_end || "nocpe"
  ].join("|");
}

function signState(payload) {
  const now = Math.floor(Date.now() / 1000);
  return jwt.sign(
    { ...payload, iat: now, exp: now + 10 * 60 },
    String(STATE_SECRET),
    { algorithm: "HS256" }
  );
}

function verifyState(token) {
  return jwt.verify(token, String(STATE_SECRET), { algorithms: ["HS256"] });
}

function allTierRoleIds() {
  return [ROLE_FREE, ROLE_APPRENTICE, ROLE_JOURNEYMAN, ROLE_MASTER, ROLE_GRANDMASTER].filter(Boolean);
}

function chooseRoleId(tierNames, labelSlugs) {
  const t = tierNames.map(x => String(x).toLowerCase()).join(" | ");
  const l = labelSlugs.map(x => String(x).toLowerCase()).join(" | ");

  // Prefer tier name matching first (most reliable)
  if (t.includes("grandmaster")) return ROLE_GRANDMASTER;
  if (t.includes("master")) return ROLE_MASTER;
  if (t.includes("journeyman")) return ROLE_JOURNEYMAN;
  if (t.includes("apprentice")) return ROLE_APPRENTICE;

  // Fallback to labels if your Ghost tiers are weirdly named
  if (l.includes("grandmaster")) return ROLE_GRANDMASTER;
  if (l.includes("master")) return ROLE_MASTER;
  if (l.includes("journeyman")) return ROLE_JOURNEYMAN;
  if (l.includes("apprentice")) return ROLE_APPRENTICE;

  return ROLE_FREE;
}

/* =====================
   HEALTH
===================== */
app.get("/health", (req, res) => {
  const missing = envMissing();
  ok(res, { ok: missing.length === 0, missing });
});

/* =====================
   ZAPIER ENTRY POINT
   KEEP THIS EXACT PATH:
   POST /ghost/resolve-tier
===================== */
app.post("/ghost/resolve-tier", async (req, res) => {
  try {
    const missing = envMissing();
    if (missing.length) return ok(res, { ok: false, error: "missing_env", missing });

    if (String(req.body?.sync_secret || "") !== String(SYNC_SECRET)) {
      return ok(res, { ok: false, error: "unauthorized" });
    }

    const email = String(req.body?.email || "").trim().toLowerCase();
    if (!email) return ok(res, { ok: false, error: "missing_email" });

    const { member } = await ghostFindMemberByEmail(email);

    const tierNames = getTierNames(member);
    const labelSlugs = getLabelSlugs(member);
    const subSig = getLatestSubscriptionSig(member);

    // ✅ THE ONLY STORAGE KEY YOU USE IN ZAPIER (EXACTLY 32 CHARS)
    const storage_key = hash32(`${email}|tiers:${tierNames.slice().sort().join(",")}|labels:${labelSlugs.slice().sort().join(",")}|sub:${subSig}`);

    // Put email in signed state so callback can fetch live member status again
    const state = signState({ email });

    const discord_link =
      `https://discord.com/oauth2/authorize` +
      `?client_id=${encodeURIComponent(DISCORD_CLIENT_ID)}` +
      `&redirect_uri=${encodeURIComponent(DISCORD_REDIRECT_URI)}` +
      `&response_type=code` +
      `&scope=${encodeURIComponent("identify guilds.join")}` +
      `&state=${encodeURIComponent(state)}`;

    // IMPORTANT: do not return any other “key” fields that could be mistakenly used in Zapier storage
    return ok(res, {
      ok: true,
      email,
      storage_key,
      storage_key_len: String(storage_key).length, // should always be 32
      discord_link
    });
  } catch (e) {
    console.error("[resolve-tier] error:", e);
    return ok(res, { ok: false, error: e.message || String(e) });
  }
});

/* =====================
   DISCORD CALLBACK
===================== */
app.get("/discord/callback", async (req, res) => {
  try {
    const missing = envMissing();
    if (missing.length) return res.status(500).send(`Missing env vars: ${missing.join(", ")}`);

    const code = String(req.query.code || "").trim();
    const stateToken = String(req.query.state || "").trim();
    if (!code) return res.status(400).send("Missing code");
    if (!stateToken) return res.status(400).send("Missing state");

    const decoded = verifyState(stateToken);
    const email = String(decoded?.email || "").trim().toLowerCase();
    if (!email) return res.status(400).send("Bad state (no email)");

    // Exchange code for access token
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
      console.error("Discord token exchange failed:", tokenData);
      return res.status(400).send("Discord auth failed");
    }

    // Get Discord user id
    const userRes = await fetch("https://discord.com/api/users/@me", {
      headers: { Authorization: `Bearer ${tokenData.access_token}` }
    });
    const user = await userRes.json();
    if (!user?.id) return res.status(400).send("Discord user lookup failed");

    // Add user to guild
    const joinRes = await fetch(
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
    if (!joinRes.ok) {
      const t = await joinRes.text().catch(() => "");
      console.error("Guild join failed:", joinRes.status, t);
      return res.status(500).send("Joined server failed (bot permissions/role hierarchy).");
    }

    // Fetch LIVE Ghost member data at callback time (so tier/labels are accurate)
    const { member } = await ghostFindMemberByEmail(email);
    const tierNames = getTierNames(member);
    const labelSlugs = getLabelSlugs(member);

    const roleToAdd = chooseRoleId(tierNames, labelSlugs);
    const tierRoleIds = allTierRoleIds();

    // Remove all tier roles first
    for (const rid of tierRoleIds) {
      await fetch(
        `https://discord.com/api/guilds/${DISCORD_GUILD_ID}/members/${user.id}/roles/${rid}`,
        { method: "DELETE", headers: { Authorization: `Bot ${DISCORD_BOT_TOKEN}` } }
      ).catch(() => {});
    }

    // Add correct tier role
    if (roleToAdd) {
      const roleRes = await fetch(
        `https://discord.com/api/guilds/${DISCORD_GUILD_ID}/members/${user.id}/roles/${roleToAdd}`,
        { method: "PUT", headers: { Authorization: `Bot ${DISCORD_BOT_TOKEN}` } }
      );
      if (!roleRes.ok) {
        const t = await roleRes.text().catch(() => "");
        console.error("Add role failed:", roleRes.status, t);
        return res
          .status(500)
          .send("✅ Connected + joined, but role assignment failed (bot role hierarchy/permissions).");
      }
    }

    return res.send(`<h2>✅ Discord Connected</h2><p>Your role has been synced. You can return to Discord.</p>`);
  } catch (e) {
    console.error("[callback] error:", e);
    return res.status(500).send(`Server error: ${e.message || String(e)}`);
  }
});

/* =====================
   START
===================== */
app.listen(Number(PORT), () => {
  console.log(`🚀 GuildHaven Hallway running on port ${PORT}`);
});
