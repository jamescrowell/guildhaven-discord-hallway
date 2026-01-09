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

// Zapier auth
SYNC_SECRET,

// OAuth state signing
STATE_SECRET,

// Discord OAuth + Bot
DISCORD_CLIENT_ID,
DISCORD_CLIENT_SECRET,
DISCORD_REDIRECT_URI, // MUST be https://guildhaven-discord-hallway.onrender.com/discord/callback
DISCORD_BOT_TOKEN,
DISCORD_GUILD_ID,

// Role IDs (Discord role IDs)
ROLE_FREE,
ROLE_APPRENTICE,
ROLE_JOURNEYMAN,
ROLE_MASTER,
ROLE_GRANDMASTER
} = process.env;

/* =====================
HELPERS
===================== */
function ok(res, payload) {
return res.status(200).json(payload);
}

function hash32(input) {
return crypto.createHash("sha256").update(String(input)).digest("hex").slice(0, 32);
}

function requireEnv(name, value) {
if (!value) throw new Error(`Missing env var: ${name}`);
}

function makeGhostAdminToken() {
requireEnv("GHOST_ADMIN_API_KEY", GHOST_ADMIN_API_KEY);
const apiKey = String(GHOST_ADMIN_API_KEY).trim();
const [id, secret] = apiKey.split(":");
if (!id || !secret) throw new Error("GHOST_ADMIN_API_KEY must be id:secret");

const now = Math.floor(Date.now() / 1000);
return jwt.sign(
{ iat: now, exp: now + 300, aud: "/admin/" },
Buffer.from(secret, "hex"),
{ algorithm: "HS256", keyid: id }
);
}

async function ghostFindMemberByEmail(email) {
requireEnv("GHOST_ADMIN_API_URL", GHOST_ADMIN_API_URL);

const base = String(GHOST_ADMIN_API_URL).replace(/\/$/, "");
const token = makeGhostAdminToken();

// Include subscriptions so we can make a "resubscribe resets" signature
const filter = `email:'${String(email).replace(/'/g, "\\'")}'`;
const url = `${base}/ghost/api/admin/members/?filter=${encodeURIComponent(filter)}&include=labels,subscriptions,tiers`;

const resp = await fetch(url, {
method: "GET",
headers: {
Authorization: `Ghost ${token}`,
Accept: "application/json"
}
});

const text = await resp.text();
let data;
try { data = JSON.parse(text); } catch { data = { raw: text }; }

const member = data?.members?.[0] || null;
return { httpStatus: resp.status, member };
}

function getTierNames(member) {
const arr = Array.isArray(member?.tiers) ? member.tiers : [];
return arr.map(t => t?.name).filter(Boolean);
}

// THIS is the key to your “resubscribe resets” behavior.
// When someone cancels then later resubscribes (even to same tier), Ghost usually creates/updates a subscription.
// We fold in latest subscription signature so storage_key changes on true re-subscribe events.
function getLatestSubscriptionSig(member) {
const subs = Array.isArray(member?.subscriptions) ? member.subscriptions : [];
if (!subs.length) return "sub:none";

// Pick “latest” by updated_at / created_at / current_period_start / start_date
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
// Include multiple fields so any meaningful change produces a new signature
const sig = [
last.id || "noid",
last.status || "nostatus",
last.plan_id || "noplan",
last.tier_id || "notier",
last.created_at || "nocreated",
last.updated_at || "noupdated",
last.current_period_start || "nocps",
last.current_period_end || "nocpe"
].join("|");

return `sub:${sig}`;
}

function chooseRoleIdFromTierNames(tierNames) {
const joined = tierNames.map(t => String(t).toLowerCase()).join(" | ");
if (joined.includes("grandmaster")) return ROLE_GRANDMASTER;
if (joined.includes("master")) return ROLE_MASTER;
if (joined.includes("journeyman")) return ROLE_JOURNEYMAN;
if (joined.includes("apprentice")) return ROLE_APPRENTICE;
return ROLE_FREE;
}

function allTierRoleIds() {
return [ROLE_FREE, ROLE_APPRENTICE, ROLE_JOURNEYMAN, ROLE_MASTER, ROLE_GRANDMASTER].filter(Boolean);
}

function signState(payload) {
requireEnv("STATE_SECRET", STATE_SECRET);
const now = Math.floor(Date.now() / 1000);
return jwt.sign(
{ ...payload, iat: now, exp: now + 10 * 60 },
STATE_SECRET,
{ algorithm: "HS256" }
);
}

function verifyState(token) {
requireEnv("STATE_SECRET", STATE_SECRET);
return jwt.verify(token, STATE_SECRET, { algorithms: ["HS256"] });
}

/* =====================
HEALTH
===================== */
app.get("/health", (req, res) => ok(res, { ok: true }));

/* =====================
ZAPIER ENTRY POINT
(KEEP THIS NAME)
POST /ghost/resolve-tier
===================== */
app.post("/ghost/resolve-tier", async (req, res) => {
try {
if (String(req.body?.sync_secret || "").trim() !== String(SYNC_SECRET || "").trim()) {
return ok(res, { ok: false, error: "unauthorized" });
}

const email = String(req.body?.email || "").trim().toLowerCase();
if (!email) return ok(res, { ok: false, error: "missing email" });

const { member } = await ghostFindMemberByEmail(email);

const tierNames = getTierNames(member);
const tierSig = `tiers:${tierNames.slice().sort().join(",") || "none"}`;
const subSig = getLatestSubscriptionSig(member);

// ✅ SIMPLE storage_key field (you select THIS in Zapier)
// ✅ ≤ 32 chars
// ✅ “Resubscribe resets” because subSig changes when a new subscription is created/updated
const storage_key = hash32(`${email}|${tierSig}|${subSig}`);

// ✅ OAuth state carries tier info for role assignment
const stateToken = signState({ email, tier_names: tierNames });

requireEnv("DISCORD_CLIENT_ID", DISCORD_CLIENT_ID);
requireEnv("DISCORD_REDIRECT_URI", DISCORD_REDIRECT_URI);

// ✅ This is what you put in the email (use Webhooks step output -> discord_link)
const discord_link =
`https://discord.com/oauth2/authorize` +
`?client_id=${encodeURIComponent(DISCORD_CLIENT_ID)}` +
`&redirect_uri=${encodeURIComponent(DISCORD_REDIRECT_URI)}` +
`&response_type=code` +
`&scope=${encodeURIComponent("identify guilds.join")}` +
`&state=${encodeURIComponent(stateToken)}`;

return ok(res, {
ok: true,
email,
tier_names: tierNames,
storage_key,
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
requireEnv("DISCORD_CLIENT_ID", DISCORD_CLIENT_ID);
requireEnv("DISCORD_CLIENT_SECRET", DISCORD_CLIENT_SECRET);
requireEnv("DISCORD_REDIRECT_URI", DISCORD_REDIRECT_URI);
requireEnv("DISCORD_BOT_TOKEN", DISCORD_BOT_TOKEN);
requireEnv("DISCORD_GUILD_ID", DISCORD_GUILD_ID);

const code = String(req.query.code || "").trim();
const state = String(req.query.state || "").trim();
if (!code) return res.status(400).send("Missing code");
if (!state) return res.status(400).send("Missing state");

const decoded = verifyState(state);
const tierNames = Array.isArray(decoded?.tier_names) ? decoded.tier_names : [];

// Exchange code -> token
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
console.error("Token exchange failed:", tokenData);
return res.status(400).send("Discord auth failed");
}

// Get user
const userRes = await fetch("https://discord.com/api/users/@me", {
headers: { Authorization: `Bearer ${tokenData.access_token}` }
});
const user = await userRes.json();
if (!user?.id) return res.status(400).send("Discord user lookup failed");

// Add to guild
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
return res.status(500).send("Joined server failed (bot permissions or token issue).");
}

// Role assignment
const roleToAdd = chooseRoleIdFromTierNames(tierNames);
const tierRoles = allTierRoleIds();

// Remove all tier roles first (safe)
for (const rid of tierRoles) {
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

return res.send(`<h2>✅ Discord Connected</h2><p>You can return to Discord now.</p>`);
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
