/**
* GuildHaven Discord Hallway (Render)
* - Zapier -> POST /ghost/resolve-tier
* - Generates:
* - storage_key (32 chars, changes per membership event)
* - discord_link (OAuth URL with state=storage_key)
* - Discord OAuth callback:
* - joins user to guild
* - fetches Ghost member by Discord email
* - assigns correct tier role (and removes other tier roles)
*/

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
PORT = 10000,

// Ghost Admin API
GHOST_ADMIN_API_URL,
GHOST_ADMIN_API_KEY,

// Zap auth
SYNC_SECRET,

// Discord OAuth
DISCORD_CLIENT_ID,
DISCORD_CLIENT_SECRET,
DISCORD_REDIRECT_URI, // must be https://<your-domain>/discord/callback
DISCORD_BOT_TOKEN,
DISCORD_GUILD_ID,

// Discord Role IDs (strings)
ROLE_FREE,
ROLE_APPRENTICE,
ROLE_JOURNEYMAN,
ROLE_MASTER,
ROLE_GRANDMASTER
} = process.env;

/* =====================
BASIC VALIDATION
===================== */
function requireEnv(name) {
if (!process.env[name]) {
throw new Error(`Missing required env var: ${name}`);
}
}

// Hard requirements
requireEnv("GHOST_ADMIN_API_URL");
requireEnv("GHOST_ADMIN_API_KEY");
requireEnv("SYNC_SECRET");
requireEnv("DISCORD_CLIENT_ID");
requireEnv("DISCORD_CLIENT_SECRET");
requireEnv("DISCORD_REDIRECT_URI");
requireEnv("DISCORD_BOT_TOKEN");
requireEnv("DISCORD_GUILD_ID");

/* =====================
HELPERS
===================== */
function ok(res, data) {
return res.status(200).json(data);
}

function hash32(input) {
return crypto.createHash("sha256").update(String(input)).digest("hex").slice(0, 32);
}

function normalizeCsvList(str) {
if (!str) return [];
return String(str)
.split(",")
.map(s => s.trim())
.filter(Boolean);
}

function ghostAdminToken() {
const [id, secret] = String(GHOST_ADMIN_API_KEY).split(":");
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

async function ghostAdminFetch(path) {
const token = ghostAdminToken();
const base = String(GHOST_ADMIN_API_URL).replace(/\/$/, "");
const url = `${base}${path.startsWith("/") ? "" : "/"}${path}`;

const res = await fetch(url, {
headers: { Authorization: `Ghost ${token}` }
});

const text = await res.text();
let json;
try {
json = JSON.parse(text);
} catch {
json = { raw: text };
}

if (!res.ok) {
const msg = json?.errors?.[0]?.message || json?.error || `Ghost admin error (${res.status})`;
throw new Error(msg);
}

return json;
}

async function findGhostMemberByEmail(email) {
const safeEmail = String(email).replace(/'/g, "\\'");
const json = await ghostAdminFetch(
`/ghost/api/admin/members/?filter=email:'${safeEmail}'&include=tiers,labels`
);
return json?.members?.[0] || null;
}

/**
* Determine a single “effective tier name” from Ghost member tiers.
* If multiple tiers exist (rare), pick the first sorted by name.
*/
function getEffectiveTierName(member) {
const tiers = Array.isArray(member?.tiers) ? member.tiers : [];
if (!tiers.length) return "free";
const names = tiers.map(t => t?.name).filter(Boolean).sort();
return names[0] || "free";
}

function getLabelsSignature(member, labelsFromZap) {
const ghostLabels = Array.isArray(member?.labels) ? member.labels : [];
const names = ghostLabels.map(l => l?.name).filter(Boolean);
const merged = names.length ? names : normalizeCsvList(labelsFromZap);
return merged.length ? merged.sort().join("|") : "none";
}

/**
* Map tier name -> Discord Role ID (env vars)
* Adjust matching logic here if you rename tiers.
*/
function roleIdForTier(tierName) {
const t = String(tierName || "").toLowerCase();

// IMPORTANT: these match by keywords in the tier name.
// So "Journeyman 15% discount" and "Journeyman" both still match.
if (t.includes("grandmaster")) return ROLE_GRANDMASTER;
if (t.includes("master")) return ROLE_MASTER;
if (t.includes("journey")) return ROLE_JOURNEYMAN;
if (t.includes("apprentice")) return ROLE_APPRENTICE;

// default
return ROLE_FREE;
}

/**
* Remove all known tier roles from a user, then add the correct one.
*/
async function setTierRoleForDiscordUser(discordUserId, roleIdToAdd) {
const knownRoles = [ROLE_FREE, ROLE_APPRENTICE, ROLE_JOURNEYMAN, ROLE_MASTER, ROLE_GRANDMASTER]
.filter(Boolean);

// Remove all known tier roles first (prevents stacking)
for (const rid of knownRoles) {
await fetch(
`https://discord.com/api/guilds/${DISCORD_GUILD_ID}/members/${discordUserId}/roles/${rid}`,
{
method: "DELETE",
headers: { Authorization: `Bot ${DISCORD_BOT_TOKEN}` }
}
);
}

// Add the correct role
if (roleIdToAdd) {
const addRes = await fetch(
`https://discord.com/api/guilds/${DISCORD_GUILD_ID}/members/${discordUserId}/roles/${roleIdToAdd}`,
{
method: "PUT",
headers: { Authorization: `Bot ${DISCORD_BOT_TOKEN}` }
}
);

if (!addRes.ok) {
const txt = await addRes.text().catch(() => "");
throw new Error(`Failed to add role. Discord said ${addRes.status}: ${txt}`);
}
}
}

/* =====================
HEALTH CHECK
===================== */
app.get("/health", (req, res) => ok(res, { ok: true }));

/* =====================
ZAPIER ENTRY POINT
(DO NOT CHANGE PATH)
===================== */
app.post("/ghost/resolve-tier", async (req, res) => {
try {
if (req.body.sync_secret !== SYNC_SECRET) {
return ok(res, { ok: false, error: "unauthorized" });
}

const email = String(req.body.email || "").toLowerCase().trim();
const labelsFromZap = req.body.labels; // optional (your Zap has this)

if (!email) return ok(res, { ok: false, error: "missing email" });

// Pull canonical state from Ghost (tiers + labels + updated_at)
const member = await findGhostMemberByEmail(email);

// If Ghost member not found, still return something stable
const tierName = member ? getEffectiveTierName(member) : "unknown";
const labelsSig = member ? getLabelsSignature(member, labelsFromZap) : (labelsFromZap || "none");

// CRITICAL: eventStamp changes when membership changes (unsubscribe/resubscribe/upgrade/etc.)
const eventStamp =
member?.updated_at ||
member?.created_at ||
new Date().toISOString();

// This is the ONLY thing that should drive the Zapier Storage key.
// ALWAYS 32 chars.
const storage_key = hash32(`${email}|${tierName}|${labelsSig}|${eventStamp}`);

// Discord OAuth link goes into the email
// IMPORTANT: include "email" scope so callback can map to Ghost member reliably
const discord_link =
`https://discord.com/oauth2/authorize` +
`?client_id=${DISCORD_CLIENT_ID}` +
`&redirect_uri=${encodeURIComponent(DISCORD_REDIRECT_URI)}` +
`&response_type=code` +
`&scope=${encodeURIComponent("identify email guilds.join")}` +
`&state=${encodeURIComponent(storage_key)}`;

return ok(res, {
ok: true,
email,
tier_sig: tierName,
label_sig: labelsSig,
storage_key, // <- THIS is what Step 3 must use as Key
discord_link // <- THIS is what your email body should link to
});
} catch (err) {
return ok(res, {
ok: false,
error: String(err?.message || err || "unknown error")
});
}
});

/* =====================
DISCORD CALLBACK
===================== */
app.get("/discord/callback", async (req, res) => {
try {
const code = req.query.code;
if (!code) return res.status(400).send("Missing code");

// Exchange code -> access token
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
if (!tokenData?.access_token) {
return res.status(400).send("Discord auth failed (no access token)");
}

// Get Discord user (includes email ONLY if scope includes "email")
const userRes = await fetch("https://discord.com/api/users/@me", {
headers: { Authorization: `Bearer ${tokenData.access_token}` }
});
const user = await userRes.json();

if (!user?.id) {
return res.status(400).send("Discord user lookup failed");
}

// Join guild
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
const txt = await joinRes.text().catch(() => "");
return res.status(400).send(`Failed to join guild. Discord said ${joinRes.status}: ${txt}`);
}

// Assign tier role:
// We map Discord email -> Ghost member -> tier -> role
const discordEmail = String(user.email || "").toLowerCase().trim();

if (!discordEmail) {
// If email scope wasn’t granted, we can still join but cannot map tier safely.
return res.send(`
<h2>✅ Discord Connected</h2>
<p>You successfully joined the server, but Discord did not provide your email.</p>
<p>Please re-run the link and approve the <b>email</b> permission, or contact support.</p>
`);
}

const member = await findGhostMemberByEmail(discordEmail);
const tierName = member ? getEffectiveTierName(member) : "free";
const roleId = roleIdForTier(tierName);

// Apply role (remove other tier roles first)
await setTierRoleForDiscordUser(user.id, roleId);

return res.send(`
<h2>✅ Discord Connected</h2>
<p>You're in! Your membership role has been applied.</p>
<p>You can now return to Discord.</p>
`);
} catch (err) {
return res.status(500).send(`Server error: ${String(err?.message || err)}`);
}
});

/* =====================
START SERVER
===================== */
app.listen(PORT, () => {
console.log(`🚀 GuildHaven Hallway running on ${PORT}`);
});
