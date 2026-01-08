import "dotenv/config";
import express from "express";
import crypto from "crypto";

const app = express();
app.use(express.json());

// -------------------- ENV --------------------
const {
  PORT = 3000,
  BASE_URL,

  DISCORD_CLIENT_ID,
  DISCORD_CLIENT_SECRET,
  DISCORD_REDIRECT_URI,
  DISCORD_GUILD_ID,
  DISCORD_BOT_TOKEN,

  STATE_SECRET,

  // Paid roles (Free is join-only)
  ROLE_APPRENTICE,
  ROLE_JOURNEYMAN,
  ROLE_MASTER,
  ROLE_GRANDMASTER,

  // Optional logging to Zapier (for your Sheets/log zap)
  ZAPIER_WEBHOOK_URL,

  // Optional: redirect users to a nice page after success
  SUCCESS_REDIRECT_URL,

  // For Zapier -> hallway server-to-server calls (auto upgrades/downgrades)
  SYNC_SECRET,
} = process.env;

const REQUIRED = [
  "BASE_URL",
  "DISCORD_CLIENT_ID",
  "DISCORD_CLIENT_SECRET",
  "DISCORD_REDIRECT_URI",
  "DISCORD_GUILD_ID",
  "DISCORD_BOT_TOKEN",
  "STATE_SECRET",
  "SYNC_SECRET", // required once you enable auto sync
];

for (const k of REQUIRED) {
  if (!process.env[k]) {
    console.error(`Missing env var: ${k}`);
    process.exit(1);
  }
}

// -------------------- ROLE MAP --------------------
// ✅ free = join-only (no role assignment)
const ROLE_MAP = {
  free: null,
  apprentice: ROLE_APPRENTICE,
  journeyman: ROLE_JOURNEYMAN,
  master: ROLE_MASTER,
  grandmaster: ROLE_GRANDMASTER,
};

const TIER_ROLES = [
  ROLE_APPRENTICE,
  ROLE_JOURNEYMAN,
  ROLE_MASTER,
  ROLE_GRANDMASTER,
].filter(Boolean);

function normalizeTier(tier) {
  return String(tier || "").trim().toLowerCase();
}

function normalizeEmail(email) {
  return String(email || "").trim().toLowerCase();
}

// -------------------- STATE SIGNING (SECURITY) --------------------
function base64urlEncode(str) {
  return Buffer.from(str)
    .toString("base64")
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
}

function base64urlDecode(b64url) {
  const b64 = b64url.replace(/-/g, "+").replace(/_/g, "/");
  const pad = b64.length % 4 === 0 ? "" : "=".repeat(4 - (b64.length % 4));
  return Buffer.from(b64 + pad, "base64").toString("utf8");
}

function signState(payloadObj) {
  const payload = base64urlEncode(JSON.stringify(payloadObj));
  const sig = crypto
    .createHmac("sha256", STATE_SECRET)
    .update(payload)
    .digest("base64")
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
  return `${payload}.${sig}`;
}

function verifyState(state) {
  if (!state || !state.includes(".")) return null;

  const [payload, sig] = state.split(".");
  const expected = crypto
    .createHmac("sha256", STATE_SECRET)
    .update(payload)
    .digest("base64")
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");

  if (sig.length !== expected.length) return null;
  const ok = crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected));
  if (!ok) return null;

  try {
    return JSON.parse(base64urlDecode(payload));
  } catch {
    return null;
  }
}

// -------------------- HTML HELPERS --------------------
function page(title, msg) {
  return `<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>${title}</title>
  <style>
    body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial; padding:40px; line-height:1.5}
    .card{max-width:760px; border:1px solid #ddd; border-radius:16px; padding:24px}
    code{background:#f6f6f6; padding:2px 6px; border-radius:6px}
  </style>
</head>
<body>
  <div class="card">
    <h2>${title}</h2>
    <p>${msg}</p>
  </div>
</body>
</html>`;
}

// -------------------- DISCORD API HELPERS --------------------
async function discordFetch(url, options = {}) {
  const res = await fetch(url, options);
  const text = await res.text();
  let json;
  try {
    json = text ? JSON.parse(text) : null;
  } catch {
    json = null;
  }

  if (!res.ok) {
    const err = new Error(`Discord API error ${res.status} ${res.statusText}`);
    err.status = res.status;
    err.bodyText = text;
    err.bodyJson = json;
    err.url = url;
    throw err;
  }
  return json;
}

async function exchangeCodeForToken(code) {
  const params = new URLSearchParams();
  params.set("client_id", DISCORD_CLIENT_ID);
  params.set("client_secret", DISCORD_CLIENT_SECRET);
  params.set("grant_type", "authorization_code");
  params.set("code", code);
  params.set("redirect_uri", DISCORD_REDIRECT_URI);

  return await discordFetch("https://discord.com/api/oauth2/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: params,
  });
}

async function getDiscordUser(accessToken) {
  return await discordFetch("https://discord.com/api/users/@me", {
    headers: { Authorization: `Bearer ${accessToken}` },
  });
}

async function addUserToGuild({ userId, accessToken }) {
  return await discordFetch(
    `https://discord.com/api/guilds/${DISCORD_GUILD_ID}/members/${userId}`,
    {
      method: "PUT",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bot ${DISCORD_BOT_TOKEN}`,
      },
      body: JSON.stringify({ access_token: accessToken }),
    }
  );
}

async function addRoleToMember({ userId, roleId }) {
  return await discordFetch(
    `https://discord.com/api/guilds/${DISCORD_GUILD_ID}/members/${userId}/roles/${roleId}`,
    {
      method: "PUT",
      headers: { Authorization: `Bot ${DISCORD_BOT_TOKEN}` },
    }
  );
}

async function removeRoleFromMember({ userId, roleId }) {
  return await discordFetch(
    `https://discord.com/api/guilds/${DISCORD_GUILD_ID}/members/${userId}/roles/${roleId}`,
    {
      method: "DELETE",
      headers: { Authorization: `Bot ${DISCORD_BOT_TOKEN}` },
    }
  );
}

async function postToZapier(payload) {
  if (!ZAPIER_WEBHOOK_URL) return;
  try {
    await fetch(ZAPIER_WEBHOOK_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
  } catch (e) {
    console.warn("Zapier webhook failed:", e?.message || e);
  }
}

// -------------------- ZAPIER SECRET GUARD --------------------
function requireZapierSecret(req, res) {
  const got = req.header("x-sync-secret") || "";
  if (!SYNC_SECRET || got !== SYNC_SECRET) {
    res.status(401).json({ ok: false, error: "Unauthorized" });
    return false;
  }
  return true;
}

// -------------------- ROLE APPLICATION (BOT-ONLY) --------------------
async function applyTierRoles({ discordUserId, tier }) {
  const cleanTier = normalizeTier(tier);

  if (!(cleanTier in ROLE_MAP)) {
    const err = new Error(`Invalid tier: ${cleanTier}`);
    err.status = 400;
    throw err;
  }

  const roleId = ROLE_MAP[cleanTier] || null; // free => null

  // Always remove paid roles first (idempotent + safe)
  for (const r of TIER_ROLES) {
    if (!r) continue;
    try {
      await removeRoleFromMember({ userId: discordUserId, roleId: r });
    } catch {
      // ignore
    }
  }

  // Add paid role if applicable
  if (roleId) {
    await addRoleToMember({ userId: discordUserId, roleId });
  }

  return { tier: cleanTier, assignedRoleId: roleId };
}

// -------------------- ROUTES --------------------
app.get("/health", (req, res) => res.json({ ok: true }));

app.get("/", (req, res) => {
  res.send(
    page(
      "GuildHaven OAuth Hallway",
      `Use <code>/discord/start?tier=free&email=you@email.com</code> (join-only) or <code>/discord/start?tier=apprentice&email=you@email.com</code> (role assignment).`
    )
  );
});

/**
 * GET /discord/start
 * Example:
 * /discord/start?tier=apprentice&email=test@email.com
 */
app.get("/discord/start", (req, res) => {
  const tier = normalizeTier(req.query.tier);
  const email = String(req.query.email || "").trim();

  // ✅ free is valid even though ROLE_MAP.free is null
  if (!tier || !(tier in ROLE_MAP)) {
    return res
      .status(400)
      .send(
        page(
          "Missing or invalid tier",
          "Use: <code>free</code>, <code>apprentice</code>, <code>journeyman</code>, <code>master</code>, <code>grandmaster</code>."
        )
      );
  }

  const statePayload = {
    tier,
    email,
    ts: Date.now(),
    nonce: crypto.randomBytes(16).toString("hex"),
  };

  const state = signState(statePayload);

  const auth = new URL("https://discord.com/api/oauth2/authorize");
  auth.searchParams.set("client_id", DISCORD_CLIENT_ID);
  auth.searchParams.set("redirect_uri", DISCORD_REDIRECT_URI);
  auth.searchParams.set("response_type", "code");
  auth.searchParams.set("scope", "identify guilds.join");
  auth.searchParams.set("state", state);
  auth.searchParams.set("prompt", "consent");

  res.redirect(auth.toString());
});

/**
 * GET /discord/callback
 */
app.get("/discord/callback", async (req, res) => {
  const { code, state, error } = req.query;

  if (error) {
    return res
      .status(400)
      .send(page("Discord authorization failed", `Error: <code>${String(error)}</code>`));
  }

  if (!code || !state) {
    return res
      .status(400)
      .send(page("Missing code/state", "Please restart from the email link."));
  }

  const payload = verifyState(String(state));
  if (!payload) {
    return res
      .status(400)
      .send(page("Invalid state", "Security check failed. Please restart from the email link."));
  }

  // Expire links after 15 minutes
  const MAX_AGE_MS = 15 * 60 * 1000;
  if (Date.now() - payload.ts > MAX_AGE_MS) {
    return res.status(400).send(page("Link expired", "Please request a fresh link."));
  }

  const tier = normalizeTier(payload.tier);
  const email = payload.email || "";

  if (!(tier in ROLE_MAP)) {
    return res.status(400).send(page("Invalid tier", `Tier <code>${tier}</code> is not supported.`));
  }

  const roleId = ROLE_MAP[tier] || null; // free => null

  try {
    // 1) code -> token
    const token = await exchangeCodeForToken(String(code));
    const accessToken = token.access_token;

    // 2) identify user
    const user = await getDiscordUser(accessToken);
    const discordUserId = user.id;
    const discordUsername = user.username;

    // 3) add to guild
    await addUserToGuild({ userId: discordUserId, accessToken });

    // 4) assign role ONLY if paid tier
    if (roleId) {
      // remove other paid roles first
      for (const r of TIER_ROLES) {
        if (r && r !== roleId) {
          try {
            await removeRoleFromMember({ userId: discordUserId, roleId: r });
          } catch {}
        }
      }
      await addRoleToMember({ userId: discordUserId, roleId });
    }

    // 5) log to Zapier (optional)
    await postToZapier({
      event: "discord_onboarded",
      email,
      tier,
      discordUserId,
      discordUsername,
      joinedAt: new Date().toISOString(),
      source: "oauth_hallway",
    });

    // 6) success redirect or page
    if (SUCCESS_REDIRECT_URL) {
      const u = new URL(SUCCESS_REDIRECT_URL);
      u.searchParams.set("tier", tier);
      u.searchParams.set("discord", discordUserId);
      return res.redirect(u.toString());
    }

    const msg = roleId
      ? `You are in! <code>${discordUsername}</code> was added and assigned <code>${tier}</code>.`
      : `You are in! <code>${discordUsername}</code> was added to the server. (Free = no role assigned.)`;

    return res.send(page("Welcome to GuildHaven ✅", msg));
  } catch (e) {
    console.error("Callback error:", e);

    const status = e?.status ? `Discord status: <code>${e.status}</code>. ` : "";
    const hint =
      e?.status === 401
        ? "401 usually means your Bot Token is wrong."
        : e?.status === 403
        ? "403 usually means bot permissions/role hierarchy are wrong (bot role must be ABOVE the target role)."
        : e?.status === 404
        ? "404 usually means Guild ID or Role ID is wrong."
        : "Check Render logs for details.";

    return res.status(500).send(page("Something went wrong", `${status}${hint}`));
  }
});

/**
 * POST /discord/sync
 * Zapier calls this after Ghost tier changes (no OAuth, no clicks).
 * Body: { email, tier, discordUserId }
 * Header: x-sync-secret: <SYNC_SECRET>
 */
app.post("/discord/sync", async (req, res) => {
  if (!requireZapierSecret(req, res)) return;

  const email = normalizeEmail(req.body?.email);
  const tier = normalizeTier(req.body?.tier);
  const discordUserId = String(req.body?.discordUserId || "").trim();

  if (!email || !tier || !discordUserId) {
    return res.status(400).json({
      ok: false,
      error: "Missing required fields: email, tier, discordUserId",
    });
  }

  try {
    const result = await applyTierRoles({ discordUserId, tier });

    await postToZapier({
      event: "discord_synced",
      email,
      tier: result.tier,
      discordUserId,
      updatedAt: new Date().toISOString(),
      source: "zapier_sync",
    });

    return res.json({ ok: true, ...result });
  } catch (e) {
    console.error("Sync error:", e);
    return res.status(e?.status || 500).json({
      ok: false,
      error: e?.message || "Sync failed",
      discordStatus: e?.status || null,
    });
  }
});

/**
 * POST /discord/remove-paid
 * Zapier calls this when Ghost membership cancels.
 * Body: { email, discordUserId }
 * Header: x-sync-secret: <SYNC_SECRET>
 *
 * Behavior: removes all paid tier roles, keeps member in server.
 */
app.post("/discord/remove-paid", async (req, res) => {
  if (!requireZapierSecret(req, res)) return;

  const email = normalizeEmail(req.body?.email);
  const discordUserId = String(req.body?.discordUserId || "").trim();

  if (!email || !discordUserId) {
    return res.status(400).json({
      ok: false,
      error: "Missing required fields: email, discordUserId",
    });
  }

  try {
    for (const r of TIER_ROLES) {
      if (!r) continue;
      try {
        await removeRoleFromMember({ userId: discordUserId, roleId: r });
      } catch {}
    }

    await postToZapier({
      event: "discord_paid_removed",
      email,
      discordUserId,
      updatedAt: new Date().toISOString(),
      source: "zapier_cancel",
    });

    return res.json({ ok: true, removedPaidRoles: true });
  } catch (e) {
    console.error("Remove-paid error:", e);
    return res.status(e?.status || 500).json({
      ok: false,
      error: e?.message || "Remove paid roles failed",
      discordStatus: e?.status || null,
    });
  }
});

app.listen(PORT, () => {
  console.log(`GuildHaven hallway running on port ${PORT}`);
  console.log(`Base URL: ${BASE_URL}`);
});
