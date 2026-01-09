/**
 * GuildHaven Discord Hallway (Render)
 * - POST /ghost/resolve-tier  (Zapier calls this)
 * - GET  /health             (quick env check)
 *
 * Env Vars required:
 *   PORT (Render provides)
 *   GHOST_ADMIN_API_URL     e.g. https://your-site.ghost.io
 *   GHOST_ADMIN_API_KEY     Ghost Admin API key in format: id:secret
 *   SYNC_SECRET             shared secret between Zapier + this service
 *   DISCORD_OAUTH_URL       e.g. https://guildhaven-discord-hallway.onrender.com/discord/start
 */

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
  DISCORD_OAUTH_URL
} = process.env;

function ok(res, payload) {
  return res.status(200).json(payload);
}

function envCheck() {
  const missing = [];
  if (!GHOST_ADMIN_API_URL) missing.push("GHOST_ADMIN_API_URL");
  if (!GHOST_ADMIN_API_KEY) missing.push("GHOST_ADMIN_API_KEY");
  if (!SYNC_SECRET) missing.push("SYNC_SECRET");
  if (!DISCORD_OAUTH_URL) missing.push("DISCORD_OAUTH_URL");
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

  // Escape any single quotes in email for the Ghost filter syntax
  const safeEmail = String(email).replace(/'/g, "\\'");
  const filter = `email:'${safeEmail}'`;

  const url = `${base}/ghost/api/admin/members/?filter=${encodeURIComponent(
    filter
  )}&include=labels,subscriptions,tiers`;

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
  try {
    data = JSON.parse(text);
  } catch {
    data = { raw: text };
  }

  return { httpStatus: resp.status, data };
}

/**
 * We need a value that CHANGES when a user truly resubscribes later.
 * Best candidates come from subscription fields. Ghost can vary per setup,
 * so we try several, pick the most recent.
 */
function pickMembershipEpoch(member) {
  const subs = Array.isArray(member?.subscriptions) ? member.subscriptions : [];

  const candidates = [];
  for (const s of subs) {
    if (!s) continue;

    // Try a few possible fields Ghost may expose
    if (s.current_period_start) candidates.push(String(s.current_period_start));
    if (s.start_date) candidates.push(String(s.start_date));
    if (s.created_at) candidates.push(String(s.created_at));
    if (s.updated_at) candidates.push(String(s.updated_at));
  }

  // Fallbacks (still usually change if account deleted/recreated)
  if (member?.updated_at) candidates.push(String(member.updated_at));
  if (member?.created_at) candidates.push(String(member.created_at));

  // Use the most "recent-looking" candidate
  const best = candidates
    .map(v => v || "")
    .filter(Boolean)
    .sort()
    .slice(-1)[0];

  return best || "unknown";
}

/**
 * Build a stable but Zapier-safe 32-char key.
 * Zapier Storage key limit is 32 chars, so we hash.
 */
function toZapKey(longKey) {
  return crypto.createHash("md5").update(longKey).digest("hex"); // 32 chars
}

app.get("/health", (req, res) => {
  const missing = envCheck();
  if (missing.length) return ok(res, { ok: false, error: "Missing env vars", missing });

  return ok(res, {
    ok: true,
    service: "guildhaven-discord-hallway",
    has_discord_oauth_url: !!DISCORD_OAUTH_URL,
    ghost_admin_api_url: GHOST_ADMIN_API_URL
  });
});

/**
 * Zapier calls this on Ghost "Member Updated"
 * Body must contain: { email: "..." , sync_secret: "..." } OR header x-sync-secret
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

  console.log("[resolve-tier] email=", email);

  let member = null;
  let ghostError = null;
  let ghostHttp = null;

  try {
    const r = await ghostFindMemberByEmail(email);
    ghostHttp = r.httpStatus;
    member = r.data?.members?.[0] || null;
  } catch (e) {
    ghostError = e.message || String(e);
  }

  const memberId = member?.id || null;
  const status = member?.status || "unknown";

  const tierNames = Array.isArray(member?.tiers)
    ? member.tiers.map(t => t?.name).filter(Boolean)
    : [];

  const labels = Array.isArray(member?.labels)
    ? member.labels.map(l => l?.slug).filter(Boolean)
    : [];

  const membershipEpoch = member ? pickMembershipEpoch(member) : "unknown";

  // This signature changes when: tier changes OR subscription epoch changes (resubscribe)
  const tierSig = [
    `status:${status}`,
    `tiers:${tierNames.slice().sort().join(",")}`,
    `labels:${labels.slice().sort().join(",")}`,
    `epoch:${membershipEpoch}`
  ].join("|");

  // base identity
  const baseId = memberId ? `mid:${memberId}` : `email:${email}`;

  // This is human-readable but too long for Zapier Storage:
  const longKey = `gh:${baseId}:${tierSig}`;

  // Zapier-safe key (32 chars)
  const zap_key = toZapKey(longKey);

  // Discord link for the email
  // IMPORTANT: DISCORD_OAUTH_URL must be your actual OAuth start route that works in browser.
  let discord_link = null;
  try {
    const link = new URL(DISCORD_OAUTH_URL);
    link.searchParams.set("email", email);
    discord_link = link.toString();
  } catch (e) {
    // If DISCORD_OAUTH_URL is not a full URL, we return an explicit error
    return ok(res, {
      ok: false,
      error: "DISCORD_OAUTH_URL is not a valid full URL",
      hint: "Set DISCORD_OAUTH_URL like https://your-service.onrender.com/discord/start",
      details: String(e)
    });
  }

  // IMPORTANT: member-not-found is NOT fatal; we still return ok:true so Zapier can proceed.
  // (You can decide what to do with member_found in Zapier if you want.)
  return ok(res, {
    ok: true,
    email,
    member_found: !!member,
    ghost_http: ghostHttp,
    ghost_error: ghostError,
    ghost_status: status,
    tier_names: tierNames,
    labels,
    membership_epoch: membershipEpoch,
    tier_sig: tierSig,
    zap_key,        // ✅ USE THIS AS YOUR STORAGE KEY
    discord_link    // ✅ PUT THIS IN THE EMAIL BODY
  });
});

app.listen(Number(PORT), () => {
  console.log(`Hallway listening on port ${PORT}`);
});
