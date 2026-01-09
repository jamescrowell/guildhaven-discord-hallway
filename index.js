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

  // Discord OAuth (needed for /discord/start redirect)
  DISCORD_CLIENT_ID,
  DISCORD_REDIRECT_URI,
  DISCORD_SCOPES = "identify guilds.join",
  DISCORD_PERMISSIONS
} = process.env;

/* ------------------------- helpers ------------------------- */

function ok(res, payload) {
  return res.status(200).json(payload);
}

function baseUrlFromReq(req) {
  const proto = (req.get("x-forwarded-proto") || req.protocol || "https").split(",")[0].trim();
  const host = (req.get("x-forwarded-host") || req.get("host") || "").split(",")[0].trim();
  return `${proto}://${host}`;
}

function requiredCoreEnvMissing() {
  const missing = [];
  if (!GHOST_ADMIN_API_URL) missing.push("GHOST_ADMIN_API_URL");
  if (!GHOST_ADMIN_API_KEY) missing.push("GHOST_ADMIN_API_KEY");
  if (!SYNC_SECRET) missing.push("SYNC_SECRET");
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

function sha32Hex(input) {
  // Returns exactly 32 hex chars (safe for Storage by Zapier key)
  return crypto.createHash("sha256").update(String(input)).digest("hex").slice(0, 32);
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

  const filter = `email:'${String(email).replace(/'/g, "\\'")}'`;
  const url =
    `${base}/ghost/api/admin/members/` +
    `?filter=${encodeURIComponent(filter)}` +
    `&include=labels,subscriptions,tiers`;

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
  try { data = JSON.parse(text); } catch { data = { raw: text }; }
  return { httpStatus: resp.status, data };
}

function normalizeArray(arr) {
  return Array.isArray(arr) ? arr : [];
}

function buildTierSig(member) {
  const status = member && member.status ? String(member.status) : "unknown";

  const tierNames = normalizeArray(member && member.tiers)
    .map(t => t && t.name)
    .filter(Boolean)
    .map(String)
    .sort();

  const labels = normalizeArray(member && member.labels)
    .map(l => l && (l.slug || l.name))
    .filter(Boolean)
    .map(String)
    .sort();

  const subs = normalizeArray(member && member.subscriptions)
    .map(s => ({
      id: s && s.id ? String(s.id) : "",
      status: s && s.status ? String(s.status) : "",
      start: s && (s.current_period_start || s.start_date || s.created_at)
        ? String(s.current_period_start || s.start_date || s.created_at)
        : "",
      end: s && (s.current_period_end || s.cancel_at || s.ended_at)
        ? String(s.current_period_end || s.cancel_at || s.ended_at)
        : ""
    }))
    .filter(s => s.id || s.status || s.start || s.end)
    .sort((a, b) => (a.id + a.start).localeCompare(b.id + b.start));

  const subsSig = subs.map(s => `${s.id}:${s.status}:${s.start}:${s.end}`).join("|");

  return `${status}|tiers:${tierNames.join(",")}|labels:${labels.join(",")}|subs:${subsSig}`;
}

/* ------------------------- routes ------------------------- */

app.get("/health", (req, res) => {
  const missing = requiredCoreEnvMissing();
  if (missing.length) return ok(res, { ok: false, error: "Missing env vars", missing });
  return ok(res, { ok: true });
});

app.post("/ghost/resolve-tier", async (req, res) => {
  const missing = requiredCoreEnvMissing();
  if (missing.length) return ok(res, { ok: false, error: "Missing env vars", missing });

  const provided = getProvidedSecret(req);
  if (!provided) return ok(res, { ok: false, error: "Missing sync secret" });
  if (provided !== SYNC_SECRET) return ok(res, { ok: false, error: "Unauthorized (bad sync secret)" });

  const email = (req.body && req.body.email ? String(req.body.email) : "").trim().toLowerCase();
  if (!email) {
    return ok(res, {
      ok: false,
      error: "Missing email",
      hint: 'Send JSON body like {"email":"person@example.com"}'
    });
  }

  let member = null;
  let ghostError = null;
  let ghostHttp = null;

  try {
    const r = await ghostFindMemberByEmail(email);
    ghostHttp = r.httpStatus;
    member = r.data && r.data.members && r.data.members[0] ? r.data.members[0] : null;
  } catch (e) {
    ghostError = e.message || String(e);
  }

  const memberFound = !!member;
  const memberId = member && member.id ? String(member.id) : "";
  const tierSig = member ? buildTierSig(member) : `unknown|tiers:|labels:|subs:`;

  // ✅ THIS is what Zapier will use. It is ALWAYS <= 32 chars.
  // It changes when: memberId changes OR tiers/labels/subscriptions change.
  // That means: if someone unsubscribes and later re-subscribes, this will change -> increment starts from 1 again.
  const longSig = `mid:${memberId || "none"}|email:${email}|${tierSig}`;
  const storage_key = sha32Hex(longSig);

  // Signed token for /discord/start
  const tokenPayload = { e: email, k: storage_key, t: Date.now() };
  const token = jwt.sign(tokenPayload, SYNC_SECRET, { expiresIn: "30d" });

  const startLink = new URL(`${baseUrlFromReq(req)}/discord/start`);
  startLink.searchParams.set("token", token);

  const tierNames = normalizeArray(member && member.tiers).map(t => t && t.name).filter(Boolean);
  const labels = normalizeArray(member && member.labels).map(l => l && (l.slug || l.name)).filter(Boolean);

  return ok(res, {
    ok: true,
    email,
    member_found: memberFound,
    ghost_http: ghostHttp,
    ghost_error: ghostError,
    ghost_status: member && member.status ? member.status : "unknown",
    tier_names: tierNames,
    labels,
    tier_sig: tierSig,

    // ✅ pick THIS in Zapier Step 3
    storage_key,

    // ✅ paste THIS in Gmail body
    discord_link: startLink.toString()
  });
});

app.get("/discord/start", (req, res) => {
  const token = (req.query && req.query.token ? String(req.query.token) : "").trim();
  if (!token) return ok(res, { ok: false, error: "Missing token" });

  let payload;
  try {
    payload = jwt.verify(token, SYNC_SECRET);
  } catch (e) {
    return ok(res, { ok: false, error: "Invalid or expired token", details: e.message || String(e) });
  }

  const missing = [];
  if (!DISCORD_CLIENT_ID) missing.push("DISCORD_CLIENT_ID");
  if (!DISCORD_REDIRECT_URI) missing.push("DISCORD_REDIRECT_URI");
  if (!DISCORD_SCOPES) missing.push("DISCORD_SCOPES");

  if (missing.length) {
    return ok(res, {
      ok: false,
      error: "Discord OAuth is not configured on Render (missing env vars)",
      missing,
      hint: "Add the missing DISCORD_* env vars in Render, redeploy, then retry the email link."
    });
  }

  const auth = new URL("https://discord.com/oauth2/authorize");
  auth.searchParams.set("client_id", DISCORD_CLIENT_ID);
  auth.searchParams.set("redirect_uri", DISCORD_REDIRECT_URI);
  auth.searchParams.set("response_type", "code");
  auth.searchParams.set("scope", DISCORD_SCOPES);

  if (DISCORD_PERMISSIONS) auth.searchParams.set("permissions", String(DISCORD_PERMISSIONS));

  // Pass the signed token as state so callback can verify
  auth.searchParams.set("state", token);

  return res.redirect(auth.toString());
});

app.listen(Number(PORT), () => {
  console.log(`Hallway listening on port ${PORT}`);
});

