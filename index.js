const express = require("express");
const morgan = require("morgan");
const jwt = require("jsonwebtoken");
const fetch = require("node-fetch");

const app = express();
app.use(express.json({ limit: "1mb" }));
app.use(morgan("combined"));

const {
  PORT = "10000",
  GHOST_ADMIN_API_URL,     // e.g. https://YOUR-SITE.ghost.io
  GHOST_ADMIN_API_KEY,     // Ghost Admin API key: id:secret
  SYNC_SECRET,
  DISCORD_OAUTH_URL        // e.g. https://guildhaven-discord-hallway.onrender.com/discord/start
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

  const safeEmail = String(email).replace(/'/g, "\\'");
  const filter = `email:'${safeEmail}'`;

  const url =
    `${base}/ghost/api/admin/members/?filter=${encodeURIComponent(filter)}` +
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

app.get("/health", (req, res) => {
  const missing = envCheck();
  if (missing.length) return ok(res, { ok: false, error: "Missing env vars", missing });
  return ok(res, { ok: true });
});

app.post("/ghost/resolve-tier", async (req, res) => {
  const missing = envCheck();
  if (missing.length) return ok(res, { ok: false, error: "Missing env vars", missing });

  const provided = getProvidedSecret(req);
  if (!provided) return ok(res, { ok: false, error: "Missing sync secret" });
  if (provided !== SYNC_SECRET) return ok(res, { ok: false, error: "Unauthorized (bad sync secret)" });

  const email = (req.body && req.body.email ? String(req.body.email) : "").trim().toLowerCase();
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
    member = r.data && r.data.members && r.data.members[0] ? r.data.members[0] : null;
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

  // ----- NEW: subscription signature for "same tier months later" -----
  const subs = Array.isArray(member?.subscriptions) ? member.subscriptions : [];

  const latestSub = subs
    .slice()
    .sort((a, b) =>
      String(b?.created_at || b?.start_date || "").localeCompare(
        String(a?.created_at || a?.start_date || "")
      )
    )[0] || null;

  const subId = latestSub?.id || "";
  const subCreated = latestSub?.created_at || latestSub?.start_date || "";
  const subStatus = latestSub?.status || "";

  const subSig = `sub:${subId || "none"}|sub_status:${subStatus || "none"}|sub_created:${subCreated || "none"}`;

  const tierSig =
    `${status}|tiers:${tierNames.slice().sort().join(",")}` +
    `|labels:${labels.slice().sort().join(",")}` +
    `|${subSig}`;

  const baseId = memberId ? `mid:${memberId}` : `email:${email}`;
  const storage_key = `guildhaven_email_sent:${baseId}:${tierSig}`;

  const link = new URL(DISCORD_OAUTH_URL);
  link.searchParams.set("email", email);

  return ok(res, {
    ok: true,
    email,
    member_found: !!member,
    ghost_http: ghostHttp,
    ghost_error: ghostError,
    ghost_status: status,
    tier_names: tierNames,
    labels,
    latest_subscription: latestSub ? {
      id: subId || null,
      status: subStatus || null,
      created_at: subCreated || null
    } : null,
    tier_sig: tierSig,
    storage_key,
    discord_link: link.toString()
  });
});

app.listen(Number(PORT), () => {
  console.log(`Hallway listening on port ${PORT}`);
});

