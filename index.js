import express from "express";
import jwt from "jsonwebtoken";

const app = express();
app.use(express.json({ limit: "1mb" }));

/**
 * ===== REQUIRED ENV VARS =====
 * SYNC_SECRET        -> shared secret between Zapier and this service
 * GHOST_ADMIN_API_URL -> e.g. https://storytellers-guild.ghost.io
 * GHOST_ADMIN_API_KEY -> Ghost Admin API key (format: "{id}:{secret}")
 *
 * Optional:
 * PORT
 */

/**
 * Accept secret from multiple places to avoid Zapier header weirdness.
 */
function requireSyncSecret(req, res, next) {
  const expected = (process.env.SYNC_SECRET || "").trim();

  const fromHeader =
    req.get("x-sync-secret") ||
    req.get("X-Sync-Secret") ||
    req.get("x-sync_secret");

  const provided =
    (fromHeader || "").trim() ||
    (req.body?.sync_secret || "").trim() ||
    (req.query?.sync_secret || "").trim();

  if (!expected) {
    return res.status(500).json({ error: "Server missing SYNC_SECRET env var" });
  }

  if (!provided || provided !== expected) {
    return res.status(401).json({
      error: "Unauthorized",
      hint: "Check SYNC_SECRET in Render + x-sync-secret header (or send sync_secret in body).",
    });
  }

  next();
}

/**
 * Ghost Admin API auth token generator.
 * Ghost Admin API key format: "{id}:{secret}"
 * We sign a JWT using the secret and include the key id in the header (kid).
 */
function makeGhostAdminToken() {
  const apiKey = process.env.GHOST_ADMIN_API_KEY;
  if (!apiKey || !apiKey.includes(":")) {
    throw new Error(
      "Missing/invalid GHOST_ADMIN_API_KEY. Expected format: {id}:{secret}"
    );
  }

  const [id, secret] = apiKey.split(":");
  const keySecret = Buffer.from(secret, "hex");

  const now = Math.floor(Date.now() / 1000);
  const token = jwt.sign(
    {
      iat: now,
      exp: now + 5 * 60, // 5 minutes
      aud: "/admin/",
    },
    keySecret,
    {
      algorithm: "HS256",
      keyid: id,
    }
  );

  return token;
}

/**
 * Fetch a member by email from Ghost Admin API.
 * Uses /ghost/api/admin/members/?filter=email:'...'
 */
async function fetchGhostMemberByEmail(email) {
  const base = (process.env.GHOST_ADMIN_API_URL || "").replace(/\/$/, "");
  if (!base) throw new Error("Missing GHOST_ADMIN_API_URL");

  const token = makeGhostAdminToken();

  // Ghost filter syntax requires single quotes.
  // Escape single quotes in email just in case.
  const safeEmail = String(email).replace(/'/g, "\\'");
  const url = `${base}/ghost/api/admin/members/?filter=email:'${encodeURIComponent(
    safeEmail
  )}'&include=tiers`;

  const resp = await fetch(url, {
    method: "GET",
    headers: {
      Authorization: `Ghost ${token}`,
      "Content-Type": "application/json",
      Accept: "application/json",
    },
  });

  const text = await resp.text();
  let data;
  try {
    data = JSON.parse(text);
  } catch {
    data = { raw: text };
  }

  if (!resp.ok) {
    return {
      ok: false,
      status: resp.status,
      error: "Ghost Admin API error",
      details: data,
    };
  }

  const member = data?.members?.[0];
  if (!member) {
    return {
      ok: false,
      status: 404,
      error: "Member not found in Ghost",
    };
  }

  // tiers may come back in different shapes depending on Ghost version.
  // We normalize to a list of tier names if possible.
  const tiersRaw =
    member.tiers ||
    member?.subscriptions?.[0]?.tier ||
    member?.subscriptions?.map((s) => s?.tier) ||
    [];

  const tierNames = Array.isArray(tiersRaw)
    ? tiersRaw.map((t) => t?.name).filter(Boolean)
    : tiersRaw?.name
    ? [tiersRaw.name]
    : [];

  return {
    ok: true,
    member: {
      id: member.id,
      uuid: member.uuid,
      email: member.email,
      name: member.name,
      status: member.status, // "free" or "paid"
      tier_names: tierNames, // could be []
    },
  };
}

/**
 * Health check
 */
app.get("/health", (req, res) => {
  res.json({ ok: true });
});

/**
 * Main Zapier endpoint:
 * POST /ghost/resolve-member
 *
 * Accepts:
 *  - body.email (recommended)
 *  - OR query.email
 *
 * Auth:
 *  - header x-sync-secret
 *  - OR body.sync_secret
 *  - OR query.sync_secret
 */
app.post("/ghost/resolve-member", requireSyncSecret, async (req, res) => {
  try {
    const email = (req.body?.email || req.query?.email || "").trim();
    if (!email) {
      return res.status(400).json({
        error: "Missing email",
        hint: "Send JSON body like { \"email\": \"person@example.com\" }",
      });
    }

    const result = await fetchGhostMemberByEmail(email);

    if (!result.ok) {
      return res.status(result.status || 500).json(result);
    }

    // This is what Zapier will use downstream
    return res.json({
      ok: true,
      email: result.member.email,
      status: result.member.status, // free/paid
      tier_names: result.member.tier_names, // array of tier names
      member_id: result.member.id,
      member_uuid: result.member.uuid,
    });
  } catch (err) {
    return res.status(500).json({
      error: "Server error",
      message: err?.message || String(err),
    });
  }
});

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`Server listening on ${port}`));
