/**
 * GuildHaven Discord Hallway
 * - Receives Zapier webhook with { email }
 * - Validates sync secret (header OR body)
 * - Looks up member in Ghost Admin API by email
 * - Returns JSON ALWAYS (200), even on errors, so Zapier doesn’t mask details
 */

import express from "express";
import morgan from "morgan";
import jwt from "jsonwebtoken";
import fetch from "node-fetch";

const app = express();

// ---- Middleware
app.use(express.json({ limit: "1mb" }));
app.use(morgan("combined"));

// ---- ENV (expected)
const {
  PORT = "10000",
  GHOST_URL,                 // e.g. https://storytellers-guild.ghost.io
  GHOST_ADMIN_API_KEY,       // Admin API key (not Content key)
  GH_SYNC_SECRET,            // your shared secret
} = process.env;

function ok(res, payload) {
  return res.status(200).json(payload);
}

function getProvidedSecret(req) {
  // Accept secret from either header or body (Zapier sometimes sends one or the other)
  return (
    req.header("x-sync-secret") ||
    req.header("X-Sync-Secret") ||
    req.body?.sync_secret ||
    req.body?.x_sync_secret ||
    req.body?.xSyncSecret ||
    null
  );
}

function safeEnvCheck() {
  const missing = [];
  if (!GHOST_URL) missing.push("GHOST_URL");
  if (!GHOST_ADMIN_API_KEY) missing.push("GHOST_ADMIN_API_KEY");
  if (!GH_SYNC_SECRET) missing.push("GH_SYNC_SECRET");
  return missing;
}

function makeGhostAdminToken(adminApiKey) {
  // Ghost Admin API key format: "<id>:<secret>"
  const [id, secret] = adminApiKey.split(":");
  if (!id || !secret) {
    throw new Error("GHOST_ADMIN_API_KEY must look like '<id>:<secret>'");
  }

  const now = Math.floor(Date.now() / 1000);
  const token = jwt.sign(
    {
      iat: now,
      exp: now + 5 * 60,
      aud: "/admin/",
    },
    Buffer.from(secret, "hex"),
    {
      keyid: id,
      algorithm: "HS256",
      header: { typ: "JWT" },
    }
  );

  return token;
}

async function ghostGetMemberByEmail(email) {
  const token = makeGhostAdminToken(GHOST_ADMIN_API_KEY);

  // Ghost Admin API: GET /ghost/api/admin/members/?filter=email:'...'
  // We URL encode carefully and request related fields we may need
  const filter = `email:'${email.replace(/'/g, "\\'")}'`;
  const url =
    `${GHOST_URL.replace(/\/$/, "")}` +
    `/ghost/api/admin/members/?filter=${encodeURIComponent(filter)}&include=labels,subscriptions`;

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

  return { status: resp.status, data };
}

// ---- Routes
app.get("/health", (req, res) => {
  const missing = safeEnvCheck();
  if (missing.length) {
    return ok(res, { ok: false, error: "Missing env vars", missing });
  }
  return ok(res, { ok: true });
});

// Use ONE endpoint name in Zapier. (Pick one and stick to it.)
app.post("/ghost/resolve-tier", async (req, res) => {
  const missing = safeEnvCheck();
  if (missing.length) return ok(res, { ok: false, error: "Missing env vars", missing });

  const providedSecret = getProvidedSecret(req);
  if (!providedSecret) {
    return ok(res, {
      ok: false,
      error: "Missing sync secret",
      hint: "Send header 'x-sync-secret' OR body field 'sync_secret'",
    });
  }
  if (providedSecret !== GH_SYNC_SECRET) {
    return ok(res, { ok: false, error: "Unauthorized (bad sync secret)" });
  }

  const email = req.body?.email;
  if (!email || typeof email !== "string") {
    return ok(res, {
      ok: false,
      error: "Missing email",
      receivedBodyKeys: Object.keys(req.body || {}),
      hint: "Send JSON body: { \"email\": \"person@example.com\" }",
    });
  }

  try {
    const { status, data } = await ghostGetMemberByEmail(email);

    // Ghost returns members: [...]
    const member = data?.members?.[0];

    if (!member) {
      return ok(res, {
        ok: false,
        error: "Member not found in Ghost",
        ghostStatus: status,
        ghostResponse: data,
      });
    }

    // Determine a simple tier signal
    const currentStatus = member.status || "unknown"; // often: "free" or "paid"
    const labels = (member.labels || []).map(l => ({
      id: l.id,
      name: l.name,
      slug: l.slug,
    }));

    // You can extend this mapping later (e.g. map label slug -> discord role)
    return ok(res, {
      ok: true,
      email,
      member: {
        id: member.id,
        status: currentStatus,
        name: member.name,
        labels,
      },
    });
  } catch (err) {
    return ok(res, {
      ok: false,
      error: "Server exception",
      message: err?.message || String(err),
    });
  }
});

// ---- Start
app.listen(Number(PORT), () => {
  console.log(`GuildHaven hallway listening on port ${PORT}`);
});
