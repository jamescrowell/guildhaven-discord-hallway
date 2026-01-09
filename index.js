/**
 * server.js — GuildHaven Discord Hallway (Render)
 *
 * Adds:
 *   POST /ghost/resolve-tier  -> returns tier_slug based on Ghost Admin API lookup by email
 *
 * Requires env vars:
 *   PORT
 *   SYNC_SECRET
 *
 *   DISCORD_CLIENT_ID
 *   DISCORD_CLIENT_SECRET
 *   DISCORD_REDIRECT_URI
 *   DISCORD_BOT_TOKEN
 *   DISCORD_GUILD_ID
 *   ROLE_ID_MEMBER (optional)
 *   ROLE_ID_APPRENTICE
 *   ROLE_ID_JOURNEYMAN
 *   ROLE_ID_MASTER
 *   ROLE_ID_GRANDMASTER
 *
 *   GHOST_ADMIN_API_URL          e.g. https://guildhaven.com
 *   GHOST_ADMIN_API_KEY          e.g. {id}:{secret}
 *
 *   GHOST_TIER_NAME_APPRENTICE   e.g. Apprentice
 *   GHOST_TIER_NAME_JOURNEYMAN   e.g. Journeyman
 *   GHOST_TIER_NAME_MASTER       e.g. Master
 *   GHOST_TIER_NAME_GRANDMASTER  e.g. Grandmaster
 */

import express from "express";
import crypto from "crypto";
import jwt from "jsonwebtoken";

const app = express();
app.use(express.json());

// -----------------------------
// Helpers
// -----------------------------
function requireSecret(req, res) {
  const provided =
    req.get("x-sync-secret") ||
    req.query.sync_secret ||
    req.body?.sync_secret;

  if (!process.env.SYNC_SECRET) {
    res.status(500).json({ error: "SYNC_SECRET not set on server" });
    return false;
  }
  if (!provided || provided !== process.env.SYNC_SECRET) {
    res.status(401).json({ error: "Unauthorized" });
    return false;
  }
  return true;
}

function normalizeTierSlug(raw) {
  const v = String(raw || "").toLowerCase().trim();
  const allowed = new Set(["free", "apprentice", "journeyman", "master", "grandmaster"]);
  return allowed.has(v) ? v : null;
}

function buildGhostAdminJwt() {
  const key = process.env.GHOST_ADMIN_API_KEY;
  if (!key || !key.includes(":")) {
    throw new Error("GHOST_ADMIN_API_KEY must be in the form {id}:{secret}");
  }
  const [id, secret] = key.split(":");
  const signingKey = Buffer.from(secret, "hex");

  // Ghost Admin API JWT requirements:
  // - HS256
  // - kid header = id
  // - aud = /admin/
  // - short expiry
  const token = jwt.sign(
    {},
    signingKey,
    {
      keyid: id,
      algorithm: "HS256",
      expiresIn: "5m",
      audience: "/admin/"
    }
  );
  return token;
}

async function ghostAdminFetch(path) {
  const base = process.env.GHOST_ADMIN_API_URL;
  if (!base) throw new Error("GHOST_ADMIN_API_URL not set");

  const url = new URL(path, base.endsWith("/") ? base : base + "/");
  const token = buildGhostAdminJwt();

  const resp = await fetch(url.toString(), {
    method: "GET",
    headers: {
      Authorization: `Ghost ${token}`,
      "Accept-Version": "v5.0",
      "Content-Type": "application/json"
    }
  });

  if (!resp.ok) {
    const txt = await resp.text().catch(() => "");
    throw new Error(`Ghost Admin API error ${resp.status}: ${txt}`);
  }
  return resp.json();
}

function mapGhostTierNameToSlug(tierName) {
  const name = String(tierName || "").trim();

  const A = process.env.GHOST_TIER_NAME_APPRENTICE || "Apprentice";
  const J = process.env.GHOST_TIER_NAME_JOURNEYMAN || "Journeyman";
  const M = process.env.GHOST_TIER_NAME_MASTER || "Master";
  const G = process.env.GHOST_TIER_NAME_GRANDMASTER || "Grandmaster";

  if (name === A) return "apprentice";
  if (name === J) return "journeyman";
  if (name === M) return "master";
  if (name === G) return "grandmaster";

  return null;
}

function pickBestTierFromMember(member) {
  // Ghost member payloads can vary by version and fields returned.
  // Common places:
  // - member.tiers (array of tier objects)
  // - member.subscriptions (array) each with tier / plan references
  //
  // We want the *currently active paid tier*. If multiple, pick first match.
  const tiers = Array.isArray(member?.tiers) ? member.tiers : [];
  for (const t of tiers) {
    const slug = mapGhostTierNameToSlug(t?.name);
    if (slug) return { slug, source: "member.tiers", tierName: t?.name || "" };
  }

  const subs = Array.isArray(member?.subscriptions) ? member.subscriptions : [];
  // Look for an active subscription first
  const activeSubs = subs.filter(s => String(s?.status || "").toLowerCase() === "active");
  for (const s of activeSubs) {
    const tn = s?.tier?.name || s?.plan?.nickname || s?.plan?.name || "";
    const slug = mapGhostTierNameToSlug(tn);
    if (slug) return { slug, source: "member.subscriptions(active)", tierName: tn };
  }

  // Fallback: any subscription tier-ish name
  for (const s of subs) {
    const tn = s?.tier?.name || s?.plan?.nickname || s?.plan?.name || "";
    const slug = mapGhostTierNameToSlug(tn);
    if (slug) return { slug, source: "member.subscriptions(any)", tierName: tn };
  }

  return null;
}

// -----------------------------
// NEW endpoint: Resolve tier from Ghost by email
// -----------------------------
app.post("/ghost/resolve-tier", async (req, res) => {
  try {
    if (!requireSecret(req, res)) return;

    const email = String(req.body?.email || "").trim();
    if (!email) return res.status(400).json({ error: "Missing email" });

    // Filter by email in Ghost Admin API
    // NOTE: filter syntax is sensitive; this is the standard approach.
    const filter = `email:'${email.replace(/'/g, "\\'")}'`;
    const encodedFilter = encodeURIComponent(filter);

    const data = await ghostAdminFetch(
      `/ghost/api/admin/members/?limit=1&filter=${encodedFilter}&include=tiers,subscriptions`
    );

    const member = data?.members?.[0];
    if (!member) {
      return res.status(404).json({ error: "Member not found in Ghost", email });
    }

    const pick = pickBestTierFromMember(member);
    const tier_slug = pick?.slug || "free";

    return res.json({
      email,
      tier_slug,
      debug: {
        found: true,
        mapped_from: pick?.source || null,
        ghost_tier_name: pick?.tierName || null
      }
    });
  } catch (err) {
    return res.status(500).json({ error: String(err?.message || err) });
  }
});

// -----------------------------
// Existing Hallway behavior (minimal stubs / placeholders)
// NOTE: If you already have these routes, merge them—do not duplicate.
// -----------------------------

app.get("/health", (_req, res) => res.json({ ok: true }));

// If your hallway already has /discord/start, keep yours.
// This is a simple validation example.
app.get("/discord/start", (req, res) => {
  const tier = normalizeTierSlug(req.query?.tier);
  const email = String(req.query?.email || "").trim();

  if (!tier || !email) {
    return res.status(400).send(
      `Missing or invalid tier. Must be one of: free, apprentice, journeyman, master, grandmaster`
    );
  }

  // Your existing OAuth redirect logic likely lives here.
  // For now, just show confirmation so you can verify query params.
  res.status(200).send(`OK. Starting OAuth for ${email} with tier=${tier}`);
});

// If you already have /discord/sync, keep yours.
// Protected sync example:
app.post("/discord/sync", (req, res) => {
  if (!requireSecret(req, res)) return;
  res.json({ ok: true });
});

const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`Hallway server running on port ${port}`);
});
