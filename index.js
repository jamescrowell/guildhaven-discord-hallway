import fetch from "node-fetch";
import express from "express";
import jwt from "jsonwebtoken";

const app = express();
app.use(express.json());

// -----------------------------
// Auth helper (SYNC_SECRET)
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

// -----------------------------
// Ghost Admin API helpers
// -----------------------------
function buildGhostAdminJwt() {
  const key = process.env.GHOST_ADMIN_API_KEY;
  if (!key || !key.includes(":")) {
    throw new Error("GHOST_ADMIN_API_KEY must be in the form {id}:{secret}");
  }
  const [id, secret] = key.split(":");
  const signingKey = Buffer.from(secret, "hex");

  return jwt.sign(
    {},
    signingKey,
    {
      keyid: id,
      algorithm: "HS256",
      expiresIn: "5m",
      audience: "/admin/"
    }
  );
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
  // Prefer member.tiers if present
  const tiers = Array.isArray(member?.tiers) ? member.tiers : [];
  for (const t of tiers) {
    const slug = mapGhostTierNameToSlug(t?.name);
    if (slug) return { slug, source: "member.tiers", tierName: t?.name || "" };
  }

  // Otherwise look at active subscriptions
  const subs = Array.isArray(member?.subscriptions) ? member.subscriptions : [];
  const activeSubs = subs.filter(s => String(s?.status || "").toLowerCase() === "active");

  for (const s of activeSubs) {
    const tn = s?.tier?.name || s?.plan?.nickname || s?.plan?.name || "";
    const slug = mapGhostTierNameToSlug(tn);
    if (slug) return { slug, source: "member.subscriptions(active)", tierName: tn };
  }

  // Last resort: any subscription
  for (const s of subs) {
    const tn = s?.tier?.name || s?.plan?.nickname || s?.plan?.name || "";
    const slug = mapGhostTierNameToSlug(tn);
    if (slug) return { slug, source: "member.subscriptions(any)", tierName: tn };
  }

  return null;
}

// -----------------------------
// Health check
// -----------------------------
app.get("/health", (_req, res) => res.json({ ok: true }));

// -----------------------------
// NEW: Resolve tier from Ghost by email (key fix)
// -----------------------------
app.post("/ghost/resolve-tier", async (req, res) => {
  try {
    if (!requireSecret(req, res)) return;

    const email = String(req.body?.email || "").trim();
    if (!email) return res.status(400).json({ error: "Missing email" });

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

    // FREE is fully supported as fallback
    const tier_slug = pick?.slug || "free";

    return res.json({
      email,
      tier_slug,
      debug: {
        mapped_from: pick?.source || null,
        ghost_tier_name: pick?.tierName || null
      }
    });
  } catch (err) {
    return res.status(500).json({ error: String(err?.message || err) });
  }
});

// -----------------------------
// /discord/start stub (keep or replace with your real OAuth start route)
// -----------------------------
app.get("/discord/start", (req, res) => {
  const tier = normalizeTierSlug(req.query?.tier);
  const email = String(req.query?.email || "").trim();

  if (!tier || !email) {
    return res
      .status(400)
      .send("Missing or invalid tier. Use: free, apprentice, journeyman, master, grandmaster");
  }

  // If you already have Discord OAuth logic, put it here.
  return res.status(200).send(`OK. Starting OAuth for ${email} with tier=${tier}`);
});

// -----------------------------
// /discord/sync stub (keep or replace with your real sync route)
// -----------------------------
app.post("/discord/sync", (req, res) => {
  if (!requireSecret(req, res)) return;
  return res.json({ ok: true });
});

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`Hallway running on port ${port}`));
