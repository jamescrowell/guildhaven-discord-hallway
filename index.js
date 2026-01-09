// index.js
import express from "express";
import fetch from "node-fetch";
import jwt from "jsonwebtoken";

const app = express();
app.use(express.json());

// ---------- ENV VARS YOU MUST SET IN RENDER ----------
// GHOST_ADMIN_API_URL = https://YOUR-SITE.ghost.io
// GHOST_ADMIN_API_KEY = {admin_key_id}:{admin_key_secret}
// SYNC_SECRET = any-long-random-string
// -----------------------------------------------------

function requireSyncSecret(req, res) {
  const headerSecret = req.header("x-sync-secret") || req.header("sync_secret");
  const expected = process.env.SYNC_SECRET;

  if (!expected) {
    return res.status(500).json({ error: "Server missing SYNC_SECRET env var" });
  }
  if (!headerSecret || headerSecret !== expected) {
    return res.status(401).json({ error: "Unauthorized" });
  }
  return null;
}

function buildGhostAdminJwt() {
  const key = process.env.GHOST_ADMIN_API_KEY;
  if (!key || !key.includes(":")) throw new Error("Missing/invalid GHOST_ADMIN_API_KEY");

  const [id, secret] = key.split(":");
  const now = Math.floor(Date.now() / 1000);

  return jwt.sign(
    {
      iat: now,
      exp: now + 5 * 60,
      aud: "/admin/"
    },
    Buffer.from(secret, "hex"),
    {
      keyid: id,
      algorithm: "HS256"
    }
  );
}

// Helper: safely pick a tier slug/name from Ghost member object
function pickTier(member) {
  // Ghost sometimes returns `tiers` on member, sometimes via subscriptions -> tier
  const tiers = Array.isArray(member.tiers) ? member.tiers : [];
  if (tiers.length > 0) {
    return {
      tier_id: tiers[0].id || null,
      tier_slug: tiers[0].slug || null,
      tier_name: tiers[0].name || null
    };
  }

  const subs = Array.isArray(member.subscriptions) ? member.subscriptions : [];
  // Find an active subscription if present
  const activeSub =
    subs.find(s => s.status === "active") ||
    subs.find(s => s.status === "trialing") ||
    subs[0];

  if (activeSub && activeSub.tier) {
    return {
      tier_id: activeSub.tier_toggle_id || activeSub.tier.id || null,
      tier_slug: activeSub.tier.slug || null,
      tier_name: activeSub.tier.name || null
    };
  }

  return { tier_id: null, tier_slug: "free", tier_name: "Free" };
}

function pickSubscriptionId(member) {
  const subs = Array.isArray(member.subscriptions) ? member.subscriptions : [];
  const active =
    subs.find(s => s.status === "active") ||
    subs.find(s => s.status === "trialing") ||
    null;
  return active ? (active.id || null) : null;
}

app.post("/ghost/resolve-member", async (req, res) => {
  const authErr = requireSyncSecret(req, res);
  if (authErr) return;

  const email = (req.body?.email || "").trim().toLowerCase();
  if (!email) return res.status(400).json({ error: "Missing email" });

  const baseUrl = process.env.GHOST_ADMIN_API_URL;
  if (!baseUrl) return res.status(500).json({ error: "Missing GHOST_ADMIN_API_URL env var" });

  try {
    const token = buildGhostAdminJwt();

    // Ghost Admin API: find member by email
    // NOTE: This endpoint supports filter. We request related data if available.
    const url =
      `${baseUrl.replace(/\/$/, "")}/ghost/api/admin/members/?filter=` +
      encodeURIComponent(`email:'${email}'`) +
      `&include=tiers,subscriptions`;

    const resp = await fetch(url, {
      method: "GET",
      headers: {
        Authorization: `Ghost ${token}`,
        "Content-Type": "application/json"
      }
    });

    if (!resp.ok) {
      const text = await resp.text();
      return res.status(502).json({ error: "Ghost API error", status: resp.status, detail: text });
    }

    const data = await resp.json();
    const member = data?.members?.[0];
    if (!member) return res.status(404).json({ error: "Member not found in Ghost for email", email });

    const member_id = member.id;
    const status = member.status || "free";

    const { tier_id, tier_slug, tier_name } = pickTier(member);
    const subscription_id = pickSubscriptionId(member);

    // ✅ The dedupe key that fixes duplicates AND allows delete/rejoin to re-email:
    // - Paid: subscription_id + tier_slug (or tier_id) (stable per subscription/tier)
    // - Free: member_id (new if deleted & re-joined)
    const event_key =
      subscription_id
        ? `sub:${subscription_id}:tier:${tier_slug || tier_id || "unknown"}`
        : `free:${member_id}`;

    return res.json({
      email,
      member_id,
      status,
      tier_id,
      tier_slug: tier_slug || "free",
      tier_name: tier_name || "Free",
      subscription_id,
      event_key
    });
  } catch (e) {
    return res.status(500).json({ error: "Server error", detail: String(e?.message || e) });
  }
});

app.get("/health", (req, res) => res.json({ ok: true }));

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`Server listening on ${port}`));
