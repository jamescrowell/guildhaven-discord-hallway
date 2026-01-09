import express from "express";
import fetch from "node-fetch";

const app = express();
app.use(express.json());

const {
  SYNC_SECRET,
  DISCORD_OAUTH_URL,          // e.g. https://guildhaven-discord-hallway.onrender.com/discord/auth
  GHOST_ADMIN_API_URL,        // e.g. https://storytellers-guild.ghost.io/ghost/api/admin
  GHOST_ADMIN_API_KEY         // Admin API key in "id:secret" format (Ghost Admin token string)
} = process.env;

function getIncomingSecret(req) {
  return req.headers["x-sync-secret"] || req.body?.sync_secret || req.query?.sync_secret;
}

function buildDiscordLink(email) {
  // Keep it simple: your OAuth flow can use the email to resolve member + roles
  const url = new URL(DISCORD_OAUTH_URL);
  url.searchParams.set("email", email);
  return url.toString();
}

function stableTierSig({ status, labels }) {
  // status: free/paid/comped/etc
  // labels: array of label slugs (or empty)
  const safeStatus = status || "unknown";
  const safeLabels = Array.isArray(labels) ? labels.slice().sort() : [];
  return `${safeStatus}|${safeLabels.join(",")}`;
}

async function findGhostMemberByEmail(email) {
  // Returns { member, error } without throwing outward
  try {
    const endpoint = `${GHOST_ADMIN_API_URL}/members/?filter=email:${encodeURIComponent(email)}`;
    const resp = await fetch(endpoint, {
      headers: {
        Authorization: `Ghost ${GHOST_ADMIN_API_KEY}`,
        "Content-Type": "application/json"
      }
    });

    const data = await resp.json().catch(() => ({}));
    const member = data?.members?.[0] || null;

    return { member, error: null };
  } catch (err) {
    return { member: null, error: err?.message || "ghost_lookup_failed" };
  }
}

// IMPORTANT: this is the route your Zap is calling
app.post("/ghost/resolve-tier", async (req, res) => {
  const incoming = getIncomingSecret(req);
  if (!incoming || incoming !== SYNC_SECRET) {
    // Return 200 so Zap step doesn’t hard-fail (you can still inspect status)
    return res.status(200).json({ ok: false, status: "unauthorized" });
  }

  const emailRaw = req.body?.email;
  const email = typeof emailRaw === "string" ? emailRaw.trim().toLowerCase() : "";

  if (!email) {
    // Again: never 4xx for Zap stability
    return res.status(200).json({ ok: false, status: "missing_email" });
  }

  const { member, error } = await findGhostMemberByEmail(email);

  const status = member?.status || "unknown";
  const labels = (member?.labels || []).map(l => l?.slug).filter(Boolean);

  const tierSig = stableTierSig({ status, labels });

  // KEY IDEA:
  // - If member exists, use member.id so a deleted/recreated account becomes a NEW key
  // - Include tierSig so upgrades/downgrades become NEW keys (so you DO send another email)
  const baseId = member?.id ? `mid:${member.id}` : `email:${email}`;
  const storage_key = `guildhaven_sync_sent:${baseId}:${tierSig}`;

  const discord_link = buildDiscordLink(email);

  return res.status(200).json({
    ok: true,
    status: member ? "member_found" : "member_not_found",
    email,
    ghost_member_id: member?.id || null,
    ghost_status: status,
    ghost_labels: labels,
    tier_sig: tierSig,
    storage_key,
    discord_link,
    ghost_lookup_error: error || null
  });
});

app.get("/health", (_req, res) => res.status(200).send("ok"));

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`Server running on ${port}`));
