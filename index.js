import express from "express";
import crypto from "crypto";

const app = express();
const PORT = process.env.PORT || 3000;

const {
  DISCORD_CLIENT_ID,
  DISCORD_CLIENT_SECRET,
  DISCORD_REDIRECT_URI,
  STATE_SECRET,
  ZAPIER_WEBHOOK_URL,
  INVITE_FREE,
  INVITE_APPRENTICE,
  INVITE_JOURNEYMAN,
  INVITE_MASTER,
  INVITE_GRANDMASTER
} = process.env;

function must(v, name) {
  if (!v) throw new Error(`Missing env var: ${name}`);
  return v;
}

function signState(obj) {
  const payload = Buffer.from(JSON.stringify(obj)).toString("base64url");
  const sig = crypto
    .createHmac("sha256", must(STATE_SECRET, "STATE_SECRET"))
    .update(payload)
    .digest("base64url");
  return `${payload}.${sig}`;
}

function verifyState(state) {
  const [payload, sig] = (state || "").split(".");
  if (!payload || !sig) return null;

  const expected = crypto
    .createHmac("sha256", must(STATE_SECRET, "STATE_SECRET"))
    .update(payload)
    .digest("base64url");

  if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) return null;

  try {
    return JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
  } catch {
    return null;
  }
}

function inviteForTier(tier) {
  const t = (tier || "").toLowerCase();
  if (t === "apprentice") return must(INVITE_APPRENTICE, "INVITE_APPRENTICE");
  if (t === "journeyman") return must(INVITE_JOURNEYMAN, "INVITE_JOURNEYMAN");
  if (t === "master") return must(INVITE_MASTER, "INVITE_MASTER");
  if (t === "grandmaster") return must(INVITE_GRANDMASTER, "INVITE_GRANDMASTER");
  return must(INVITE_FREE, "INVITE_FREE");
}

async function exchangeCodeForToken(code) {
  const body = new URLSearchParams({
    client_id: must(DISCORD_CLIENT_ID, "DISCORD_CLIENT_ID"),
    client_secret: must(DISCORD_CLIENT_SECRET, "DISCORD_CLIENT_SECRET"),
    grant_type: "authorization_code",
    code,
    redirect_uri: must(DISCORD_REDIRECT_URI, "DISCORD_REDIRECT_URI")
  });

  const resp = await fetch("https://discord.com/api/oauth2/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body
  });

  if (!resp.ok) throw new Error(`Token exchange failed`);
  return resp.json();
}

async function fetchDiscordUser(accessToken) {
  const resp = await fetch("https://discord.com/api/users/@me", {
    headers: { Authorization: `Bearer ${accessToken}` }
  });
  if (!resp.ok) throw new Error(`Fetch user failed`);
  return resp.json();
}

async function postToZapier(payload) {
  await fetch(ZAPIER_WEBHOOK_URL, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload)
  });
}

app.get("/discord/start", (req, res) => {
  const email = (req.query.email || "").toLowerCase();
  const tier = (req.query.tier || "free").toLowerCase();
  if (!email.includes("@")) return res.status(400).send("Missing email");

  const state = signState({ email, tier });
  const url = new URL("https://discord.com/oauth2/authorize");
  url.searchParams.set("client_id", DISCORD_CLIENT_ID);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("redirect_uri", DISCORD_REDIRECT_URI);
  url.searchParams.set("scope", "identify");
  url.searchParams.set("state", state);

  res.redirect(url.toString());
});

app.get("/discord/callback", async (req, res) => {
  try {
    const decoded = verifyState(req.query.state);
    if (!decoded) return res.status(400).send("Invalid state");

    const token = await exchangeCodeForToken(req.query.code);
    const user = await fetchDiscordUser(token.access_token);

    await postToZapier({
      email: decoded.email,
      tier: decoded.tier,
      discord_user_id: user.id,
      discord_username: user.username
    });

    res.redirect(inviteForTier(decoded.tier));
  } catch {
    res.status(500).send("Discord connect failed");
  }
});

app.get("/", (_, res) => res.send("Hallway running"));

app.listen(PORT);
