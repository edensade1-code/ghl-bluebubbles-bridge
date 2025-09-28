// index.js
// All-in-one bridge for GHL ↔ BlueBubbles (iMessage), with optional OAuth & signed webhooks.

import express from "express";
import cors from "cors";
import helmet from "helmet";
import morgan from "morgan";
import axios from "axios";
import crypto from "crypto";
import bodyParser from "body-parser";
import qs from "querystring";

// ---------- Config ----------
const app = express();

// Accept JSON and form-encoded (so GHL/Zapier both work)
app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true }));
app.use(bodyParser.text({ type: ["text/*"] })); // just in case

// CORS and security headers (allow GHL iframing later)
app.use(
  helmet({
    contentSecurityPolicy: {
      useDefaults: true,
      directives: {
        "frame-ancestors": ["'self'", "*.gohighlevel.com", "*.leadconnectorhq.com"],
      },
    },
    frameguard: { action: "sameorigin" },
  })
);
app.use(
  cors({
    origin: [/\.gohighlevel\.com$/, /\.leadconnectorhq\.com$/, /localhost/, /.*/],
    credentials: true,
  })
);
app.use(morgan("tiny"));

const PORT = Number(process.env.PORT || 8080);

// BlueBubbles relay
const BB_BASE =
  process.env.BB_BASE?.trim() || "https://relay.asapcashhomebuyers.com";
const BB_GUID =
  process.env.BB_GUID?.trim() || "REPLACE_WITH_BLUEBUBBLES_SERVER_PASSWORD";

// Forward inbound iMessage events (optional)
const GHL_INBOUND_URL = process.env.GHL_INBOUND_URL?.trim() || "";

// OAuth (optional)
const CLIENT_ID = process.env.CLIENT_ID?.trim() || "";
const CLIENT_SECRET = process.env.CLIENT_SECRET?.trim() || "";
const GHL_REDIRECT_URI =
  process.env.GHL_REDIRECT_URI?.trim() ||
  "https://ieden-bluebubbles-bridge.onrender.com/oauth/callback";

// Signed marketplace webhooks (optional)
const GHL_SHARED_SECRET = process.env.GHL_SHARED_SECRET?.trim() || "";

// Logging hints
if (!BB_GUID || BB_GUID === "REPLACE_WITH_BLUEBUBBLES_SERVER_PASSWORD") {
  console.warn("[WARN] BB_GUID is not set. Set the BlueBubbles server password via env.");
}
if (!GHL_INBOUND_URL) {
  console.log("[bridge] GHL_INBOUND_URL not set. /webhook will log & 200 but not forward.");
}
if (!CLIENT_ID || !CLIENT_SECRET) {
  console.log("[bridge] OAuth not configured (CLIENT_ID/CLIENT_SECRET missing).");
}
if (!GHL_SHARED_SECRET) {
  console.log("[bridge] GHL_SHARED_SECRET not set (will not verify marketplace webhook signatures).");
}

// ---------- Helpers ----------
const newTempGuid = (prefix = "temp") =>
  `${prefix}-${crypto.randomBytes(6).toString("hex")}`;

// normalize U.S. numbers to +1XXXXXXXXXX; accept already-E.164
const toE164US = (raw) => {
  if (!raw) return null;
  const d = String(raw).replace(/\D/g, "");
  if (d.startsWith("1") && d.length === 11) return `+${d}`;
  if (d.length === 10) return `+1${d}`;
  // if already +E.164
  if (String(raw).startsWith("+")) return String(raw);
  return null;
};

const ensureE164 = (phone) => {
  const e = toE164US(phone);
  if (!e) throw new Error("Invalid 'to' phone. Provide E.164 like +13051234567");
  return e;
};

const chatGuidForPhone = (e164) => `iMessage;-;${e164}`;

const bbPost = async (path, body) => {
  const url = `${BB_BASE}${path}?guid=${encodeURIComponent(BB_GUID)}`;
  const { data } = await axios.post(url, body, {
    headers: { "Content-Type": "application/json" },
    timeout: 15000,
  });
  return data;
};

// Verify GHL marketplace webhook HMAC (if secret is set)
const verifyGhlSignature = (req) => {
  if (!GHL_SHARED_SECRET) return true; // skip if not configured
  const sig = req.header("X-GHL-Signature") || "";
  // GHL typically signs the raw body. We reconstruct raw if possible:
  let raw = "";
  try {
    // If JSON, re-stringify; if urlencoded, rebuild; if text, as-is
    if (req.is("application/json")) raw = JSON.stringify(req.body);
    else if (req.is("application/x-www-form-urlencoded")) raw = qs.stringify(req.body);
    else if (typeof req.body === "string") raw = req.body;
    else raw = JSON.stringify(req.body ?? {});
  } catch {
    raw = "";
  }
  const hmac = crypto.createHmac("sha256", GHL_SHARED_SECRET).update(raw).digest("hex");
  const match = crypto.timingSafeEqual(Buffer.from(hmac), Buffer.from(sig || "", "utf8"));
  return match;
};

// ---------- Routes ----------

// Root: basic info
app.get("/", (_req, res) => {
  res.status(200).json({
    ok: true,
    name: "ghl-bluebubbles-bridge",
    relay: BB_BASE,
    oauthConfigured: !!(CLIENT_ID && CLIENT_SECRET),
    inboundForward: !!GHL_INBOUND_URL,
  });
});

// Health: ping BlueBubbles
app.get("/health", async (_req, res) => {
  try {
    const pong = await axios.get(
      `${BB_BASE}/api/v1/ping?guid=${encodeURIComponent(BB_GUID)}`,
      { timeout: 8000 }
    );
    return res.status(200).json({ ok: true, relay: BB_BASE, ping: pong.data ?? null });
  } catch (e) {
    return res.status(503).json({
      ok: false,
      relay: BB_BASE,
      error: e?.response?.data ?? e?.message ?? "Ping failed",
    });
  }
});

// SEND: minimal, works with JSON or form-encoded
// Body: { to:"+1305...", message:"Hello" }
app.post("/send", async (req, res) => {
  try {
    const to = req.body?.to;
    const message = req.body?.message;
    const e164 = ensureE164(to);
    if (!message || !String(message).trim()) {
      return res.status(400).json({ ok: false, error: "Missing 'message'" });
    }

    const payload = {
      chatGuid: chatGuidForPhone(e164),
      tempGuid: newTempGuid("temp-bridge"),
      message: String(message),
      method: "apple-script",
    };

    const data = await bbPost("/api/v1/message/text", payload);
    return res.status(200).json({ ok: true, relay: BB_BASE, data });
  } catch (err) {
    const status = err?.response?.status ?? 500;
    return res.status(status).json({
      ok: false,
      relay: BB_BASE,
      error: err?.response?.data ?? err?.message ?? "Unknown error",
    });
  }
});

// Power-user passthrough: { path:"/api/v1/...", body:{...} }
app.post("/bb", async (req, res) => {
  try {
    const { path, body } = req.body || {};
    if (!path || typeof path !== "string" || !path.startsWith("/api/")) {
      return res.status(400).json({ ok: false, error: "Provide valid 'path' starting with /api/" });
    }
    const data = await bbPost(path, body ?? {});
    return res.status(200).json({ ok: true, relay: BB_BASE, data });
  } catch (err) {
    const status = err?.response?.status ?? 500;
    return res.status(status).json({
      ok: false,
      relay: BB_BASE,
      error: err?.response?.data ?? err?.message ?? "Unknown error",
    });
  }
});

// INBOUND from BlueBubbles → optional forward to GHL
app.post("/webhook", async (req, res) => {
  try {
    const event = req.body || {};
    const evtName =
      event?.event ||
      event?.type ||
      event?.name ||
      (event?.data?.message ? "new-message" : "webhook");

    // Normalize a few handy fields
    const normalized = {
      event: evtName,
      messageText:
        event?.data?.message?.text ??
        event?.message?.text ??
        event?.message ??
        null,
      from:
        event?.data?.message?.handle?.address ??
        event?.message?.handle?.address ??
        null,
      chatGuid:
        event?.data?.message?.chats?.[0]?.guid ??
        event?.data?.chat?.guid ??
        null,
      raw: event,
      receivedAt: new Date().toISOString(),
    };

    // Forward if configured
    if (GHL_INBOUND_URL) {
      try {
        await axios.post(GHL_INBOUND_URL, normalized, {
          headers: { "Content-Type": "application/json" },
          timeout: 10000,
        });
      } catch (e) {
        console.error("[bridge] forward to GHL failed:", e?.message);
      }
    }

    console.log("[bridge] /webhook:", evtName, normalized.messageText);
    return res.status(200).json({ ok: true });
  } catch (err) {
    console.error("[bridge] /webhook error:", err?.message);
    // ACK 200 so BB doesn't retry forever
    return res.status(200).json({ ok: true });
  }
});

// Example: signed GHL marketplace webhooks (optional)
app.post("/ghl/webhook", (req, res) => {
  try {
    if (!verifyGhlSignature(req)) {
      return res.status(401).json({ ok: false, error: "Invalid signature" });
    }
    // Handle install/uninstall/account events here:
    // const evt = req.body;
    console.log("[bridge] /ghl/webhook verified");
    return res.status(200).json({ ok: true });
  } catch (e) {
    console.error("[bridge] /ghl/webhook error:", e?.message);
    return res.status(200).json({ ok: true });
  }
});

// ---------- OAuth (optional) ----------
const OAUTH_BASE = "https://marketplace.gohighlevel.com/oauth";

app.get("/oauth/start", (req, res) => {
  if (!CLIENT_ID || !GHL_REDIRECT_URI) {
    return res.status(400).send("OAuth not configured.");
  }
  const scope = [
    "conversations.readonly",
    "conversations.write",
    "contacts.readonly",
    "locations.readonly",
  ].join(" ");
  const params = new URLSearchParams({
    client_id: CLIENT_ID,
    response_type: "code",
    redirect_uri: GHL_REDIRECT_URI,
    scope,
  });
  return res.redirect(`${OAUTH_BASE}/authorize?${params.toString()}`);
});

app.get("/oauth/callback", async (req, res) => {
  try {
    const code = req.query.code;
    if (!code) return res.status(400).send("Missing code");

    const tokenRes = await axios.post(
      `${OAUTH_BASE}/token`,
      {
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
        grant_type: "authorization_code",
        code,
        redirect_uri: GHL_REDIRECT_URI,
      },
      { headers: { "Content-Type": "application/json" }, timeout: 15000 }
    );

    const tokens = tokenRes.data;
    // TODO: Persist tokens by sub-account (locationId). For now, just log.
    console.log("[bridge] OAuth tokens:", Object.keys(tokens));

    return res
      .status(200)
      .send("Connected to HighLevel. You can close this window.");
  } catch (e) {
    console.error("[bridge] OAuth callback error:", e?.response?.data || e.message);
    return res.status(500).send("OAuth error");
  }
});

// ---------- Start ----------
app.listen(PORT, () => {
  console.log(`[bridge] listening on :${PORT}`);
  console.log(`[bridge] BB_BASE = ${BB_BASE}`);
  if (GHL_INBOUND_URL) console.log(`[bridge] Forwarding inbound to ${GHL_INBOUND_URL}`);
  if (CLIENT_ID && CLIENT_SECRET) console.log("[bridge] OAuth is configured.");
  if (GHL_SHARED_SECRET) console.log("[bridge] GHL webhook signature verification enabled.");
});
