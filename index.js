// index.js
// All-in-one bridge for GHL ↔ BlueBubbles (iMessage), with OAuth, actions/triggers, and a minimal inbox UI.

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

// CORS and security headers (allow GHL/LeadConnector iframing)
app.use(
  helmet({
    contentSecurityPolicy: {
      useDefaults: true,
      directives: {
        "frame-ancestors": [
          "'self'",
          "*.gohighlevel.com",
          "*.leadconnectorhq.com",
          "*.msgsndr.com"
        ],
      },
    },
    frameguard: { action: "sameorigin" },
  })
);
app.use(
  cors({
    origin: [/\.gohighlevel\.com$/, /\.leadconnectorhq\.com$/, /\.msgsndr\.com$/, /localhost/],
    credentials: true,
  })
);
app.use(morgan("tiny"));

const PORT = Number(process.env.PORT || 8080);

// BlueBubbles relay
const BB_BASE = (process.env.BB_BASE || "https://relay.asapcashhomebuyers.com").trim();
const BB_GUID = (process.env.BB_GUID || "REPLACE_WITH_BLUEBUBBLES_SERVER_PASSWORD").trim();

// Optional forward of normalized inbound to your own GHL workflow webhook
const GHL_INBOUND_URL = (process.env.GHL_INBOUND_URL || "").trim();

// OAuth (HighLevel / LeadConnector)
const CLIENT_ID = (process.env.CLIENT_ID || "").trim();
const CLIENT_SECRET = (process.env.CLIENT_SECRET || "").trim();
const GHL_REDIRECT_URI = (process.env.GHL_REDIRECT_URI || "https://ieden-bluebubbles-bridge-1.onrender.com/oauth/callback").trim();

// Use LeadConnector services host for OAuth (token + authorize)
// Use two hosts: marketplace for authorize, services for token
const OAUTH_AUTHORIZE_BASE = "https://marketplace.gohighlevel.com/oauth";
const OAUTH_TOKEN_BASE     = "https://services.leadconnectorhq.com/oauth";

// Shared secret for verifying your own inbound subscription calls (and/or marketplace webhook)
const GHL_SHARED_SECRET = (process.env.GHL_SHARED_SECRET || "").trim();

// Simple in-memory token store (swap for DB later)
const tokenStore = new Map();
// tokenStore.set(<locationId>, { access_token, refresh_token, expires_in, ... })

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
  console.log("[bridge] GHL_SHARED_SECRET not set (Bearer header/HMAC checks will be skipped).");
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
  if (String(raw).startsWith("+")) return String(raw);
  return null;
};

const ensureE164 = (phone) => {
  const e = toE164US(phone);
  if (!e) throw new Error("Invalid 'to' phone. Provide E.164 like +13051234567");
  return e;
};

const chatGuidForPhone = (e164) => `iMessage;-;${e164}`;

// Low-level BlueBubbles calls
const bbPost = async (path, body) => {
  const url = `${BB_BASE}${path}?guid=${encodeURIComponent(BB_GUID)}`;
  const { data } = await axios.post(url, body, {
    headers: { "Content-Type": "application/json" },
    timeout: 15000,
  });
  return data;
};
const bbGet = async (path) => {
  const url = `${BB_BASE}${path}${path.includes("?") ? "&" : "?"}guid=${encodeURIComponent(BB_GUID)}`;
  const { data } = await axios.get(url, { timeout: 15000 });
  return data;
};

// Verify HMAC signature from GHL (if you use X-GHL-Signature hex)
const verifyGhlSignature = (req) => {
  if (!GHL_SHARED_SECRET) return true; // skip if not configured
  const sigHex = req.header("X-GHL-Signature") || "";
  // Reconstruct raw body best-effort
  let raw = "";
  try {
    if (req.is("application/json")) raw = JSON.stringify(req.body);
    else if (req.is("application/x-www-form-urlencoded")) raw = qs.stringify(req.body);
    else if (typeof req.body === "string") raw = req.body;
    else raw = JSON.stringify(req.body ?? {});
  } catch {
    raw = "";
  }
  const expectedHex = crypto.createHmac("sha256", GHL_SHARED_SECRET).update(raw).digest("hex");
  if (expectedHex.length !== sigHex.length) return false;
  return crypto.timingSafeEqual(Buffer.from(expectedHex, "hex"), Buffer.from(sigHex, "hex"));
};

// Optional Bearer check (for Subscription URL you configured)
const verifyBearer = (req) => {
  if (!GHL_SHARED_SECRET) return true;
  const auth = req.header("Authorization") || "";
  const m = auth.match(/^Bearer\s+(.+)$/i);
  if (!m) return false;
  return m[1].trim() === GHL_SHARED_SECRET;
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
    routes: [
      "/health",
      "/send",
      "/bb",
      "/webhook",
      "/api/chats",
      "/api/messages",
      "/app",
      "/oauth/start",
      "/oauth/callback",
      "/oauth/debug"
    ],
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

    return res.status(200).json({
      ok: true,
      provider: "eden-imessage",
      relay: BB_BASE,
      data: {
        guid: data?.guid || data?.data?.guid || payload.tempGuid,
        text: data?.text || message,
        isDelivered: !!(data?.isDelivered ?? true),
      },
    });
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

// INBOUND handler (dual-mode):
// - If called by BlueBubbles relay → normalize and (optionally) forward to your GHL webhook
// - If called by GHL Trigger Subscription URL (with Bearer) → just 200 OK
app.post("/webhook", async (req, res) => {
  try {
    // Allow GHL subscription pings through with Bearer
    if (verifyBearer(req)) {
      console.log("[bridge] /webhook: GHL subscription event");
      return res.status(200).json({ ok: true });
    }

    const event = req.body || {};
    const evtName =
      event?.event ||
      event?.type ||
      event?.name ||
      (event?.data?.message ? "new-message" : "webhook");

    // Normalize some handy fields (BlueBubbles inbound)
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
      to:
        event?.data?.message?.chats?.[0]?.lastAddressedHandle ??
        null,
      chatGuid:
        event?.data?.message?.chats?.[0]?.guid ??
        event?.data?.chat?.guid ??
        null,
      raw: event,
      receivedAt: new Date().toISOString(),
    };

    // Forward if configured (your internal GHL inbound webhook)
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
    // Always 200 so BlueBubbles doesn't retry
    return res.status(200).json({ ok: true });
  } catch (err) {
    console.error("[bridge] /webhook error:", err?.message);
    return res.status(200).json({ ok: true });
  }
});

// Example: signed marketplace webhooks (install/uninstall). Optional.
app.post("/ghl/webhook", (req, res) => {
  try {
    if (!verifyGhlSignature(req)) {
      return res.status(401).json({ ok: false, error: "Invalid signature" });
    }
    console.log("[bridge] /ghl/webhook verified");
    return res.status(200).json({ ok: true });
  } catch (e) {
    console.error("[ghl/webhook] error:", e?.message);
    return res.status(200).json({ ok: true });
  }
});

// ---------- OAuth (HighLevel / LeadConnector) ----------

// Start OAuth flow manually if needed
app.get("/oauth/start", (req, res) => {
  if (!CLIENT_ID || !GHL_REDIRECT_URI) {
    return res.status(400).send("OAuth not configured (missing CLIENT_ID or GHL_REDIRECT_URI).");
  }
  const scope = [
    "conversations.read",
    "conversations.write",
    "contacts.read",
    "locations.read",
  ].join(" ");
  const params = new URLSearchParams({
    client_id: CLIENT_ID,
    response_type: "code",
    redirect_uri: GHL_REDIRECT_URI,
    scope,
  });
  return res.redirect(`${OAUTH_AUTHORIZE_BASE}/authorize?${params.toString()}`);
});

// Handle OAuth callback and store tokens (in-memory for now)
app.get("/oauth/callback", async (req, res) => {
  try {
    const { code, error, error_description } = req.query;
    if (error) {
      console.error("[oauth] authorize error:", error, error_description || "");
      return res.status(400).send("OAuth denied. Please try again.");
    }
    if (!code) return res.status(400).send("Missing authorization code.");

    const body = qs.stringify({
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
      grant_type: "authorization_code",
      code,
      redirect_uri: GHL_REDIRECT_URI,
    });

    const tokenRes = await axios.post(
  `${OAUTH_TOKEN_BASE}/token`,
  body,
  { headers: { "Content-Type": "application/x-www-form-urlencoded" }, timeout: 20000 }
);

    const tokens = tokenRes.data || {};
    const locationId =
      tokens.locationId ||
      tokens.location_id ||
      tokens.location ||
      "default";

    tokenStore.set(locationId, tokens);

    console.log("[oauth] tokens saved for location:", locationId, {
      haveAccess: !!tokens.access_token,
      haveRefresh: !!tokens.refresh_token,
      expiresIn: tokens.expires_in,
    });

    return res
      .status(200)
      .send(`<!doctype html>
<html>
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>App Connected</title>
<style>
  body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;margin:0;background:#0b0b0c;color:#e5e7eb;display:flex;align-items:center;justify-content:center;height:100vh}
  .card{background:#111827;border:1px solid #1f2937;border-radius:14px;padding:24px;max-width:560px;text-align:center;box-shadow:0 10px 30px rgba(0,0,0,.3)}
  h1{margin:0 0 6px;font-size:22px}
  p{margin:6px 0 0;color:#9ca3af}
  .ok{display:inline-block;margin-top:14px;background:#16a34a;color:#fff;padding:8px 12px;border-radius:8px}
</style>
</head>
<body>
  <div class="card">
    <h1>✅ Eden iMessage connected</h1>
    <p>You can close this window and return to HighLevel.</p>
    <div class="ok">Location: ${locationId}</div>
  </div>
  <script>
    setTimeout(() => { window.close?.(); }, 1500);
  </script>
</body>
</html>`);
  } catch (e) {
    console.error(
      "[oauth] callback error:",
      e?.response?.status,
      e?.response?.data || e.message
    );
    return res.status(500).send("OAuth error. Check server logs for details.");
  }
});

// Quick debug (no secrets exposed)
app.get("/oauth/debug", (_req, res) => {
  const entries = Array.from(tokenStore.keys());
  res.json({ ok: true, locationsWithTokens: entries });
});

// ---------- BlueBubbles proxy UI ----------

// List chats (for sidebar)
app.get("/api/chats", async (_req, res) => {
  try {
    const data = await bbGet("/api/v1/chats");
    const chats = (data?.data ?? data ?? []).map((c) => ({
      guid: c.guid,
      name: c.displayName || c.chatIdentifier || c.guid,
      last: c?.lastMessage?.text || "",
    }));
    res.json({ ok: true, chats });
  } catch (e) {
    res.status(500).json({ ok: false, error: e?.response?.data ?? e?.message });
  }
});

// Get messages for a chat
app.get("/api/messages", async (req, res) => {
  try {
    const chatGuid = req.query.chatGuid;
    if (!chatGuid) return res.status(400).json({ ok: false, error: "chatGuid required" });

    const path = `/api/v1/chat/${encodeURIComponent(chatGuid)}/messages?limit=50`;
    const data = await bbGet(path);

    const messages = (data?.data ?? data ?? []).map((m) => ({
      guid: m.guid,
      text: m.text || "",
      fromMe: !!m.isFromMe,
      date: m.dateCreated || m.date || null,
    }));
    res.json({ ok: true, chatGuid, messages });
  } catch (e) {
    res.status(500).json({ ok: false, error: e?.response?.data ?? e?.message });
  }
});

// Minimal embedded UI for GHL Custom Page
app.get("/app", (_req, res) => {
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.end(`<!doctype html>
<html>
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>iMessage Inbox</title>
<style>
  :root{color-scheme:dark light}
  body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;margin:0;background:#0b0b0c;color:#e5e7eb}
  header{display:flex;align-items:center;justify-content:space-between;padding:16px 20px;border-bottom:1px solid #1f2937}
  .wrap{display:grid;grid-template-columns:280px 1fr;gap:0}
  .sidebar{border-right:1px solid #1f2937;max-height:calc(100vh - 58px);overflow:auto}
  .chat{padding:12px 14px;border-bottom:1px solid #111827;cursor:pointer}
  .chat:hover{background:#0f172a}
  .chat.active{background:#111827}
  .main{display:flex;flex-direction:column;height:calc(100vh - 58px)}
  .msgs{flex:1;overflow:auto;padding:16px}
  .msg{max-width:70%;margin:8px 0;padding:10px 12px;border-radius:12px;line-height:1.3;white-space:pre-wrap}
  .me{background:#2563eb;color:white;margin-left:auto}
  .them{background:#111827}
  .composer{display:flex;gap:8px;padding:12px;border-top:1px solid #1f2937}
  input,button,textarea{font-size:15px}
  textarea{flex:1;background:#0b0b0c;color:#e5e7eb;border:1px solid #1f2937;border-radius:10px;padding:10px;min-height:44px}
  button{background:#16a34a;border:none;border-radius:10px;color:white;padding:10px 14px;cursor:pointer}
  button:disabled{opacity:.6;cursor:not-allowed}
  .status{font-size:12px;color:#9ca3af}
</style>
</head>
<body>
<header>
  <div>
    <strong>iMessage (Private)</strong>
    <span class="status" id="status">checking…</span>
  </div>
  <div class="status">Relay: ${BB_BASE}</div>
</header>

<div class="wrap">
  <aside class="sidebar" id="list"></aside>
  <main class="main">
    <div class="msgs" id="msgs"><div class="status" style="padding:16px">Pick a chat on the left.</div></div>
    <div class="composer">
      <textarea id="text" placeholder="Type an iMessage…"></textarea>
      <button id="send">Send</button>
    </div>
  </main>
</div>

<script>
(async function(){
  try {
    const r = await fetch('/oauth/debug');
    const j = await r.json();
    if (!j.locationsWithTokens || j.locationsWithTokens.length === 0) {
      // No tokens saved, redirect top-level window to auth
      if (window.top === window.self) {
        // already top
        window.location.href = '/oauth/start';
      } else {
        // bust out of iframe
        window.top.location.href = '/oauth/start';
      }
      return;
    }
  } catch(e) {
    console.error('Auth check failed', e);
  }
})();
const statusEl = document.getElementById('status');
const listEl = document.getElementById('list');
const msgsEl = document.getElementById('msgs');
const sendBtn = document.getElementById('send');
const textEl = document.getElementById('text');

let current = null;

async function ping(){
  try{
    const r = await fetch('/health');
    const j = await r.json();
    statusEl.textContent = j.ok ? 'online' : 'offline';
  }catch(e){
    statusEl.textContent = 'offline';
  }
}

async function loadChats(){
  const r = await fetch('/api/chats');
  const j = await r.json();
  listEl.innerHTML = '';
  (j.chats||[]).forEach(c=>{
    const div = document.createElement('div');
    div.className = 'chat' + (current===c.guid ? ' active':'');
    div.textContent = (c.name || c.guid);
    div.onclick = ()=>select(c.guid);
    listEl.appendChild(div);
  });
}

async function select(guid){
  current = guid;
  await renderMessages();
  Array.from(listEl.children).forEach(el=>{
    el.classList.toggle('active', el.textContent.includes(''+guid) ? true : false);
  });
}

function bubble(m){
  const div = document.createElement('div');
  div.className = 'msg ' + (m.fromMe ? 'me':'them');
  div.textContent = m.text || '';
  return div;
}

async function renderMessages(){
  if(!current){ return; }
  msgsEl.innerHTML = '';
  const r = await fetch('/api/messages?chatGuid='+encodeURIComponent(current));
  const j = await r.json();
  (j.messages||[]).forEach(m=> msgsEl.appendChild(bubble(m)));
  msgsEl.scrollTop = msgsEl.scrollHeight;
}

async function send(){
  if(!current){ alert('Pick a chat first'); return; }
  const text = (textEl.value||'').trim();
  if(!text) return;

  // Extract phone from chatGuid when possible: iMessage;-;+1XXXXXXXXXX
  let to = null;
  try {
    const parts = current.split(';');
    to = parts[2];
  } catch(_) {}

  if(!to){ alert('Cannot derive phone from chatGuid'); return; }

  sendBtn.disabled = true;
  try{
    const r = await fetch('/send',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({to, message:text})});
    const j = await r.json();
    if(!j.ok){ alert('Send failed: ' + (j.error||'unknown')); }
    textEl.value = '';
    setTimeout(renderMessages, 700);
  }catch(e){
    alert('Send error: '+e.message);
  }finally{
    sendBtn.disabled = false;
  }
}

sendBtn.addEventListener('click', send);
textEl.addEventListener('keydown', (e)=>{ if(e.key==='Enter' && !e.shiftKey){ e.preventDefault(); send(); } });

(async function(){
  await ping();
  await loadChats();
})();
</script>
</body>
</html>`);
});

// ---------- Start ----------
app.listen(PORT, () => {
  console.log(`[bridge] listening on :${PORT}`);
  console.log(`[bridge] BB_BASE = ${BB_BASE}`);
  if (GHL_INBOUND_URL) console.log(`[bridge] Forwarding inbound to ${GHL_INBOUND_URL}`);
  if (CLIENT_ID && CLIENT_SECRET) console.log("[bridge] OAuth is configured.");
  if (GHL_SHARED_SECRET) console.log("[bridge] Shared secret checks enabled.");
});
