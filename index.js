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
// --- BB GET helper (add near bbPost) ---
const bbGet = async (path) => {
  const url = `${BB_BASE}${path}${path.includes("?") ? "&" : "?"}guid=${encodeURIComponent(BB_GUID)}`;
  const { data } = await axios.get(url, { timeout: 15000 });
  return data;
};

// --- List chats (for sidebar) ---
app.get("/api/chats", async (_req, res) => {
  try {
    // BlueBubbles: GET /api/v1/chats?guid=...
    const data = await bbGet("/api/v1/chats");
    // map lightly for UI
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

// --- Get messages for a chat ---
app.get("/api/messages", async (req, res) => {
  try {
    const chatGuid = req.query.chatGuid;
    if (!chatGuid) return res.status(400).json({ ok: false, error: "chatGuid required" });

    // BlueBubbles: GET /api/v1/chat/{guid}/messages?limit=50&offset=0&includeDeleted=false
    const path = `/api/v1/chat/${encodeURIComponent(chatGuid)}/messages?limit=50`;
    const data = await bbGet(path);

    // Normalize minimally
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
// --- Minimal embedded UI for GHL Custom Page ---
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
      <textarea id="text" placeholder="Type a message…"></textarea>
      <button id="send">Send</button>
    </div>
  </main>
</div>

<script>
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
    setTimeout(renderMessages, 700); // refresh shortly
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
  if (GHL_SHARED_SECRET) console.log("[bridge] GHL webhook signature verification enabled.");
});
