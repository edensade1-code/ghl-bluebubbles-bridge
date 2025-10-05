// index.js
// Eden iMessage Bridge — GHL (HighLevel) ↔ BlueBubbles with OAuth, Conversation Provider delivery,
// optional inbound forwarding to a workflow URL, and a minimal embedded inbox UI.

import express from "express";
import cors from "cors";
import helmet from "helmet";
import morgan from "morgan";
import axios from "axios";
import crypto from "crypto";
import bodyParser from "body-parser";
import qs from "querystring";

const app = express();

/** ---------------- Middleware ---------------- **/

// Capture raw body (useful for HMAC verification later)
app.use(
  express.json({
    limit: "1mb",
    verify: (req, _res, buf) => {
      try {
        req.rawBody = buf.toString("utf8");
      } catch {
        req.rawBody = "";
      }
    },
  })
);
app.use(express.urlencoded({ extended: true }));
app.use(bodyParser.text({ type: ["text/*"] })); // safety for odd callers

// Allow iframing in GHL/LeadConnector
app.use(
  helmet({
    contentSecurityPolicy: {
      useDefaults: true,
      directives: {
        "frame-ancestors": [
          "'self'",
          "*.gohighlevel.com",
          "*.leadconnectorhq.com",
          "*.msgsndr.com",
        ],
      },
    },
    frameguard: { action: "sameorigin" },
  })
);

// CORS
app.use(
  cors({
    origin: [/\.gohighlevel\.com$/, /\.leadconnectorhq\.com$/, /\.msgsndr\.com$/, /localhost/],
    credentials: true,
  })
);

app.use(morgan("tiny"));

/** ---------------- Config ---------------- **/
const PORT = Number(process.env.PORT || 8080);

// BlueBubbles
const BB_BASE = (process.env.BB_BASE || "https://relay.asapcashhomebuyers.com").trim();
const BB_GUID = (process.env.BB_GUID || "REPLACE_WITH_BLUEBUBBLES_SERVER_PASSWORD").trim();

// Optional: forward normalized inbound to your own GHL workflow webhook
const GHL_INBOUND_URL = (process.env.GHL_INBOUND_URL || "").trim();

// OAuth (HighLevel / LeadConnector)
const CLIENT_ID = (process.env.CLIENT_ID || "").trim();
const CLIENT_SECRET = (process.env.CLIENT_SECRET || "").trim();
const GHL_REDIRECT_URI = (
  process.env.GHL_REDIRECT_URI ||
  "https://ieden-bluebubbles-bridge-1.onrender.com/oauth/callback"
).trim();

// OAuth hosts
const OAUTH_AUTHORIZE_BASE = "https://marketplace.gohighlevel.com/oauth";
const OAUTH_TOKEN_BASE = "https://services.leadconnectorhq.com/oauth";

// Shared secret (used for Conversation Provider auth and optional HMAC)
const GHL_SHARED_SECRET = (process.env.GHL_SHARED_SECRET || "").trim();

// Simple in-memory token store (swap for DB later)
const tokenStore = new Map(); // locationId -> tokens

// Sanity logs
if (!BB_GUID || BB_GUID === "REPLACE_WITH_BLUEBUBBLES_SERVER_PASSWORD") {
  console.warn("[WARN] BB_GUID is not set. Set your BlueBubbles server password.");
}
if (!CLIENT_ID || !CLIENT_SECRET) {
  console.log("[bridge] OAuth not configured (CLIENT_ID/CLIENT_SECRET missing).");
}
if (!GHL_SHARED_SECRET) {
  console.log("[bridge] GHL_SHARED_SECRET not set (Bearer/HMAC checks disabled).");
}
if (!GHL_INBOUND_URL) {
  console.log("[bridge] GHL_INBOUND_URL not set (inbound messages won’t be forwarded to a workflow).");
}

/** ---------------- Helpers ---------------- **/
// ===== LeadConnector API helpers =====
const LC_API = "https://services.leadconnectorhq.com";
const LC_VERSION = "2021-07-28"; // required header

const getAnyLocation = () => {
  const first = tokenStore.entries().next();
  if (first.done) return null;
  const [locationId, tokens] = first.value;
  return { locationId, tokens };
};

const lcHeaders = (accessToken) => ({
  "Authorization": `Bearer ${accessToken}`,
  "Content-Type": "application/json",
  "Accept": "application/json",
  "Version": LC_VERSION,
});

// naive refresh if you want later; for now just use access_token we have
const getAccessTokenFor = (locationId) => {
  const row = tokenStore.get(locationId);
  return row?.access_token || null;
};

// Find or create a contact by phone
const upsertContactByPhone = async (locationId, accessToken, e164Phone) => {
  // 1) try search by phone
  try {
    const r = await axios.get(
      `${LC_API}/contacts/search?locationId=${encodeURIComponent(locationId)}&phone=${encodeURIComponent(e164Phone)}`,
      { headers: lcHeaders(accessToken), timeout: 15000 }
    );
    const hit = r?.data?.contacts?.[0] || r?.data?.contact || null;
    if (hit?.id) return hit.id;
  } catch (_) {}

  // 2) create minimal contact
  const createBody = {
    locationId,
    // HighLevel expects one of: phone, phoneNumbers, etc.; phone is commonly accepted
    phone: e164Phone,
    name: e164Phone, // placeholder name
  };
  const cr = await axios.post(`${LC_API}/contacts/`, createBody, {
    headers: lcHeaders(accessToken),
    timeout: 15000,
  });
  return cr?.data?.id || cr?.data?.contact?.id;
};

// Push inbound message into Conversations
const pushInboundMessage = async ({
  locationId,
  accessToken,
  contactId,
  text,
  fromNumber,   // customer number (sender)
  toNumber,     // your iMessage number (optional)
}) => {
  // Many installs accept this shape on /conversations/messages
  const body = {
    locationId,
    contactId,
    // channel/type metadata:
    type: "SMS",                 // GHL treats provider channels as SMS-like
    direction: "inbound",
    message: text,
    fromNumber,
    toNumber,
    provider: "iMessage (EDEN)", // label for clarity
  };

  try {
    const r = await axios.post(`${LC_API}/conversations/messages`, body, {
      headers: lcHeaders(accessToken),
      timeout: 20000,
    });
    return r.data;
  } catch (e) {
    // Fallback: some accounts prefer a different field name for text
    try {
      const alt = { ...body, text: text };
      const r2 = await axios.post(`${LC_API}/conversations/messages`, alt, {
        headers: lcHeaders(accessToken),
        timeout: 20000,
      });
      return r2.data;
    } catch (e2) {
      console.error("[inbound->GHL] failed:", e?.response?.status, e?.response?.data || e.message);
      throw e2;
    }
  }
};


const newTempGuid = (prefix = "temp") =>
  `${prefix}-${crypto.randomBytes(6).toString("hex")}`;

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
  if (!e) throw new Error("Invalid 'to' phone. Use E.164 like +13051234567");
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
const bbGet = async (path) => {
  const url = `${BB_BASE}${path}${path.includes("?") ? "&" : "?"}guid=${encodeURIComponent(BB_GUID)}`;
  const { data } = await axios.get(url, { timeout: 15000 });
  return data;
};

const verifyGhlSignature = (req) => {
  if (!GHL_SHARED_SECRET) return true;
  const sigHex = req.header("X-GHL-Signature") || "";
  const raw = req.rawBody || (() => {
    // fallback (shouldn’t hit because we captured rawBody above)
    try {
      if (req.is("application/json")) return JSON.stringify(req.body);
      if (req.is("application/x-www-form-urlencoded")) return qs.stringify(req.body);
      if (typeof req.body === "string") return req.body;
      return JSON.stringify(req.body ?? {});
    } catch {
      return "";
    }
  })();
  const expectedHex = crypto.createHmac("sha256", GHL_SHARED_SECRET).update(raw).digest("hex");
  if (!sigHex || expectedHex.length !== sigHex.length) return false;
  return crypto.timingSafeEqual(Buffer.from(expectedHex, "hex"), Buffer.from(sigHex, "hex"));
};

const verifyBearer = (req) => {
  if (!GHL_SHARED_SECRET) return true;
  // Prefer Authorization header
  const auth = req.header("Authorization") || "";
  const m = auth.match(/^Bearer\s+(.+)$/i);
  if (m && m[1].trim() === GHL_SHARED_SECRET) return true;
  // Fallback: ?key= on query
  if ((req.query.key || "").trim() === GHL_SHARED_SECRET) return true;
  return false;
};

// Extract flexible fields GHL might send
const extractToAndMessage = (body = {}) => {
  const to =
    body.to ||
    body.toNumber ||
    body.to_phone ||
    body.recipient?.phone ||
    body.recipientPhone ||
    body.phone ||
    body.number ||
    body.toPhone ||
    body.to_phone_number ||
    body.address ||
    body.destination ||
    null;

  const message =
    body.message ||
    body.text ||
    body.body ||
    body.content ||
    body.messageBody ||
    null;

  return { to, message };
};

/** ---------------- Core send handler (used by /provider/deliver and /send) ---------------- **/
const handleProviderSend = async (req, res) => {
  try {
    // Only enforce Bearer/key if you actually set GHL_SHARED_SECRET
    if (GHL_SHARED_SECRET && !verifyBearer(req)) {
      return res.status(401).json({ status: "error", error: "Unauthorized" });
    }

    console.log("[provider] inbound headers:", req.headers);
    console.log("[provider] inbound payload:", req.body);

    let { to, message } = extractToAndMessage(req.body || {});
    if (!to) to = req.query.to;
    if (!message) message = req.query.message;

    const e164 = ensureE164(to);
    if (!message || !String(message).trim()) {
      return res.status(400).json({ ok: false, success: false, error: "Missing 'message'" });
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
      success: true,
      status: "sent",
      provider: "eden-imessage",
      relay: BB_BASE,
      id: data?.guid || data?.data?.guid || payload.tempGuid,
      data,
    });
  } catch (err) {
    console.error("[provider] send error:", err?.response?.data || err.message);
    const status = err?.response?.status ?? 500;
    return res.status(status).json({
      ok: false,
      success: false,
      error: err?.response?.data ?? err?.message ?? "Unknown error",
    });
  }
};

/** ---------------- Routes ---------------- **/

app.get("/", (_req, res) => {
  res.status(200).json({
    ok: true,
    name: "ghl-bluebubbles-bridge",
    relay: BB_BASE,
    oauthConfigured: !!(CLIENT_ID && CLIENT_SECRET),
    inboundForward: !!GHL_INBOUND_URL,
    routes: [
      "/health",
      "/provider/deliver",
      "/send",
      "/bb",
      "/webhook",
      "/api/chats",
      "/api/messages",
      "/app",
      "/oauth/start",
      "/oauth/callback",
      "/oauth/debug",
    ],
  });
});

app.get("/health", async (_req, res) => {
  try {
    const pong = await axios.get(`${BB_BASE}/api/v1/ping?guid=${encodeURIComponent(BB_GUID)}`, { timeout: 8000 });
    res.status(200).json({ ok: true, relay: BB_BASE, ping: pong.data ?? null });
  } catch (e) {
    res.status(503).json({ ok: false, relay: BB_BASE, error: e?.response?.data ?? e?.message ?? "Ping failed" });
  }
});

// Conversation Provider Delivery URL (use this in the Marketplace “Delivery URL”)
app.post("/provider/deliver", handleProviderSend);

// Keep /send for tests (Postman, etc.)
app.post("/send", handleProviderSend);

// BlueBubbles passthrough
app.post("/bb", async (req, res) => {
  try {
    const { path, body } = req.body || {};
    if (!path || typeof path !== "string" || !path.startsWith("/api/")) {
      return res.status(400).json({ ok: false, error: "Provide valid 'path' starting with /api/" });
    }
    const data = await bbPost(path, body ?? {});
    res.status(200).json({ ok: true, relay: BB_BASE, data });
  } catch (err) {
    const status = err?.response?.status ?? 500;
    res.status(status).json({ ok: false, relay: BB_BASE, error: err?.response?.data ?? err?.message ?? "Unknown error" });
  }
});

// Inbound webhook (from BlueBubbles) + GHL trigger subscription ping
app.post("/webhook", async (req, res) => {
  try {
    // 0) Allow GHL Trigger subscription pings (they include your Bearer)
    if (verifyBearer(req)) return res.status(200).json({ ok: true });

    // 1) Parse BlueBubbles payload (your logs show this exact shape)
    const src  = req.body || {};
    const data = src.data || {};
    const messageText =
      data.text ??
      data.message?.text ??
      src.text ??
      null;

    const fromNumber =
      data.handle?.address ??
      data.message?.handle?.address ??
      src.from ??
      null;

    const chatGuid =
      data.chats?.[0]?.guid ??
      data.chat?.guid ??
      null;

    const toNumber =
      data.chats?.[0]?.chatIdentifier ??
      data.chats?.[0]?.lastAddressedHandle ??
      data.to ??
      null;

    const isFromMe = Boolean(
      data.isFromMe ?? data.message?.isFromMe ?? src.isFromMe ?? false
    );

    // 2) Ignore echoes of your own outbound (optional)
    if (isFromMe) {
      console.log("[bridge] /webhook: own-message (ignored)", messageText);
      return res.status(200).json({ ok: true, ignored: "isFromMe" });
    }

    // 3) Make sure we have a location & token to talk to GHL
    const any = getAnyLocation();
    if (!any) {
      console.error("[inbound->GHL] no OAuth tokens saved yet (install the app first)");
      return res.status(200).json({ ok: true, note: "no-oauth" });
    }
    const { locationId, tokens } = any;
    const accessToken = getAccessTokenFor(locationId);
    if (!accessToken) {
      console.error("[inbound->GHL] missing access_token for location", locationId);
      return res.status(200).json({ ok: true, note: "no-access-token" });
    }

    // 4) Normalize/validate
    if (!messageText || !fromNumber) {
      console.log("[inbound->GHL] missing message or fromNumber", { messageText, fromNumber });
      return res.status(200).json({ ok: true });
    }

    // 5) Ensure a contact exists for the sender (by phone)
    const e164 = ensureE164(fromNumber);
    const contactId = await upsertContactByPhone(locationId, accessToken, e164);

    // 6) Push the inbound into HighLevel Conversations
    const pushed = await pushInboundMessage({
      locationId,
      accessToken,
      contactId,
      text: messageText,
      fromNumber: e164,
      toNumber: toNumber || null,
    });

    console.log("[inbound->GHL] delivered", {
      locationId,
      contactId,
      chatGuid,
      len: messageText.length,
    });

    // (Optional) also forward to your own webhook if configured
    if (GHL_INBOUND_URL) {
      const normalized = {
        event: "incoming-imessage",
        messageText,
        from: e164,
        to: toNumber || null,
        chatGuid,
        receivedAt: new Date().toISOString(),
      };
      try {
        await axios.post(GHL_INBOUND_URL, normalized, {
          headers: { "Content-Type": "application/json" },
          timeout: 10000,
        });
      } catch (e) {
        console.error("[bridge] forward to GHL_INBOUND_URL failed:", e?.message);
      }
    }

    return res.status(200).json({ ok: true, pushed });
  } catch (err) {
    console.error("[bridge] /webhook error:", err?.response?.data || err.message);
    // Always 200 so BlueBubbles doesn’t retry forever
    return res.status(200).json({ ok: true, error: "ingest-failed" });
  }
});



// Optional: signed marketplace webhook
app.post("/ghl/webhook", (req, res) => {
  try {
    if (!verifyGhlSignature(req)) return res.status(401).json({ ok: false, error: "Invalid signature" });
    console.log("[bridge] /ghl/webhook verified");
    res.status(200).json({ ok: true });
  } catch (e) {
    console.error("[ghl/webhook] error:", e?.message);
    res.status(200).json({ ok: true });
  }
});

/** ---------------- OAuth (HL / LeadConnector) ---------------- **/

app.get("/oauth/start", (req, res) => {
  if (!CLIENT_ID || !GHL_REDIRECT_URI) {
    return res.status(400).send("OAuth not configured (missing CLIENT_ID or GHL_REDIRECT_URI).");
  }

  // Scopes: message access only, no contact creation permissions
  const scope = [
    "conversations.readonly",
    "conversations.write",
    "locations.readonly"
  ].join(" ");

  const params = new URLSearchParams({
    client_id: CLIENT_ID,
    response_type: "code",
    redirect_uri: GHL_REDIRECT_URI,
    scope,
  });

  res.redirect(`${OAUTH_AUTHORIZE_BASE}/authorize?${params.toString()}`);
});

app.get("/oauth/callback", async (req, res) => {
  try {
    const { code, error, error_description } = req.query;
    if (error) return res.status(400).send("OAuth denied. Please try again.");
    if (!code)   return res.status(400).send("Missing authorization code.");

    const body = qs.stringify({
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
      grant_type: "authorization_code",
      code,
      redirect_uri: GHL_REDIRECT_URI,
    });

    const tokenRes = await axios.post(`${OAUTH_TOKEN_BASE}/token`, body, {
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      timeout: 20000,
    });

    const tokens = tokenRes.data || {};
    const locationId = tokens.locationId || tokens.location_id || tokens.location || "default";
    tokenStore.set(locationId, tokens);

    console.log("[oauth] tokens saved for location:", locationId, {
      haveAccess:  !!tokens.access_token,
      haveRefresh: !!tokens.refresh_token,
      expiresIn: tokens.expires_in,
    });

    return res.status(200).send(`<!doctype html><html><body style="font-family:system-ui;background:#0b0b0c;color:#e5e7eb;display:flex;align-items:center;justify-content:center;height:100vh"><div style="background:#111827;border:1px solid #1f2937;border-radius:14px;padding:24px;max-width:560px;text-align:center;box-shadow:0 10px 30px rgba(0,0,0,.3)"><h1>✅ Eden iMessage connected</h1><p>You can close this window and return to HighLevel.</p><div style="margin-top:10px;background:#16a34a;color:#fff;padding:8px 12px;border-radius:8px">Location: ${locationId}</div></div><script>setTimeout(()=>{window.close?.();},1500)</script></body></html>`);
  } catch (e) {
    console.error("[oauth] callback error:", e?.response?.status, e?.response?.data || e.message);
    res.status(500).send("OAuth error. Check server logs for details.");
  }
});

app.get("/oauth/debug", (_req, res) => {
  res.json({ ok: true, locationsWithTokens: Array.from(tokenStore.keys()) });
});

/** ---------------- Minimal embedded UI ---------------- **/

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

app.get("/api/messages", async (req, res) => {
  try {
    const chatGuid = req.query.chatGuid;
    if (!chatGuid) return res.status(400).json({ ok: false, error: "chatGuid required" });
    const data = await bbGet(`/api/v1/chat/${encodeURIComponent(chatGuid)}/messages?limit=50`);
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

app.get("/app", (_req, res) => {
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.end(`<!doctype html>
<html><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/><title>iMessage Inbox</title>
<style>:root{color-scheme:dark light}body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;margin:0;background:#0b0b0c;color:#e5e7eb}
header{display:flex;align-items:center;justify-content:space-between;padding:16px 20px;border-bottom:1px solid #1f2937}
.wrap{display:grid;grid-template-columns:280px 1fr;gap:0}.sidebar{border-right:1px solid #1f2937;max-height:calc(100vh - 58px);overflow:auto}
.chat{padding:12px 14px;border-bottom:1px solid #111827;cursor:pointer}.chat:hover{background:#0f172a}.chat.active{background:#111827}
.main{display:flex;flex-direction:column;height:calc(100vh - 58px)}.msgs{flex:1;overflow:auto;padding:16px}
.msg{max-width:70%;margin:8px 0;padding:10px 12px;border-radius:12px;line-height:1.3;white-space:pre-wrap}.me{background:#2563eb;color:#fff;margin-left:auto}.them{background:#111827}
.composer{display:flex;gap:8px;padding:12px;border-top:1px solid #1f2937}textarea{flex:1;background:#0b0b0c;color:#e5e7eb;border:1px solid #1f2937;border-radius:10px;padding:10px;min-height:44px}
button{background:#16a34a;border:none;border-radius:10px;color:white;padding:10px 14px;cursor:pointer}button:disabled{opacity:.6;cursor:not-allowed}.status{font-size:12px;color:#9ca3af}</style></head>
<body>
<header><div><strong>iMessage (Private)</strong><span class="status" id="status">checking…</span></div><div class="status">Relay: ${BB_BASE}</div></header>
<div class="wrap"><aside class="sidebar" id="list"></aside><main class="main">
  <div class="msgs" id="msgs"><div class="status" style="padding:16px">Pick a chat on the left.</div></div>
  <div class="composer"><textarea id="text" placeholder="Type an iMessage…"></textarea><button id="send">Send</button></div>
</main></div>
<script>
(async function(){
  try{const r=await fetch('/oauth/debug');const j=await r.json();if(!j.locationsWithTokens||j.locationsWithTokens.length===0){(window.top===window.self?window:window.top).location.href='/oauth/start';return;}}catch(e){}
})();
const statusEl=document.getElementById('status'),listEl=document.getElementById('list'),msgsEl=document.getElementById('msgs'),sendBtn=document.getElementById('send'),textEl=document.getElementById('text');let current=null;
async function ping(){try{const r=await fetch('/health');const j=await r.json();statusEl.textContent=j.ok?'online':'offline';}catch(e){statusEl.textContent='offline';}}
async function loadChats(){const r=await fetch('/api/chats');const j=await r.json();listEl.innerHTML='';(j.chats||[]).forEach(c=>{const d=document.createElement('div');d.className='chat'+(current===c.guid?' active':'');d.textContent=(c.name||c.guid);d.onclick=()=>select(c.guid);listEl.appendChild(d);});}
async function select(g){current=g;await renderMessages();Array.from(listEl.children).forEach(el=>{el.classList.toggle('active',el.textContent.includes(''+g));});}
function bubble(m){const d=document.createElement('div');d.className='msg '+(m.fromMe?'me':'them');d.textContent=m.text||'';return d;}
async function renderMessages(){if(!current)return;msgsEl.innerHTML='';const r=await fetch('/api/messages?chatGuid='+encodeURIComponent(current));const j=await r.json();(j.messages||[]).forEach(m=>msgsEl.appendChild(bubble(m)));msgsEl.scrollTop=msgsEl.scrollHeight;}
async function send(){if(!current){alert('Pick a chat first');return;}const t=(textEl.value||'').trim();if(!t)return;let to=null;try{to=current.split(';')[2]}catch(_){ }if(!to){alert('Cannot derive phone from chatGuid');return;}sendBtn.disabled=true;try{const r=await fetch('/send',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({to, message:t})});const j=await r.json();if(!j.ok&&!j.success){alert('Send failed: '+(j.error||'unknown'));}textEl.value='';setTimeout(renderMessages,700);}catch(e){alert('Send error: '+e.message);}finally{sendBtn.disabled=false;}}
sendBtn.addEventListener('click',send);textEl.addEventListener('keydown',e=>{if(e.key==='Enter'&&!e.shiftKey){e.preventDefault();send();}});
(async function(){await ping();await loadChats();})();</script>
</body></html>`);
});

/** ---------------- Start ---------------- **/
app.listen(PORT, () => {
  console.log(`[bridge] listening on :${PORT}`);
  console.log(`[bridge] BB_BASE = ${BB_BASE}`);
  if (GHL_INBOUND_URL) console.log(`[bridge] Forwarding inbound to ${GHL_INBOUND_URL}`);
  if (CLIENT_ID && CLIENT_SECRET) console.log("[bridge] OAuth is configured.");
  if (GHL_SHARED_SECRET) console.log("[bridge] Shared secret checks enabled.");
});
