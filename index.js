// index.js
// Eden iMessage Bridge — HighLevel (GHL) ↔ BlueBubbles

import express from "express";
import cors from "cors";
import helmet from "helmet";
import morgan from "morgan";
import axios from "axios";
import crypto from "crypto";
import bodyParser from "body-parser";
import qs from "querystring";
import fs from "fs/promises";

const app = express();

/* -------------------------------------------------------------------------- */
/* Middleware                                                                 */
/* -------------------------------------------------------------------------- */
// Capture raw JSON for optional signature checks
app.use(
  express.json({
    limit: "1mb",
    verify: (req, _res, buf) => {
      try { req.rawBody = buf.toString("utf8"); } catch { req.rawBody = ""; }
    },
  })
);
app.use(express.urlencoded({ extended: true }));
app.use(bodyParser.text({ type: ["text/*"] })); // friendly for quick tests

// Helmet (allow embedding in GHL iframes)
app.use(
  helmet({
    contentSecurityPolicy: {
      useDefaults: true,
      directives: {
        // allow HighLevel to embed our app
        "frame-ancestors": [
          "'self'",
          "*.gohighlevel.com",
          "*.leadconnectorhq.com",
          "*.msgsndr.com",
          "marketplace.gohighlevel.com"
        ],
        // keep inline script for the tiny /app UI
        "script-src": ["'self'", "'unsafe-inline'"],
      },
    },
    // IMPORTANT: disable X-Frame-Options so CSP controls framing
    frameguard: false,
    // Loosen these so the GHL preview doesn’t get blocked
    crossOriginEmbedderPolicy: false,
    crossOriginOpenerPolicy: false,
  })
);

// CORS for GHL domains and local dev
app.use(
  cors({
    origin: [/\.gohighlevel\.com$/, /\.leadconnectorhq\.com$/, /\.msgsndr\.com$/, /localhost/],
    credentials: true,
  })
);

app.use(morgan("tiny"));

/* -------------------------------------------------------------------------- */
/* Config                                                                     */
/* -------------------------------------------------------------------------- */
const PORT = Number(process.env.PORT || 8080);

// BlueBubbles relay + password (Server Password from BB Settings → Connection)
const BB_BASE = (process.env.BB_BASE || "https://relay.asapcashhomebuyers.com").trim();
const BB_GUID = (process.env.BB_GUID || "REPLACE_WITH_BLUEBUBBLES_SERVER_PASSWORD").trim();

// Optional: forward a minimal event to a webhook (not required)
const GHL_INBOUND_URL = (process.env.GHL_INBOUND_URL || "").trim();

// OAuth (LeadConnector)
const CLIENT_ID = (process.env.CLIENT_ID || "").trim();
const CLIENT_SECRET = (process.env.CLIENT_SECRET || "").trim();
const GHL_REDIRECT_URI = (
  process.env.GHL_REDIRECT_URI ||
  "https://ieden-bluebubbles-bridge-1.onrender.com/oauth/callback"
).trim();

const OAUTH_AUTHORIZE_BASE = "https://marketplace.gohighlevel.com/oauth";
const OAUTH_TOKEN_BASE     = "https://services.leadconnectorhq.com/oauth";

// Conversation Provider shared secret (Authorization: Bearer ... or ?key=...)
const GHL_SHARED_SECRET = (process.env.GHL_SHARED_SECRET || "").trim();

/**
 * IMPORTANT
 * ----------
 * PARKING_NUMBER **must be a phone number that belongs to the GHL Location**.
 * (Typically the Twilio/LeadConnector SMS DID, e.g. +17867334163.)
 * GHL will reject inbound creates if `fromNumber` is not one of the Location’s numbers.
 * Do NOT set this to your iPhone’s number.
 */
const ENV_PARKING_NUMBER =
  (process.env.PARKING_NUMBER || process.env.BUSINESS_NUMBER || "").trim();

// Token persistence
const TOKENS_FILE = (process.env.TOKENS_FILE || "./tokens.json").trim();

/* -------------------------------------------------------------------------- */
/* State & Helpers                                                            */
/* -------------------------------------------------------------------------- */
const tokenStore = new Map(); // Map<locationId, tokens>

// lightweight inbound de-dupe
const recentInboundKeys = new Set();
const DEDUPE_TTL_MS = 15_000;
const dedupeKey = (o) =>
  `${o.chatGuid || ""}|${o.from || ""}|${(o.text || "").slice(0, 128)}`;
const rememberInbound = (k) => {
  recentInboundKeys.add(k);
  setTimeout(() => recentInboundKeys.delete(k), DEDUPE_TTL_MS);
};

// tokens I/O
async function loadTokenStore() {
  try {
    const raw = await fs.readFile(TOKENS_FILE, "utf8");
    const arr = JSON.parse(raw);
    if (Array.isArray(arr)) {
      tokenStore.clear();
      for (const [loc, tok] of arr) tokenStore.set(loc, tok);
      console.log(`[oauth] loaded ${tokenStore.size} location token(s) from ${TOKENS_FILE}`);
    }
  } catch { /* fresh start */ }
}
async function saveTokenStore() {
  try {
    const arr = Array.from(tokenStore.entries());
    await fs.writeFile(TOKENS_FILE, JSON.stringify(arr, null, 2), "utf8");
    console.log(`[oauth] tokens persisted to ${TOKENS_FILE}`);
  } catch (e) {
    console.error("[oauth] failed to persist tokens:", e?.message);
  }
}

// sanity warnings
if (!BB_GUID || BB_GUID === "REPLACE_WITH_BLUEBUBBLES_SERVER_PASSWORD") {
  console.warn("[WARN] BB_GUID is not set. Set your BlueBubbles server password.");
}
if (!CLIENT_ID || !CLIENT_SECRET) {
  console.log("[bridge] OAuth not configured (CLIENT_ID/CLIENT_SECRET missing).");
}
if (!GHL_SHARED_SECRET) {
  console.log("[bridge] GHL_SHARED_SECRET not set (Bearer/key checks disabled).");
}
if (!ENV_PARKING_NUMBER) {
  console.log("[bridge] PARKING_NUMBER/BUSINESS_NUMBER not set (inbound will be rejected by GHL).");
}

/* -------------------------------------------------------------------------- */
/* General helpers                                                            */
/* -------------------------------------------------------------------------- */
const newTempGuid = (p = "temp") => `${p}-${crypto.randomBytes(6).toString("hex")}`;

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
  if (!e) throw new Error("Invalid US phone. Use E.164 like +13051234567");
  return e;
};
const chatGuidForPhone = (e164) => `iMessage;-;${e164}`;
// Resolve our identity (parking/business) number as E.164 or null
function getIdentityNumber() {
  try {
    return ENV_PARKING_NUMBER ? ensureE164(ENV_PARKING_NUMBER) : null;
  } catch {
    return null;
  }
}

// BB REST wrappers
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

// shared-secret checks
const verifyBearer = (req) => {
  if (!GHL_SHARED_SECRET) return true;
  const auth = req.header("Authorization") || "";
  const m = auth.match(/^Bearer\s+(.+)$/i);
  if (m && m[1].trim() === GHL_SHARED_SECRET) return true;
  if ((req.query.key || "").trim() === GHL_SHARED_SECRET) return true; // fallback
  return false;
};

/* -------------------------------------------------------------------------- */
/* LeadConnector helpers                                                      */
/* -------------------------------------------------------------------------- */
const LC_API = "https://services.leadconnectorhq.com";
const LC_VERSION = "2021-07-28";

const lcHeaders = (accessToken) => ({
  "Authorization": `Bearer ${accessToken}`,
  "Content-Type": "application/json",
  "Accept": "application/json",
  "Version": LC_VERSION,
});

const getAnyLocation = () => {
  const it = tokenStore.entries().next();
  if (it.done) return null;
  const [locationId, tokens] = it.value;
  return { locationId, tokens };
};

async function getValidAccessToken(locationId) {
  const row = tokenStore.get(locationId);
  if (!row) return null;

  const created = Number(row._created_at_ms || 0) || Date.now();
  const ttl = Number(row.expires_in || 0) * 1000;
  const slack = 60_000;
  const isExpired = ttl > 0 ? (Date.now() > created + ttl - slack) : false;

  if (!isExpired) return row.access_token || null;

  if (!row.refresh_token) return row.access_token || null;

  try {
    const body = qs.stringify({
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
      grant_type: "refresh_token",
      refresh_token: row.refresh_token,
    });
    const resp = await axios.post(`${OAUTH_TOKEN_BASE}/token`, body, {
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      timeout: 20000,
    });
    const fresh = resp.data || {};
    fresh._created_at_ms = Date.now();
    tokenStore.set(locationId, { ...row, ...fresh });
    await saveTokenStore();
    console.log("[oauth] refreshed access token for location:", locationId);
    return fresh.access_token || null;
  } catch (e) {
    console.error("[oauth] refresh failed:", e?.response?.status, e?.response?.data || e.message);
    return row.access_token || null;
  }
}

async function withLcCall(locationId, fn) {
  let token = await getValidAccessToken(locationId);
  if (!token) throw new Error("no-access-token");
  try {
    return await fn(token);
  } catch (e) {
    if (e?.response?.status === 401) {
      token = await getValidAccessToken(locationId);
      if (!token) throw e;
      return await fn(token);
    }
    throw e;
  }
}

// Find existing contact by phone (tolerant to formats)
const findContactIdByPhone = async (locationId, e164Phone) => {
  const digits = (e164Phone || "").replace(/\D/g, "");
  const last10 = digits.slice(-10);

  const tryQueries = [
    e164Phone,
    digits,
    last10,
    `(${last10.slice(0,3)}) ${last10.slice(3,6)}-${last10.slice(6)}`,
  ];

  const normalize = (p) => {
    if (!p) return null;
    const d = String(p).replace(/\D/g, "");
    if (d.length >= 11 && d.startsWith("1")) return `+${d}`;
    if (d.length === 10) return `+1${d}`;
    return d ? `+${d}` : null;
  };

  for (const q of tryQueries) {
    try {
      const r = await withLcCall(locationId, (access) =>
        axios.get(
          `${LC_API}/contacts/?locationId=${encodeURIComponent(locationId)}&query=${encodeURIComponent(q)}`,
          { headers: lcHeaders(access), timeout: 15000 }
        )
      );

      const list = r?.data?.contacts || r?.data?.items || r?.data?.data || [];
      for (const c of list) {
        const candidates = new Set();
        if (c.phone) candidates.add(c.phone);
        if (Array.isArray(c.phoneNumbers)) {
          for (const pn of c.phoneNumbers) {
            if (typeof pn === "string") candidates.add(pn);
            else if (pn?.phone) candidates.add(pn.phone);
            else if (pn?.number) candidates.add(pn.number);
          }
        }
        for (const cand of candidates) {
          const n = normalize(cand);
          if (n && n === normalize(e164Phone)) {
            return c.id || c._id || null;
          }
        }
      }
    } catch (e) {
      console.error("[findContactIdByPhone] query failed:", q, e?.response?.status, e?.response?.data || e.message);
    }
  }
  return null;
};

// Create a message in Conversations (we pass direction explicitly)
// **toNumber must be CONTACT phone**
// **fromNumber must be a LOCATION phone**
const pushInboundMessage = async ({
  locationId,
  accessToken,
  contactId,
  text,
  fromNumber, // location number (Twilio/LeadConnector DID)
  toNumber,   // contact phone
  direction = "inbound",
}) => {
  const body = {
  locationId,
  contactId,
  type: "SMS",
  direction,
  message: text,
  fromNumber,
  toNumber,

  // ⬇️ THIS LINE IS THE IMPORTANT ONE
  conversationProviderId: "68d94718bcd02bcf453ccf46",

  // purely cosmetic label for your own logs
  provider: "iMessage (EDEN)",
};
   try {
    const r = await axios.post(`${LC_API}/conversations/messages`, body, {
      headers: lcHeaders(accessToken),
      timeout: 20000,
    });
    const resp = r.data || {};
    console.log("[inbound->GHL] push response:", JSON.stringify(resp));
    // Normalize a simple success flag so our logs aren’t misleading
    if (resp.error || resp.success === false) {
      console.error("[inbound->GHL] API accepted request but reported error:", JSON.stringify(resp));
    }
    return resp;
  } catch (e) {
    console.error("[inbound->GHL] push failed:", e?.response?.status, e?.response?.data || e.message);
    return null;
  }
};

/* -------------------------------------------------------------------------- */
/* Provider send (Delivery URL)                                               */
/* -------------------------------------------------------------------------- */

function extractToAndMessage(rawBody = {}) {
  let body = rawBody;
  if (typeof body === "string") {
    try { body = JSON.parse(body); } catch { body = {}; }
  }
  if (!body || typeof body !== "object") body = {};

  const to =
    body.to ||
    body.toNumber ||
    body.phone ||
    body.number ||
    body.recipient?.phone ||
    body.address ||
    body.destination ||
    null;

  const message =
    body.message ||
    body.text ||
    body.body ||
    body.content ||
    null;

  return { to, message, body };
}

const handleProviderSend = async (req, res) => {
  try {
    if (GHL_SHARED_SECRET && !verifyBearer(req)) {
      return res.status(401).json({ status: "error", error: "Unauthorized" });
    }

    const { to: toRaw, message: messageRaw, body: parsedBody } = extractToAndMessage(req.body || {});
    let to = toRaw ?? req.query.to;
    let message = messageRaw ?? req.query.message;

    console.log("[provider] method:", req.method);
    console.log("[provider] headers:", req.headers);
    console.log("[provider] raw body type:", typeof req.body);
    if (typeof req.body === "string") console.log("[provider] raw body (string):", req.body.slice(0, 400));
    console.log("[provider] parsed body:", parsedBody);
    console.log("[provider] extracted:", { to, message });

    if (!to) return res.status(400).json({ ok: false, success: false, error: "Missing 'to' phone" });
    const e164 = ensureE164(String(to));
    if (!message || !String(message).trim()) {
      return res.status(400).json({ ok: false, success: false, error: "Missing 'message'" });
    }
// Map BlueBubbles direction to GHL (GHL infers direction from numbers)
let direction, fromNumber, toNumber;
if (isFromMe) {
  // You → contact (outbound)
  direction  = "outbound";
  fromNumber = identityNumber;   // your location/parking number
  toNumber   = contactE164;      // the contact's phone
} else {
  // Contact → you (inbound)
  direction  = "inbound";
  fromNumber = contactE164;      // the contact's phone (MUST be fromNumber)
  toNumber   = identityNumber;   // your location/parking number
}
    const payload = {
      chatGuid: chatGuidForPhone(e164),
      tempGuid: newTempGuid("temp-bridge"),
      message: String(message),
      method: "apple-script",
    };

    const data = await bbPost("/api/v1/message/text", payload);
// --- Mirror this outbound into GHL so it appears in the Inbox UI
try {
  // We need a location (OAuth) and the contactId for "to" so we can log the message
  const any = getAnyLocation();
  if (any) {
    const { locationId } = any;
    const identityNumber = getIdentityNumber();                   // from env
    const contactId = await findContactIdByPhone(locationId, e164);
    const accessToken = await getValidAccessToken(locationId);

    if (identityNumber && contactId && accessToken) {
      await pushInboundMessage({
        locationId,
        accessToken,
        contactId,
        text: String(message),
        fromNumber: identityNumber,  // you / business identity
        toNumber: e164,              // contact's phone
        direction: "outbound",       // IMPORTANT
      });
    } else {
      console.log("[provider->mirror] skip (identity/contact/token missing)", {
        hasIdentity: !!identityNumber,
        hasContact:  !!contactId,
        hasToken:    !!accessToken,
      });
    }
  } else {
    console.log("[provider->mirror] skip: no OAuth location available");
  }
} catch (e) {
  console.error("[provider->mirror] failed to log outbound:", e?.response?.data || e.message);
}
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
// --- Simple ring buffer so we can see what we pushed into GHL
const LAST_INBOUND = [];
function rememberPush(p) {
  LAST_INBOUND.push({ at: new Date().toISOString(), ...p });
  if (LAST_INBOUND.length > 25) LAST_INBOUND.shift();
}
/* -------------------------------------------------------------------------- */
/* Routes                                                                     */
/* -------------------------------------------------------------------------- */

app.get("/", (_req, res) => {
  res.status(200).json({
    ok: true,
    name: "ghl-bluebubbles-bridge",
    relay: BB_BASE,
    oauthConfigured: !!(CLIENT_ID && CLIENT_SECRET),
    inboundForward: !!GHL_INBOUND_URL,
    parkingNumber: ENV_PARKING_NUMBER || null,
    routes: [
      "/health",
      "/provider/deliver (GET or POST)",
      "/send (POST)",
      "/bb (POST passthrough)",
      "/webhook (POST from BlueBubbles)",
      "/debug/contact",
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
    const pong = await axios.get(
      `${BB_BASE}/api/v1/ping?guid=${encodeURIComponent(BB_GUID)}`,
      { timeout: 8000 }
    );
    res.status(200).json({ ok: true, relay: BB_BASE, ping: pong.data ?? null });
  } catch (e) {
    res.status(503).json({
      ok: false,
      relay: BB_BASE,
      error: e?.response?.data ?? e?.message ?? "Ping failed",
    });
  }
});
// 1) What the bridge *thinks* it just pushed
app.get("/debug/last-inbound", (_req, res) => {
  res.json({ ok: true, items: LAST_INBOUND });
});

// 2) Find the contact in GHL by phone & show contactId + basic profile
app.get("/debug/ghl/contact-by-phone", async (req, res) => {
  try {
    const raw = (req.query.phone || "").trim();
    if (!raw) return res.status(400).json({ ok: false, error: "phone required (e.g. +19082655248)" });

    const any = getAnyLocation();
    if (!any) return res.status(400).json({ ok: false, error: "no-oauth" });
    const { locationId } = any;
    const e164 = ensureE164(raw);

    const contactId = await findContactIdByPhone(locationId, e164);
    if (!contactId) return res.json({ ok: true, found: false });

    const data = await withLcCall(locationId, (token) =>
      axios.get(`${LC_API}/contacts/${contactId}`, { headers: lcHeaders(token), timeout: 15000 })
        .then(r => r.data)
    );

    res.json({ ok: true, found: true, locationId, contactId, contact: data });
  } catch (e) {
    res.status(500).json({ ok: false, error: e?.response?.data || e.message });
  }
});

// 3) Pull the conversation for that contact and list recent messages
app.get("/debug/ghl/thread-by-contact", async (req, res) => {
  try {
    const raw = (req.query.phone || "").trim();
    if (!raw) return res.status(400).json({ ok: false, error: "phone required (e.g. +19082655248)" });

    const any = getAnyLocation();
    if (!any) return res.status(400).json({ ok: false, error: "no-oauth" });
    const { locationId } = any;
    const e164 = ensureE164(raw);

    const contactId = await findContactIdByPhone(locationId, e164);
    if (!contactId) return res.json({ ok: true, found: false, note: "contact not found" });

    // Conversations search (LeadConnector). Returns the thread + last messages chunk.
    const resp = await withLcCall(locationId, (token) =>
      axios.get(
        `${LC_API}/conversations/search?locationId=${encodeURIComponent(locationId)}&contactId=${encodeURIComponent(contactId)}&limit=25`,
        { headers: lcHeaders(token), timeout: 20000 }
      )
    );

    const payload = resp?.data || {};
    res.json({
      ok: true,
      locationId,
      contactId,
      raw: payload,           // you’ll see conversationId(s) here
    });
  } catch (e) {
    res.status(500).json({ ok: false, error: e?.response?.data || e.message });
  }
});

// Debug: contact lookup
app.get("/debug/contact", async (req, res) => {
  try {
    const any = getAnyLocation();
    if (!any) return res.status(200).json({ ok: false, error: "no-oauth" });

    const { locationId } = any;
    const raw = req.query.phone || "";
    const normalized = (raw || "").replace(/\D/g, "").length === 10
      ? `+1${(raw || "").replace(/\D/g, "")}`
      : raw;

    const id = await findContactIdByPhone(locationId, normalized);
    res.json({ ok: true, locationId, searched: normalized, foundContactId: id });
  } catch (e) {
    res.status(500).json({ ok: false, error: e?.message });
  }
});

// Conversation Provider delivery URL (GET/POST) + typo guard
app.all("/provider/deliver", handleProviderSend);
app.all("/provider/deliverl", handleProviderSend); // in case it was saved with an extra "l"
app.post("/send", handleProviderSend);

// Passthrough to BlueBubbles REST
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
    res.status(status).json({
      ok: false,
      relay: BB_BASE,
      error: err?.response?.data ?? err?.message ?? "Unknown error",
    });
  }
});

/* ---------------------------- Inbound Webhook ----------------------------- */
// Accepts BlueBubbles webhooks and also simple Postman payloads
app.post("/webhook", async (req, res) => {
  try {
    // Let trigger pings (Bearer/?key) through harmlessly
    if (verifyBearer(req)) return res.status(200).json({ ok: true });

    const src  = req.body || {};
    const data = src.data || {};

    // Extract message text
    const messageText =
      data.text ??
      data.message?.text ??
      src.text ??
      src.message ??
      null;

    // Extract "who sent it" (the contact)
    const fromRaw =
      data.handle?.address ??
      data.message?.handle?.address ??
      data.sender ??
      src.from ??
      data.handle ??
      null;

    // Chat GUID if present
    const chatGuid =
      data.chats?.[0]?.guid ??
      data.chat?.guid ??
      src.chatGuid ??
      null;

    const isFromMe = Boolean(
      data.isFromMe ?? data.message?.isFromMe ?? src.isFromMe ?? false
    );

    // Drop our own outbound echoes (we'll mirror outbound separately if desired)
    if (isFromMe) {
      console.log("[inbound] own-message ignored:", { chatGuid, text: messageText });
      return res.status(200).json({ ok: true, ignored: "from-me" });
    }

    if (!messageText || !fromRaw) {
      console.log("[inbound] missing messageText/fromNumber:", {
        messageText, fromNumberRaw: fromRaw
      });
      return res.status(200).json({ ok: true });
    }

    const any = getAnyLocation();
    if (!any) {
      console.error("[inbound] no OAuth tokens saved (install app & run /oauth/start).");
      return res.status(200).json({ ok: true, note: "no-oauth" });
    }
    const { locationId } = any;

    // Normalize numbers
    let contactE164 = null;
    try { contactE164 = ensureE164(fromRaw); } catch { contactE164 = null; }
    if (!contactE164 && chatGuid) {
      // Fallback extract from chatGuid
      const tail = String(chatGuid).split(";").pop();
      try { contactE164 = ensureE164(tail); } catch { /* ignore */ }
    }
    if (!contactE164) {
      console.log("[inbound] could not normalize contact number:", fromRaw, chatGuid);
      return res.status(200).json({ ok: true, note: "bad-contact-number" });
    }

    // PARKING_NUMBER must be a Location phone (Twilio DID)
    let locationNumber = null;
    try { locationNumber = ensureE164(ENV_PARKING_NUMBER); } catch { locationNumber = null; }
    if (!locationNumber) {
      console.error("[inbound] PARKING_NUMBER/BUSINESS_NUMBER missing/invalid. Set env to Location phone (e.g., +1786…)");
      return res.status(200).json({ ok: true, note: "no-identity-number" });
    }

    // de-dupe guard
    const key = dedupeKey({ text: messageText, from: contactE164, chatGuid });
    if (recentInboundKeys.has(key)) {
      console.log("[inbound] duplicate event suppressed.");
      return res.status(200).json({ ok: true, ignored: "duplicate" });
    }
    rememberInbound(key);

    // only mirror if contact exists
    const contactId = await findContactIdByPhone(locationId, contactE164);
    if (!contactId) {
      console.log("[inbound] contact not found in CRM; dropping (by design).", { locationId, from: contactE164 });
      return res.status(200).json({ ok: true, dropped: "no-contact" });
    }

    // token
    const accessToken = await getValidAccessToken(locationId);
    if (!accessToken) {
      console.error("[inbound] unable to obtain access token for location", locationId);
      return res.status(200).json({ ok: true, note: "no-access-token" });
    }

    // GHL rules:
    //   - direction: "inbound" (from contact to us)
    //   - toNumber   = contact phone
    //   - fromNumber = a LOCATION phone (Twilio DID on that sub-account)
    const direction = "inbound";
    const toNumber  = contactE164;    // must match contact record
    const fromNumber = locationNumber; // must be owned by Location

    console.log("[inbound] map", {
      isFromMe, contactE164, locationNumber, direction, fromNumber, toNumber, chatGuid
    });

    const pushed = await pushInboundMessage({
      locationId,
      accessToken,
      contactId,
      text: messageText,
      fromNumber,
      toNumber,
      direction,
    });

    if (!pushed) {
      console.error("[inbound] push returned null (check scopes and /conversations/messages access).");
      return res.status(200).json({ ok: true, note: "push-failed" });
    }

    console.log("[inbound] delivered → conversations:", {
      locationId,
      contactId,
      chatGuid,
      preview: messageText.slice(0, 32),
    });
rememberPush({ locationId, contactId, chatGuid, text: messageText, fromNumber, toNumber, direction });
    // optional side-forward (diagnostic)
    if (GHL_INBOUND_URL) {
      try {
        await axios.post(
          GHL_INBOUND_URL,
          {
            event: "incoming-imessage",
            messageText,
            from: contactE164,
            to: locationNumber,
            chatGuid,
            receivedAt: new Date().toISOString(),
          },
          { headers: { "Content-Type": "application/json" }, timeout: 10000 }
        );
      } catch (e) {
        console.error("[inbound] forward to GHL_INBOUND_URL failed:", e?.message);
      }
    }

    return res.status(200).json({ ok: true, pushed });
  } catch (err) {
    console.error("[inbound] /webhook error:", err?.response?.data || err.message);
    return res.status(200).json({ ok: true, error: "ingest-failed" });
  }
});

/* -------------------------------------------------------------------------- */
/* OAuth (LeadConnector)                                                      */
/* -------------------------------------------------------------------------- */

app.get("/oauth/start", (_req, res) => {
  if (!CLIENT_ID || !GHL_REDIRECT_URI) {
    return res.status(400).send("OAuth not configured (missing CLIENT_ID or GHL_REDIRECT_URI).");
  }

  // message scopes + readonly contacts/locations
  const scope = [
    "conversations/message.write",
    "conversations/message.readonly",
    "contacts.readonly",
    "locations.readonly",
  ].join(" ");

  const params = new URLSearchParams({
    client_id: CLIENT_ID,
    response_type: "code",
    redirect_uri: GHL_REDIRECT_URI,
    scope,
  });

  res.redirect(`${OAUTH_AUTHORIZE_BASE}/authorize?${params.toString()}`);
});

// Accept GET or POST; tolerate trailing slash
app.all("/oauth/callback", async (req, res) => {
  try {
    const code  = (req.query.code || req.body?.code || "").toString();
    const error = (req.query.error || req.body?.error || "").toString();

    if (error) return res.status(400).send("OAuth denied. Please try again.");
    if (!code)  return res.status(400).send("Missing authorization code.");

    const body = qs.stringify({
      client_id:     CLIENT_ID,
      client_secret: CLIENT_SECRET,
      grant_type:    "authorization_code",
      code,
      redirect_uri:  GHL_REDIRECT_URI,
    });

    const tokenRes = await axios.post(`${OAUTH_TOKEN_BASE}/token`, body, {
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      timeout: 20000,
    });

    const tokens = tokenRes.data || {};
    tokens._created_at_ms = Date.now();

    const locationId = tokens.locationId || tokens.location_id || tokens.location || "default";
    tokenStore.set(locationId, tokens);
    await saveTokenStore();

    console.log("[oauth] tokens saved for location:", locationId, {
      haveAccess:  !!tokens.access_token,
      haveRefresh: !!tokens.refresh_token,
      expiresIn: tokens.expires_in,
    });

    return res
      .status(200)
      .send(`<!doctype html><html><body style="font-family:system-ui;background:#0b0b0c;color:#e5e7eb;display:flex;align-items:center;justify-content:center;height:100vh"><div style="background:#111827;border:1px solid #1f2937;border-radius:14px;padding:24px;max-width:560px;text-align:center;box-shadow:0 10px 30px rgba(0,0,0,.3)"><h1>✅ Eden iMessage connected</h1><p>You can close this window and return to HighLevel.</p><div style="margin-top:10px;background:#16a34a;color:#fff;padding:8px 12px;border-radius:8px">Location: ${locationId}</div></div><script>setTimeout(()=>{window.close?.();},1500)</script></body></html>`);
  } catch (e) {
    console.error("[oauth] callback error:", e?.response?.status, e?.response?.data || e.message);
    res.status(500).send("OAuth error. Check server logs for details.");
  }
});

app.get("/oauth/debug", (_req, res) => {
  res.json({
    ok: true,
    locationsWithTokens: Array.from(tokenStore.keys()),
    tokensFile: TOKENS_FILE,
    parkingNumber: ENV_PARKING_NUMBER || null,
  });
});

/* -------------------------------------------------------------------------- */
/* Minimal embedded UI                                                        */
/* -------------------------------------------------------------------------- */
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

/* -------------------------------------------------------------------------- */
/* Start                                                                      */
/* -------------------------------------------------------------------------- */
// Debug: read back the last messages for a contact from LC
app.get("/debug/messages", async (req, res) => {
  try {
    const phoneRaw = (req.query.phone || "").trim();
    if (!phoneRaw) return res.status(400).json({ ok: false, error: "phone query param required" });

    const any = getAnyLocation();
    if (!any) return res.status(200).json({ ok: false, error: "no-oauth" });
    const { locationId } = any;

    // normalize to E.164 and find contactId the same way inbound does
    const phone =
      phoneRaw.startsWith("+") ? phoneRaw : toE164US(phoneRaw);
    if (!phone) return res.status(400).json({ ok: false, error: "invalid phone" });

    const contactId = await findContactIdByPhone(locationId, phone);
    if (!contactId) return res.status(404).json({ ok: false, error: "contact not found" });

    const data = await withLcCall(locationId, (access) =>
      axios.get(
        `${LC_API}/conversations/messages?locationId=${encodeURIComponent(locationId)}&contactId=${encodeURIComponent(contactId)}&limit=25`,
        { headers: lcHeaders(access), timeout: 15000 }
      )
    );

    res.json({
      ok: true,
      locationId,
      contactId,
      phone,
      raw: data?.data || data?.items || data,
    });
  } catch (e) {
    res.status(500).json({ ok: false, error: e?.response?.data || e.message });
  }
});


await loadTokenStore();

app.listen(PORT, () => {
  console.log(`[bridge] listening on :${PORT}`);
  console.log(`[bridge] BB_BASE = ${BB_BASE}`);
  console.log(`[bridge] Tokens file = ${TOKENS_FILE}`);
  console.log(`[bridge] PARKING_NUMBER = ${ENV_PARKING_NUMBER || "(not set!)"}`);
  if (GHL_INBOUND_URL) console.log(`[bridge] Forwarding inbound to ${GHL_INBOUND_URL}`);
  if (CLIENT_ID && CLIENT_SECRET) console.log("[bridge] OAuth is configured.");
  if (GHL_SHARED_SECRET) console.log("[bridge] Shared secret checks enabled.");
});

// persist tokens on shutdown
process.on("SIGTERM", async () => { try { await saveTokenStore(); } finally { process.exit(0); } });
process.on("SIGINT",  async () => { try { await saveTokenStore(); } finally { process.exit(0); } });
