// index.js
// Eden iMessage Bridge — GHL (HighLevel) ↔ BlueBubbles
// ✅ Stable build 1.3 — clean inbound/outbound logic, fixed GHL compliance (Feb 2025+)
// Outbound: Conversation Provider → BlueBubbles
// Inbound: BlueBubbles → push into GHL Conversations (if contact exists)

import express from "express";
import cors from "cors";
import helmet from "helmet";
import morgan from "morgan";
import axios from "axios";
import crypto from "crypto";
import qs from "querystring";
import fs from "fs/promises";
import bodyParser from "body-parser";

const app = express();

/* ------------------------------- Middleware ------------------------------- */
app.use(
  express.json({
    limit: "1mb",
    verify: (req, _res, buf) => {
      try { req.rawBody = buf.toString("utf8"); } catch { req.rawBody = ""; }
    },
  })
);
app.use(express.urlencoded({ extended: true }));
app.use(bodyParser.text({ type: ["text/*"] }));

app.use(
  helmet({
    contentSecurityPolicy: {
      useDefaults: true,
      directives: {
        "frame-ancestors": ["'self'", "*.gohighlevel.com", "*.leadconnectorhq.com", "*.msgsndr.com"],
        "script-src": ["'self'", "'unsafe-inline'"],
      },
    },
    frameguard: { action: "sameorigin" },
  })
);

app.use(cors({ origin: [/\.gohighlevel\.com$/, /\.leadconnectorhq\.com$/, /\.msgsndr\.com$/, /localhost/], credentials: true }));
app.use(morgan("tiny"));

/* ---------------------------------- Config --------------------------------- */
const PORT = Number(process.env.PORT || 8080);
const BB_BASE = (process.env.BB_BASE || "").trim();
const BB_GUID = (process.env.BB_GUID || "").trim();
const GHL_SHARED_SECRET = (process.env.GHL_SHARED_SECRET || "").trim();
const GHL_INBOUND_URL = (process.env.GHL_INBOUND_URL || "").trim();
const CLIENT_ID = (process.env.CLIENT_ID || "").trim();
const CLIENT_SECRET = (process.env.CLIENT_SECRET || "").trim();
const GHL_REDIRECT_URI = (process.env.GHL_REDIRECT_URI || "").trim() || "https://ieden-bluebubbles-bridge-1.onrender.com/oauth/callback";
const ENV_PARKING_NUMBER = (process.env.PARKING_NUMBER || process.env.BUSINESS_NUMBER || "").trim();
const TOKENS_FILE = (process.env.TOKENS_FILE || "./tokens.json").trim();

/* ----------------------------- Helper Utilities ---------------------------- */
const newGuid = (prefix = "tmp") => `${prefix}-${crypto.randomBytes(5).toString("hex")}`;

const toE164US = (n) => {
  if (!n) return null;
  const d = String(n).replace(/\D/g, "");
  if (d.startsWith("1") && d.length === 11) return `+${d}`;
  if (d.length === 10) return `+1${d}`;
  if (String(n).startsWith("+")) return String(n);
  return null;
};
const ensureE164 = (n) => {
  const e = toE164US(n);
  if (!e) throw new Error("Invalid US phone. Use E.164 like +13051234567");
  return e;
};
const chatGuidForPhone = (e164) => `iMessage;-;${e164}`;

const bbPost = async (path, body) => {
  const url = `${BB_BASE}${path}?guid=${encodeURIComponent(BB_GUID)}`;
  const { data } = await axios.post(url, body, { headers: { "Content-Type": "application/json" }, timeout: 15000 });
  return data;
};

/* ----------------------------- OAuth Utilities ----------------------------- */
const LC_API = "https://services.leadconnectorhq.com";
const LC_VERSION = "2021-07-28";
const tokenStore = new Map();
const lcHeaders = (access) => ({
  "Authorization": `Bearer ${access}`,
  "Content-Type": "application/json",
  "Version": LC_VERSION,
});
async function saveTokens() {
  const arr = Array.from(tokenStore.entries());
  await fs.writeFile(TOKENS_FILE, JSON.stringify(arr, null, 2));
}
async function loadTokens() {
  try {
    const arr = JSON.parse(await fs.readFile(TOKENS_FILE, "utf8"));
    for (const [k, v] of arr) tokenStore.set(k, v);
  } catch {}
}

/* ----------------------------- Contact Lookup ------------------------------ */
async function findContactIdByPhone(locationId, e164) {
  const digits = e164.replace(/\D/g, "");
  const last10 = digits.slice(-10);
  const patterns = [e164, digits, last10, `(${last10.slice(0,3)}) ${last10.slice(3,6)}-${last10.slice(6)}`];
  for (const q of patterns) {
    try {
      const r = await axios.get(`${LC_API}/contacts/?locationId=${encodeURIComponent(locationId)}&query=${encodeURIComponent(q)}`,
        { headers: lcHeaders(tokenStore.get(locationId)?.access_token || ""), timeout: 15000 });
      const list = r?.data?.contacts || [];
      for (const c of list) {
        const phones = new Set();
        if (c.phone) phones.add(c.phone);
        if (Array.isArray(c.phoneNumbers)) for (const p of c.phoneNumbers) phones.add(p.phone || p.number || p);
        if ([...phones].map(toE164US).includes(e164)) return c.id || null;
      }
    } catch {}
  }
  return null;
}

/* ------------------------- Push Inbound → GHL ------------------------- */
async function pushInboundMessage({ locationId, contactId, accessToken, text, direction, identityNumber, contactE164 }) {
  const body = {
    locationId,
    contactId,
    type: "SMS",
    direction,
    message: text,
    fromNumber: identityNumber,
    toNumber: contactE164,
    provider: "iMessage (EDEN)",
  };
  try {
    const r = await axios.post(`${LC_API}/conversations/messages`, body, { headers: lcHeaders(accessToken), timeout: 15000 });
    return r.data;
  } catch (e) {
    console.error("[inbound->GHL] push failed:", e?.response?.data || e.message);
    return null;
  }
}

/* --------------------------- Provider Deliver --------------------------- */
app.all("/provider/deliver", async (req, res) => {
  try {
    const { to, message } = req.body || {};
    if (!to || !message) return res.status(400).json({ ok: false, error: "Missing 'to' or 'message'" });
    const e164 = ensureE164(to);
    const payload = { chatGuid: chatGuidForPhone(e164), message: message, tempGuid: newGuid(), method: "apple-script" };
    const sent = await bbPost("/api/v1/message/text", payload);
    res.json({ ok: true, sent });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

/* --------------------------- Inbound Webhook --------------------------- */
app.post("/webhook", async (req, res) => {
  try {
    const src = req.body || {};
    const data = src.data || {};
    const text = data.text || src.text || null;
    const fromRaw = data.handle?.address || src.from || null;
    const isFromMe = Boolean(data.isFromMe ?? src.isFromMe ?? false);
    if (isFromMe || !text || !fromRaw) return res.json({ ok: true });

    const any = tokenStore.entries().next().value;
    if (!any) return res.json({ ok: false, note: "no-oauth" });
    const [locationId, { access_token }] = any;

    const contactE164 = ensureE164(fromRaw);
    const identityNumber = ensureE164(ENV_PARKING_NUMBER);

    const contactId = await findContactIdByPhone(locationId, contactE164);
    if (!contactId) return res.json({ ok: true, dropped: "no-contact" });

    // ✅ GHL requires fromNumber to always be location-owned number
    const direction = "inbound";
    const pushed = await pushInboundMessage({
      locationId,
      contactId,
      accessToken: access_token,
      text,
      direction,
      identityNumber,
      contactE164,
    });

    if (!pushed) return res.json({ ok: false, note: "push-failed" });
    console.log(`[inbound] delivered inbound → contact ${contactE164} (${locationId})`);
    res.json({ ok: true, pushed });
  } catch (e) {
    console.error("[inbound] error:", e.message);
    res.json({ ok: false, error: e.message });
  }
});

/* --------------------------- Misc Endpoints --------------------------- */
app.get("/", (_req, res) => res.json({ ok: true, bridge: "eden-imessage", parking: ENV_PARKING_NUMBER || null }));
app.get("/health", async (_req, res) => {
  try {
    const pong = await axios.get(`${BB_BASE}/api/v1/ping?guid=${encodeURIComponent(BB_GUID)}`);
    res.json({ ok: true, relay: pong.data });
  } catch (e) {
    res.json({ ok: false, error: e.message });
  }
});

/* ------------------------------ Start Server ------------------------------ */
await loadTokens();
app.listen(PORT, () => {
  console.log(`[bridge] listening on :${PORT}`);
  console.log(`[bridge] BB_BASE = ${BB_BASE}`);
  console.log(`[bridge] PARKING_NUMBER = ${ENV_PARKING_NUMBER}`);
  if (GHL_INBOUND_URL) console.log(`[bridge] Forwarding inbound to ${GHL_INBOUND_URL}`);
});
