// index.js - VERSION 3.7.0 (2025-11-06)
// ============================================================================
// PROJECT: Eden Bridge - Multi-Server BlueBubbles ↔ GHL
// ============================================================================
// CHANGELOG v3.7.0:
// - ADDED: bb3 server for Tiffany's dedicated Mac Mini
// - CHANGED: bb2 now only handles Mario (removed Tiffany from bb2)
// - CHANGED: Tiffany moved from bb2 to dedicated bb3 server
// - FIXED: Corrected passwords - removed exclamation mark (now "EdenBridge2025")
// - VERIFIED: Full 3-server architecture (bb1=Eden, bb2=Mario, bb3=Tiffany)
// - Each user now has dedicated Mac Mini and iPhone for 24/7 operation
// ============================================================================

import express from "express";
import cors from "cors";
import helmet from "helmet";
import morgan from "morgan";
import axios from "axios";
import crypto from "crypto";
import bodyParser from "body-parser";
import qs from "querystring";
import fs from "fs/promises";
import FormData from "form-data";

const app = express();

/* -------------------------------------------------------------------------- */
/* Middleware                                                                 */
/* -------------------------------------------------------------------------- */
app.use(
  express.json({
    limit: "10mb",
    verify: (req, _res, buf) => {
      try { req.rawBody = buf.toString("utf8"); } catch { req.rawBody = ""; }
    },
  })
);
app.use(express.urlencoded({ extended: true, limit: "10mb" }));
app.use(bodyParser.text({ type: ["text/*"] }));

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
          "marketplace.gohighlevel.com",
        ],
        "script-src": ["'self'", "'unsafe-inline'"],
      },
    },
    frameguard: false,
    crossOriginEmbedderPolicy: false,
    crossOriginOpenerPolicy: false,
  })
);

app.use(
  cors({
    origin: [/\.gohighlevel\.com$/, /\.leadconnectorhq\.com$/, /\.msgsndr\.com$/, /localhost/],
    credentials: true,
  })
);

app.use(morgan("tiny"));

/* -------------------------------------------------------------------------- */
/* Config - Environment Variables for Parking Numbers                         */
/* -------------------------------------------------------------------------- */
const PARKING_NUMBER_EDEN = (process.env.PARKING_NUMBER_EDEN || "+17867334163").trim();
const PARKING_NUMBER_MARIO = (process.env.PARKING_NUMBER_MARIO || "+17868828328").trim();
const PARKING_NUMBER_TIFFANY = (process.env.PARKING_NUMBER_TIFFANY || "+19547587444").trim();

// GHL User ID mapping (get these from GHL Settings -> My Staff)
const GHL_USER_ID_EDEN = "11umP2K61R5cuEoadD9x";
const GHL_USER_ID_MARIO = "7XskZuGiwXLneiUx10ne";
const GHL_USER_ID_TIFFANY = "BQAAlsqc9xdibpaxZP3q";

/* -------------------------------------------------------------------------- */
/* Config - BlueBubbles Servers with Parking Numbers from Env Vars            */
/* -------------------------------------------------------------------------- */
// Define your BlueBubbles servers here
// NEW v3.7.0: Each user now has dedicated server (bb1=Eden, bb2=Mario, bb3=Tiffany)
const BLUEBUBBLES_SERVERS = [
  {
    id: "bb1",
    name: "Server 1 (Original Mac - Eden)",
    baseUrl: process.env.BB_BASE || "https://relay.asapcashhomebuyers.com",
    password: process.env.BB_GUID || "REPLACE_WITH_SERVER1_PASSWORD",
    parkingNumbers: [
      { number: PARKING_NUMBER_EDEN, userId: GHL_USER_ID_EDEN, user: "Eden" },
    ],
    // iMessage phone numbers handled by this server
    phoneNumbers: [
      { number: "+13058337256", parkingNumber: PARKING_NUMBER_EDEN, userId: GHL_USER_ID_EDEN, user: "Eden" },
    ],
  },
  {
    id: "bb2",
    name: "Server 2 (Mac Mini - Mario)",
    baseUrl: "https://bb2.asapcashhomebuyers.com",
    password: process.env.BB2_GUID || "EdenBridge2025",
    parkingNumbers: [
      { number: PARKING_NUMBER_MARIO, userId: GHL_USER_ID_MARIO, user: "Mario" },
    ],
    // iMessage phone numbers handled by this server
    phoneNumbers: [
      { number: "+13059273268", parkingNumber: PARKING_NUMBER_MARIO, userId: GHL_USER_ID_MARIO, user: "Mario" },
    ],
  },
  {
    id: "bb3",
    name: "Server 3 (Mac Mini - Tiffany)",
    baseUrl: "https://bb3.asapcashhomebuyers.com",
    password: process.env.BB3_GUID || "EdenBridge2025",
    parkingNumbers: [
      { number: PARKING_NUMBER_TIFFANY, userId: GHL_USER_ID_TIFFANY, user: "Tiffany" },
    ],
    // iMessage phone numbers handled by this server
    phoneNumbers: [
      { number: "+19544450020", parkingNumber: PARKING_NUMBER_TIFFANY, userId: GHL_USER_ID_TIFFANY, user: "Tiffany" },
    ],
  },
];

// Build GHL parking numbers to iMessage numbers map dynamically
// This handles the routing from GHL parking number → iMessage number
const GHL_TO_IMESSAGE_MAP = {};
for (const server of BLUEBUBBLES_SERVERS) {
  for (const phoneConfig of server.phoneNumbers) {
    GHL_TO_IMESSAGE_MAP[phoneConfig.parkingNumber] = phoneConfig.number;
  }
}

// Build reverse map: iMessage number to parking number (for inbound messages)
const IMESSAGE_TO_GHL_MAP = {};
for (const server of BLUEBUBBLES_SERVERS) {
  for (const phoneConfig of server.phoneNumbers) {
    IMESSAGE_TO_GHL_MAP[phoneConfig.number] = phoneConfig.parkingNumber;
  }
}

// Build parking number to server map for quick lookup
const PARKING_TO_SERVER_MAP = {};
for (const server of BLUEBUBBLES_SERVERS) {
  for (const parkingConfig of server.parkingNumbers) {
    PARKING_TO_SERVER_MAP[parkingConfig.number] = server;
  }
}

// Build GHL userId to server map for quick lookup
const USERID_TO_SERVER_MAP = {};
for (const server of BLUEBUBBLES_SERVERS) {
  for (const parkingConfig of server.parkingNumbers) {
    USERID_TO_SERVER_MAP[parkingConfig.userId] = server;
  }
}

/* -------------------------------------------------------------------------- */
/* Config - Environment Variables                                             */
/* -------------------------------------------------------------------------- */
const PORT = Number(process.env.PORT || 8080);

const GHL_INBOUND_URL = (process.env.GHL_INBOUND_URL || "").trim();

const CLIENT_ID = (process.env.CLIENT_ID || "").trim();
const CLIENT_SECRET = (process.env.CLIENT_SECRET || "").trim();
const GHL_REDIRECT_URI = (
  process.env.GHL_REDIRECT_URI ||
  "https://ieden-bluebubbles-bridge-1.onrender.com/oauth/callback"
).trim();

const OAUTH_AUTHORIZE_BASE = "https://marketplace.gohighlevel.com/oauth";
const OAUTH_TOKEN_BASE     = "https://services.leadconnectorhq.com/oauth";

const GHL_SHARED_SECRET = (process.env.GHL_SHARED_SECRET || "").trim();

const TOKENS_FILE = (process.env.TOKENS_FILE || "./tokens.json").trim();
const TOKENS_ENV_KEY = "GHL_TOKENS_BASE64";

const CONVERSATION_PROVIDER_ID = (process.env.CONVERSATION_PROVIDER_ID || "68d94718bcd02bcf453ccf46").trim();

const TIMEZONE = (process.env.TIMEZONE || "America/New_York").trim();

/* -------------------------------------------------------------------------- */
/* BlueBubbles Server Routing                                                 */
/* -------------------------------------------------------------------------- */

// Find server by GHL userId
function findServerByUserId(userId) {
  const server = USERID_TO_SERVER_MAP[userId];
  
  if (server) {
    console.log(`[routing] GHL userId ${userId} → ${server.name}`);
    return server;
  }
  
  console.log(`[routing] No server found for userId ${userId}, using default`);
  return BLUEBUBBLES_SERVERS[0];
}

// Find server by parking number (from GHL 'from' field)
function findServerByParkingNumber(parkingE164) {
  const normalized = toE164US(parkingE164);
  const server = PARKING_TO_SERVER_MAP[normalized];
  
  if (server) {
    console.log(`[routing] Parking ${normalized} → ${server.name}`);
    return server;
  }
  
  console.log(`[routing] No server found for parking ${normalized}, using default`);
  return BLUEBUBBLES_SERVERS[0];
}

// Resolve GHL parking number to actual iMessage number
function resolveToIMessageNumber(phoneE164) {
  // First normalize the phone number (remove any formatting)
  const normalized = toE164US(phoneE164);
  
  // Check if this is a GHL parking number that maps to an iMessage number
  if (GHL_TO_IMESSAGE_MAP[normalized]) {
    const iMessageNumber = GHL_TO_IMESSAGE_MAP[normalized];
    console.log(`[routing] GHL parking ${normalized} mapped to iMessage ${iMessageNumber}`);
    return iMessageNumber;
  }
  
  // Otherwise return the original number
  return normalized;
}

// Find which BlueBubbles server handles a given phone number
function findServerForPhone(phoneE164) {
  // First resolve any GHL parking numbers to iMessage numbers
  const iMessageNumber = resolveToIMessageNumber(phoneE164);
  
  for (const server of BLUEBUBBLES_SERVERS) {
    for (const phoneConfig of server.phoneNumbers) {
      if (phoneConfig.number === iMessageNumber) {
        console.log(`[routing] ${phoneE164} → ${iMessageNumber} → ${server.name}`);
        return server;
      }
    }
  }
  
  // Default to first server if not found
  console.log(`[routing] No match found for ${phoneE164}, using default server`);
  return BLUEBUBBLES_SERVERS[0];
}

// Get parking number for a specific iMessage number (for inbound messages)
function getParkingNumberForIMessage(iMessageE164) {
  const parkingNumber = IMESSAGE_TO_GHL_MAP[iMessageE164];
  if (parkingNumber) {
    console.log(`[routing] iMessage ${iMessageE164} uses parking number ${parkingNumber}`);
    return parkingNumber;
  }
  
  // Fallback to first server's parking number
  console.log(`[routing] No parking number mapped for ${iMessageE164}, using default`);
  return BLUEBUBBLES_SERVERS[0].parkingNumbers[0].number;
}

// Get all active phone numbers from all servers
function getAllPhoneNumbers() {
  const allNumbers = [];
  for (const server of BLUEBUBBLES_SERVERS) {
    for (const phoneConfig of server.phoneNumbers) {
      allNumbers.push(phoneConfig.number);
    }
  }
  return allNumbers;
}

// Get all parking numbers
function getAllParkingNumbers() {
  const allParking = [];
  for (const server of BLUEBUBBLES_SERVERS) {
    for (const parkingConfig of server.parkingNumbers) {
      allParking.push(parkingConfig.number);
    }
  }
  return allParking;
}

/* -------------------------------------------------------------------------- */
/* Get iMessage Account for User (Private API Support)                       */
/* -------------------------------------------------------------------------- */

// Get the iMessage account number to send from based on userId
function getIMessageAccountForUser(userId, server) {
  // Find which phone configuration matches this userId
  for (const phoneConfig of server.phoneNumbers) {
    if (phoneConfig.userId === userId) {
      console.log(`[private-api] userId ${userId} → send from ${phoneConfig.number} (${phoneConfig.user})`);
      return phoneConfig.number;
    }
  }
  
  // Fallback to first phone number on this server
  console.log(`[private-api] userId ${userId} not found, using default ${server.phoneNumbers[0].number}`);
  return server.phoneNumbers[0].number;
}

/* -------------------------------------------------------------------------- */
/* State & Helper Functions                                                   */
/* -------------------------------------------------------------------------- */

const tokenStore = new Map();

const recentOutboundMessages = new Map();
const recentInboundKeys = new Map();
const recentOutboundAttachmentChats = new Map();
const DEDUPE_TTL_MS = 15_000;
const OUTBOUND_TTL_MS = 30_000;
const ATTACHMENT_GRACE_MS = 10_000;

const dedupeKey = ({ text, from, chatGuid }) =>
  `${chatGuid || ""}|${from || ""}|${(text || "").slice(0, 128)}`;

const rememberOutbound = (text, chatGuid, hasAttachments = false) => {
  const key = `${chatGuid}|${(text || "").slice(0, 128)}`;
  const expiry = Date.now() + OUTBOUND_TTL_MS;
  recentOutboundMessages.set(key, expiry);
  
  const textOnlyKey = `text-only|${(text || "").slice(0, 128)}`;
  recentOutboundMessages.set(textOnlyKey, expiry);
  
  if (hasAttachments) {
    const attExpiry = Date.now() + ATTACHMENT_GRACE_MS;
    recentOutboundAttachmentChats.set(chatGuid, attExpiry);
    console.log("[outbound-tracker] remembered with attachments:", { chatGuid, textPreview: text?.slice(0, 32) });
  } else {
    console.log("[outbound-tracker] remembered:", { chatGuid, textPreview: text?.slice(0, 32) });
  }
  
  if (recentOutboundMessages.size > 100) {
    const now = Date.now();
    for (const [k, exp] of recentOutboundMessages.entries()) {
      if (exp < now) recentOutboundMessages.delete(k);
    }
  }
  if (recentOutboundAttachmentChats.size > 50) {
    const now = Date.now();
    for (const [k, exp] of recentOutboundAttachmentChats.entries()) {
      if (exp < now) recentOutboundAttachmentChats.delete(k);
    }
  }
};

const isOurOutbound = (text, chatGuid, hasAttachments) => {
  const key = `${chatGuid}|${(text || "").slice(0, 128)}`;
  const expiry = recentOutboundMessages.get(key);
  if (expiry && expiry >= Date.now()) {
    console.log("[outbound-tracker] MATCH FOUND - ignoring echo (text with chatGuid)");
    return true;
  }
  if (expiry && expiry < Date.now()) {
    recentOutboundMessages.delete(key);
  }
  
  const textOnlyKey = `text-only|${(text || "").slice(0, 128)}`;
  const textOnlyExpiry = recentOutboundMessages.get(textOnlyKey);
  if (textOnlyExpiry && textOnlyExpiry >= Date.now()) {
    console.log("[outbound-tracker] MATCH FOUND - ignoring echo (text only, no chatGuid)");
    return true;
  }
  if (textOnlyExpiry && textOnlyExpiry < Date.now()) {
    recentOutboundMessages.delete(textOnlyKey);
  }
  
  if (hasAttachments && (!text || !text.trim())) {
    const attExpiry = recentOutboundAttachmentChats.get(chatGuid);
    if (attExpiry && attExpiry >= Date.now()) {
      console.log("[outbound-tracker] MATCH FOUND - ignoring echo (attachment within grace period)");
      return true;
    }
    if (attExpiry && attExpiry < Date.now()) {
      recentOutboundAttachmentChats.delete(chatGuid);
    }
  }
  
  return false;
};

const rememberInbound = (k) => {
  const expiry = Date.now() + DEDUPE_TTL_MS;
  recentInboundKeys.set(k, expiry);
  
  if (recentInboundKeys.size > 100) {
    const now = Date.now();
    for (const [key, exp] of recentInboundKeys.entries()) {
      if (exp < now) recentInboundKeys.delete(key);
    }
  }
};

const isRecentInbound = (k) => {
  const expiry = recentInboundKeys.get(k);
  if (!expiry) return false;
  if (expiry < Date.now()) {
    recentInboundKeys.delete(k);
    return false;
  }
  return true;
};

const LAST_INBOUND = [];
function rememberPush(p) {
  LAST_INBOUND.push({ at: new Date().toISOString(), ...p });
  if (LAST_INBOUND.length > 25) LAST_INBOUND.shift();
}

/* -------------------------------------------------------------------------- */
/* Token Persistence                                                          */
/* -------------------------------------------------------------------------- */

async function loadTokenStore() {
  const envTokens = process.env[TOKENS_ENV_KEY];
  if (envTokens) {
    try {
      const decoded = Buffer.from(envTokens, 'base64').toString('utf8');
      const arr = JSON.parse(decoded);
      if (Array.isArray(arr)) {
        tokenStore.clear();
        for (const [loc, tok] of arr) tokenStore.set(loc, tok);
        console.log(`[oauth] loaded ${tokenStore.size} token(s) from env var ${TOKENS_ENV_KEY}`);
        return;
      }
    } catch (e) {
      console.error("[oauth] failed to load from env var:", e.message);
    }
  }

  try {
    const raw = await fs.readFile(TOKENS_FILE, "utf8");
    const arr = JSON.parse(raw);
    if (Array.isArray(arr)) {
      tokenStore.clear();
      for (const [loc, tok] of arr) tokenStore.set(loc, tok);
      console.log(`[oauth] loaded ${tokenStore.size} location token(s) from ${TOKENS_FILE}`);
    }
  } catch {
    console.log("[oauth] no existing tokens file, starting fresh");
  }
}

async function saveTokenStore() {
  const arr = Array.from(tokenStore.entries());
  
  try {
    await fs.writeFile(TOKENS_FILE, JSON.stringify(arr, null, 2), "utf8");
    console.log(`[oauth] tokens persisted to ${TOKENS_FILE}`);
  } catch (e) {
    console.error("[oauth] file persist failed:", e?.message);
  }

  if (arr.length > 0) {
    const base64 = Buffer.from(JSON.stringify(arr)).toString('base64');
    console.log("\n" + "=".repeat(70));
    console.log("📋 COPY THIS TO RENDER ENV VAR TO PERSIST TOKENS:");
    console.log(`Key:   ${TOKENS_ENV_KEY}`);
    console.log(`Value: ${base64}`);
    console.log("=".repeat(70) + "\n");
  }
}

/* -------------------------------------------------------------------------- */
/* Startup Validation                                                         */
/* -------------------------------------------------------------------------- */

// Validate server configurations
for (const server of BLUEBUBBLES_SERVERS) {
  if (!server.password || server.password.includes("REPLACE_WITH")) {
    console.warn(`[WARN] ${server.name} password not set properly!`);
  }
  if (!server.parkingNumbers || server.parkingNumbers.length === 0) {
    console.warn(`[WARN] ${server.name} parking numbers not configured!`);
  }
}

if (!CLIENT_ID || !CLIENT_SECRET) {
  console.log("[bridge] OAuth not configured (CLIENT_ID/CLIENT_SECRET missing).");
}

/* -------------------------------------------------------------------------- */
/* Phone Number Helpers                                                       */
/* -------------------------------------------------------------------------- */

const newTempGuid = (p = "temp") => `${p}-${crypto.randomBytes(6).toString("hex")}`;

const toE164US = (raw) => {
  if (!raw) return null;
  const d = String(raw).replace(/\D/g, "");
  
  if (d.startsWith("1") && d.length === 11) return `+${d}`;
  if (d.length === 10) return `+1${d}`;
  if (String(raw).startsWith("+") && d.length >= 10) return `+${d}`;
  
  return null;
};

const ensureE164 = (phone) => {
  const e = toE164US(phone);
  if (!e) throw new Error(`Invalid US phone: ${phone}. Use E.164 like +13051234567`);
  return e;
};

const chatGuidForPhone = (e164) => `iMessage;-;${e164}`;

/* -------------------------------------------------------------------------- */
/* BlueBubbles API Helpers (Multi-Server)                                     */
/* -------------------------------------------------------------------------- */

const bbPost = async (server, path, body) => {
  const url = `${server.baseUrl}${path}?guid=${encodeURIComponent(server.password)}`;
  
  console.log(`[bbPost][${server.id}] password length: ${server.password?.length || 0}`);
  console.log(`[bbPost][${server.id}] password starts with: ${server.password?.substring(0, 10)}...`);
  console.log(`[bbPost][${server.id}] calling URL: ${server.baseUrl}${path}?guid=[REDACTED]`);
  
  try {
    const { data } = await axios.post(url, body, {
      headers: { "Content-Type": "application/json" },
      timeout: 15000,
    });
    return data;
  } catch (err) {
    console.error(`[bbPost][${server.id}] failed:`, path, err?.response?.status, err.message);
    throw err;
  }
};

const bbGet = async (server, path) => {
  const url = `${server.baseUrl}${path}${path.includes("?") ? "&" : "?"}guid=${encodeURIComponent(server.password)}`;
  try {
    const { data } = await axios.get(url, { timeout: 15000 });
    return data;
  } catch (err) {
    console.error(`[bbGet][${server.id}] failed:`, path, err?.response?.status, err.message);
    throw err;
  }
};

const bbGetBuffer = async (server, path) => {
  const url = `${server.baseUrl}${path}${path.includes("?") ? "&" : "?"}guid=${encodeURIComponent(server.password)}`;
  try {
    const { data } = await axios.get(url, { 
      timeout: 30000,
      responseType: 'arraybuffer'
    });
    return data;
  } catch (err) {
    console.error(`[bbGetBuffer][${server.id}] failed:`, path, err?.response?.status, err.message);
    throw err;
  }
};

const bbUploadAttachment = async (server, chatGuid, buffer, filename) => {
  try {
    const form = new FormData();
    form.append('attachment', buffer, {
      filename: filename || 'attachment',
      contentType: 'application/octet-stream'
    });
    form.append('chatGuid', chatGuid);
    form.append('tempGuid', newTempGuid('att'));
    form.append('name', filename || 'attachment');

    const url = `${server.baseUrl}/api/v1/message/attachment?guid=${encodeURIComponent(server.password)}`;
    
    const { data } = await axios.post(url, form, {
      headers: form.getHeaders(),
      maxBodyLength: Infinity,
      maxContentLength: Infinity,
      timeout: 60000,
    });
    
    return data;
  } catch (err) {
    console.error(`[bbUploadAttachment][${server.id}] failed:`, err?.response?.status, err?.response?.data || err.message);
    throw err;
  }
};

const verifyBearer = (req) => {
  if (!GHL_SHARED_SECRET) return true;
  const auth = req.header("Authorization") || "";
  const m = auth.match(/^Bearer\s+(.+)$/i);
  if (m && m[1].trim() === GHL_SHARED_SECRET) return true;
  if ((req.query.key || "").trim() === GHL_SHARED_SECRET) return true;
  return false;
};

/* -------------------------------------------------------------------------- */
/* GHL LeadConnector API Helpers                                              */
/* -------------------------------------------------------------------------- */

const LC_API = "https://services.leadconnectorhq.com";
const LC_VERSION = "2021-07-28";

const lcHeaders = (accessToken) => ({
  Authorization: `Bearer ${accessToken}`,
  "Content-Type": "application/json",
  Accept: "application/json",
  Version: LC_VERSION,
});

const getAnyLocation = () => {
  const it = tokenStore.entries().next();
  if (it.done) return null;
  const [locationId, tokens] = it.value;
  return { locationId, tokens };
};

/* -------------------------------------------------------------------------- */
/* OAuth Token Refresh                                                        */
/* -------------------------------------------------------------------------- */

const tokenRefreshLocks = new Map();

async function getValidAccessToken(locationId) {
  const row = tokenStore.get(locationId);
  if (!row) return null;

  const created = Number(row._created_at_ms || 0) || Date.now();
  const ttl = Number(row.expires_in || 0) * 1000;
  const slack = 60_000;
  const isExpired = ttl > 0 ? Date.now() > created + ttl - slack : false;

  if (!isExpired) return row.access_token || null;
  if (!row.refresh_token) return row.access_token || null;

  const lockKey = `refresh-${locationId}`;
  if (tokenRefreshLocks.has(lockKey)) {
    console.log("[oauth] waiting for existing refresh to complete...");
    await tokenRefreshLocks.get(lockKey);
    const updated = tokenStore.get(locationId);
    return updated?.access_token || null;
  }

  const refreshPromise = (async () => {
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
    } finally {
      tokenRefreshLocks.delete(lockKey);
    }
  })();

  tokenRefreshLocks.set(lockKey, refreshPromise);
  return await refreshPromise;
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

/* -------------------------------------------------------------------------- */
/* Contact Lookup                                                             */
/* -------------------------------------------------------------------------- */

const findContactIdByPhone = async (locationId, e164Phone) => {
  const digits = (e164Phone || "").replace(/\D/g, "");
  const last10 = digits.slice(-10);

  const tryQueries = [
    e164Phone,
    digits,
    last10,
    `(${last10.slice(0, 3)}) ${last10.slice(3, 6)}-${last10.slice(6)}`,
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
            console.log("[findContact] matched:", c.id, "for", e164Phone);
            return c.id || c._id || null;
          }
        }
      }
    } catch (e) {
      console.error("[findContactIdByPhone] query failed:", q, e?.response?.status, e?.response?.data || e.message);
    }
  }
  
  console.log("[findContact] not found for:", e164Phone);
  return null;
};

/* -------------------------------------------------------------------------- */
/* GHL Conversation Lookup - Get Assigned User's Parking Number              */
/* -------------------------------------------------------------------------- */

const getAssignedUserParkingNumber = async (locationId, contactId, fallbackServer) => {
  try {
    console.log("[conversation] fetching conversations for contact:", contactId);
    
    const conversationsResponse = await withLcCall(locationId, (access) =>
      axios.get(
        `${LC_API}/conversations/search?locationId=${encodeURIComponent(locationId)}&contactId=${encodeURIComponent(contactId)}`,
        { headers: lcHeaders(access), timeout: 15000 }
      )
    );
    
    const conversations = conversationsResponse?.data?.conversations || [];
    
    if (conversations.length === 0) {
      console.log("[conversation] no conversations found for contact, using fallback");
      return fallbackServer.parkingNumbers[0].number;
    }
    
    const activeConversation = conversations[0];
    const assignedTo = activeConversation.assignedTo;
    
    if (!assignedTo) {
      console.log("[conversation] no assigned user, using fallback");
      return fallbackServer.parkingNumbers[0].number;
    }
    
    console.log("[conversation] conversation assigned to userId:", assignedTo);
    
    for (const server of BLUEBUBBLES_SERVERS) {
      for (const parkingConfig of server.parkingNumbers) {
        if (parkingConfig.userId === assignedTo) {
          console.log(`[conversation] ✅ matched userId ${assignedTo} → ${parkingConfig.user} → parking ${parkingConfig.number}`);
          return parkingConfig.number;
        }
      }
    }
    
    console.log("[conversation] userId not found in parking map, using fallback");
    return fallbackServer.parkingNumbers[0].number;
    
  } catch (e) {
    console.error("[conversation] lookup failed:", e?.response?.status, e?.response?.data || e.message);
    console.log("[conversation] using fallback parking number");
    return fallbackServer.parkingNumbers[0].number;
  }
};

/* -------------------------------------------------------------------------- */
/* Attachment Handling                                                        */
/* -------------------------------------------------------------------------- */

function detectMimeType(buffer, filename = '') {
  if (!buffer || buffer.length === 0) return 'application/octet-stream';
  
  const bytes = buffer.slice(0, 12);
  
  if (bytes[0] === 0x89 && bytes[1] === 0x50 && bytes[2] === 0x4E && bytes[3] === 0x47) {
    return 'image/png';
  }
  
  if (bytes[0] === 0xFF && bytes[1] === 0xD8 && bytes[2] === 0xFF) {
    return 'image/jpeg';
  }
  
  if (bytes[0] === 0x47 && bytes[1] === 0x49 && bytes[2] === 0x46) {
    return 'image/gif';
  }
  
  if (bytes[8] === 0x57 && bytes[9] === 0x45 && bytes[10] === 0x42 && bytes[11] === 0x50) {
    return 'image/webp';
  }
  
  if (bytes[0] === 0x25 && bytes[1] === 0x50 && bytes[2] === 0x44 && bytes[3] === 0x46) {
    return 'application/pdf';
  }
  
  if (bytes[0] === 0x50 && bytes[1] === 0x4B && (bytes[2] === 0x03 || bytes[2] === 0x05)) {
    return 'application/zip';
  }
  
  if (bytes[4] === 0x66 && bytes[5] === 0x74 && bytes[6] === 0x79 && bytes[7] === 0x70) {
    return 'video/mp4';
  }
  
  const ext = filename.toLowerCase().split('.').pop();
  const extMap = {
    'png': 'image/png',
    'jpg': 'image/jpeg',
    'jpeg': 'image/jpeg',
    'gif': 'image/gif',
    'webp': 'image/webp',
    'pdf': 'application/pdf',
    'zip': 'application/zip',
    'mp4': 'video/mp4',
    'mov': 'video/quicktime',
    'heic': 'image/heic',
    'heif': 'image/heif',
  };
  
  return extMap[ext] || 'application/octet-stream';
}

async function downloadBBAttachment(server, attachmentGuid) {
  try {
    console.log(`[attachment][${server.id}] downloading from BB:`, attachmentGuid);
    const buffer = await bbGetBuffer(server, `/api/v1/attachment/${encodeURIComponent(attachmentGuid)}/download`);
    return buffer;
  } catch (e) {
    console.error(`[attachment][${server.id}] download failed:`, e.message);
    return null;
  }
}

async function downloadGHLAttachment(url) {
  try {
    console.log("[attachment] downloading from GHL:", url);
    const response = await axios.get(url, {
      responseType: 'arraybuffer',
      timeout: 30000
    });
    
    const buffer = Buffer.from(response.data);
    
    let mimeType = response.headers['content-type'];
    if (!mimeType || mimeType === 'application/octet-stream') {
      mimeType = detectMimeType(buffer, url);
      console.log("[attachment] detected MIME type:", mimeType);
    }
    
    return { buffer, mimeType };
  } catch (e) {
    console.error("[attachment] GHL download failed:", e.message);
    return null;
  }
}

async function uploadToGHL(locationId, accessToken, buffer, filename, mimeType) {
  try {
    console.log("[attachment] uploading to GHL:", filename, mimeType, `${buffer.length} bytes`);
    
    const form = new FormData();
    
    let uploadMimeType = mimeType || 'application/octet-stream';
    
    if (uploadMimeType === 'image/png' || filename.toLowerCase().endsWith('.png')) {
      uploadMimeType = 'image/png';
    } else if (uploadMimeType === 'image/jpeg' || uploadMimeType === 'image/jpg' || 
               filename.toLowerCase().endsWith('.jpg') || filename.toLowerCase().endsWith('.jpeg')) {
      uploadMimeType = 'image/jpeg';
    }
    
    form.append('file', buffer, {
      filename: filename || 'attachment',
      contentType: uploadMimeType
    });
    form.append('locationId', locationId);

    console.log("[attachment] attempting upload with contentType:", uploadMimeType);

    const response = await axios.post(
      `${LC_API}/medias/upload-file`,
      form,
      {
        headers: {
          ...form.getHeaders(),
          'Authorization': `Bearer ${accessToken}`,
          'Version': LC_VERSION
        },
        maxBodyLength: Infinity,
        maxContentLength: Infinity,
        timeout: 60000
      }
    );

    console.log("[attachment] upload success:", response.data);
    return response.data;
  } catch (e) {
    console.error("[attachment] upload failed:", e?.response?.status, e?.response?.data || e.message);
    
    if (e?.response?.status === 400 && e?.response?.data?.message === 'Invalid File Type') {
      console.log("[attachment] GHL rejected file type, this file type may not be supported by GHL");
    }
    
    return null;
  }
}

/* -------------------------------------------------------------------------- */
/* Push Messages to GHL with Attachments                                      */
/* -------------------------------------------------------------------------- */

const pushToGhlThread = async ({
  locationId,
  accessToken,
  contactId,
  text,
  fromNumber,
  isFromMe,
  timestamp,
  attachments = [],
  server,
}) => {
  let messageBody;
  
  if (isFromMe) {
    const date = timestamp ? new Date(timestamp) : new Date();
    const timeStr = date.toLocaleTimeString('en-US', { 
      hour: 'numeric', 
      minute: '2-digit',
      hour12: true,
      timeZone: TIMEZONE
    });
    
    messageBody = `━━━━━━━━━━━━━━━━━━━━
👤 YOU (sent from iPhone)
⏰ ${timeStr}
━━━━━━━━━━━━━━━━━━━━

${text || ''}`;
  } else {
    messageBody = text || '';
  }

  let mediaUrls = [];
  
  if (attachments && attachments.length > 0) {
    console.log(`[GHL] processing ${attachments.length} attachment(s) from ${server.name}`);
    
    for (const att of attachments) {
      try {
        const attGuid = att.guid || att.id;
        const filename = att.transferName || att.filename || 'attachment';
        let mimeType = att.mimeType || att.mime || null;
        
        const buffer = await downloadBBAttachment(server, attGuid);
        if (!buffer) {
          console.error("[GHL] failed to download attachment:", attGuid);
          continue;
        }
        
        if (!mimeType) {
          mimeType = detectMimeType(buffer, filename);
          console.log("[GHL] detected MIME type:", mimeType, "for", filename);
        }
        
        let finalFilename = filename;
        if (!finalFilename.includes('.')) {
          const extMap = {
            'image/png': '.png',
            'image/jpeg': '.jpg',
            'image/gif': '.gif',
            'image/webp': '.webp',
            'application/pdf': '.pdf',
            'video/mp4': '.mp4',
            'video/quicktime': '.mov',
          };
          finalFilename += (extMap[mimeType] || '');
        }
        
        const uploaded = await uploadToGHL(locationId, accessToken, buffer, finalFilename, mimeType);
        if (uploaded && uploaded.url) {
          mediaUrls.push(uploaded.url);
          console.log("[GHL] attachment uploaded:", uploaded.url);
        }
      } catch (e) {
        console.error("[GHL] attachment processing error:", e.message);
      }
    }
  }

  if ((!messageBody || !messageBody.trim()) && mediaUrls.length > 0) {
    if (isFromMe) {
      const date = timestamp ? new Date(timestamp) : new Date();
      const timeStr = date.toLocaleTimeString('en-US', { 
        hour: 'numeric', 
        minute: '2-digit',
        hour12: true,
        timeZone: TIMEZONE
      });
      messageBody = `━━━━━━━━━━━━━━━━━━━━
👤 YOU (sent from iPhone)
⏰ ${timeStr}
━━━━━━━━━━━━━━━━━━━━

📎 Sent ${mediaUrls.length} attachment(s)`;
    } else {
      messageBody = `📎 ${mediaUrls.length} attachment(s)`;
    }
  }

  const body = {
    locationId,
    contactId,
    message: messageBody,
    type: "Custom",
    conversationProviderId: CONVERSATION_PROVIDER_ID,
    altType: "iMessage",
  };

  if (mediaUrls.length > 0) {
    body.attachments = mediaUrls;
  }

  const endpoint = `${LC_API}/conversations/messages/inbound`;

  console.log(`[GHL] pushing to thread (${isFromMe ? 'iPhone' : 'contact'}) with ${mediaUrls.length} attachment(s) via ${server.name}`);

  try {
    const r = await axios.post(endpoint, body, {
      headers: lcHeaders(accessToken),
      timeout: 20000,
    });
    const resp = r.data || {};
    
    if (resp?.error || resp?.success === false) {
      console.error("[GHL] push accepted but errored:", resp);
      return null;
    }
    
    console.log("[GHL] push success:", {
      messageId: resp.messageId || resp.id,
      contactId,
      isFromMe,
      type: "iMessage",
      attachments: mediaUrls.length,
      server: server.name,
    });
    return resp;
  } catch (e) {
    const status = e?.response?.status;
    const data = e?.response?.data;
    
    console.error("[GHL] push failed:", status, data || e.message);
    return null;
  }
};

/* -------------------------------------------------------------------------- */
/* Provider Send (Delivery URL) - GHL → iMessage WITH ATTACHMENTS           */
/* -------------------------------------------------------------------------- */

function extractToFromAndMessage(rawBody = {}) {
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

  const from =
    body.from ||
    body.fromNumber ||
    body.sender?.phone ||
    body.source ||
    body.parkingNumber ||
    null;

  const userId = body.userId || body.user_id || body.userID || null;

  const message =
    body.message ||
    body.text ||
    body.body ||
    body.content ||
    null;

  return { to, from, userId, message, body };
}

const handleProviderSend = async (req, res) => {
  try {
    if (GHL_SHARED_SECRET && !verifyBearer(req)) {
      return res.status(401).json({ status: "error", error: "Unauthorized" });
    }

    console.log("[provider] ========== FULL REQUEST BODY ==========");
    console.log(JSON.stringify(req.body, null, 2));
    console.log("[provider] ========== QUERY PARAMS ==========");
    console.log(JSON.stringify(req.query, null, 2));
    console.log("[provider] ========================================");

    const { to: toRaw, from: fromRaw, userId, message: messageRaw, body: parsedBody } = extractToFromAndMessage(req.body || {});
    let to = toRaw ?? req.query.to;
    let from = fromRaw ?? req.query.from;
    let message = messageRaw ?? req.query.message;

    const attachmentsFromBody = 
      parsedBody?.attachments || 
      parsedBody?.mediaUrls || 
      parsedBody?.media || 
      parsedBody?.images || 
      [];

    console.log("[provider] EXTRACTED VALUES:", { 
      to, 
      from,
      userId,
      messagePreview: message?.slice(0, 50),
      attachmentsInBody: attachmentsFromBody.length 
    });

    if (!to) return res.status(400).json({ ok: false, success: false, error: "Missing 'to' phone" });
    
    let e164;
    try {
      e164 = ensureE164(String(to));
    } catch (err) {
      return res.status(400).json({ ok: false, error: err.message });
    }
    
    if ((!message || !String(message).trim()) && attachmentsFromBody.length === 0) {
      return res.status(400).json({ ok: false, success: false, error: "Missing 'message' or attachments" });
    }

    let server;
    let routedBy = "unknown";
    
    if (userId) {
      console.log(`[provider] GHL sent userId: ${userId}`);
      server = findServerByUserId(userId);
      routedBy = "userId";
    } else if (from) {
      console.log(`[provider] GHL sent 'from' field: ${from}`);
      server = findServerByParkingNumber(from);
      routedBy = "from-field";
    } else {
      console.log(`[provider] No userId or 'from' field, falling back to 'to' number routing`);
      server = findServerForPhone(e164);
      routedBy = "to-field-fallback";
    }
    
    console.log(`[provider] routing to ${server.name} for ${e164}`);

    const sendFromAccount = userId ? getIMessageAccountForUser(userId, server) : server.phoneNumbers[0].number;
    console.log(`[provider] sending from iMessage account: ${sendFromAccount}`);
    
    let chatGuid;
    if (sendFromAccount) {
      chatGuid = `iMessage;-;${e164};-;${sendFromAccount}`;
      console.log(`[provider] using Private API chatGuid: ${chatGuid}`);
    } else {
      chatGuid = chatGuidForPhone(e164);
    }

    let textMessageSent = false;
    let data = null;
    if (message && String(message).trim()) {
      const payload = {
        chatGuid,
        tempGuid: newTempGuid("temp-bridge"),
        message: String(message),
        method: "private-api",
      };
      
      data = await bbPost(server, "/api/v1/message/text", payload);
      textMessageSent = true;

      rememberOutbound(String(message), chatGuid, attachmentsFromBody.length > 0);
    } else {
      console.log("[provider] no text message, sending attachments only");
      rememberOutbound("", chatGuid, true);
    }

    let successfulAttachments = 0;
    if (attachmentsFromBody.length > 0) {
      console.log(`[provider] sending ${attachmentsFromBody.length} attachment(s) to ${server.name}`);
      
      for (const attachment of attachmentsFromBody) {
        try {
          const attachmentUrl = 
            attachment.url || 
            attachment.src || 
            attachment.mediaUrl ||
            (typeof attachment === 'string' ? attachment : null);
            
          if (!attachmentUrl) {
            console.log("[provider] skipping attachment - no URL found:", attachment);
            continue;
          }

          let filename = attachment.name || attachment.filename || 'attachment';
          
          console.log("[provider] downloading attachment:", attachmentUrl);
          
          const downloadResult = await downloadGHLAttachment(attachmentUrl);
          if (!downloadResult || !downloadResult.buffer) {
            console.error("[provider] download failed for:", attachmentUrl);
            continue;
          }

          const { buffer, mimeType } = downloadResult;
          
          if (!filename.includes('.')) {
            const extMap = {
              'image/png': '.png',
              'image/jpeg': '.jpg',
              'image/gif': '.gif',
              'image/webp': '.webp',
              'application/pdf': '.pdf',
              'video/mp4': '.mp4',
              'video/quicktime': '.mov',
            };
            filename += (extMap[mimeType] || '');
          }

          console.log("[provider] downloaded", buffer.length, "bytes, MIME:", mimeType, "uploading to BlueBubbles...");
          
          const bbResult = await bbUploadAttachment(server, chatGuid, buffer, filename);
          console.log("[provider] ✅ attachment sent to BlueBubbles:", bbResult?.guid || 'success');
          successfulAttachments++;
        } catch (e) {
          console.error("[provider] failed to send attachment:", e.message);
        }
      }
    } else {
      console.log("[provider] no attachments found in request body");
    }

    return res.status(200).json({
      ok: true,
      success: true,
      status: "delivered",
      delivered: true,
      provider: "eden-imessage",
      relay: server.baseUrl,
      server: server.name,
      routedBy: routedBy,
      messageId: textMessageSent ? (data?.guid || data?.data?.guid || `msg-${newTempGuid()}`) : `attachment-${newTempGuid()}`,
      id: textMessageSent ? (data?.guid || data?.data?.guid || `msg-${newTempGuid()}`) : `attachment-${newTempGuid()}`,
      attachmentCount: successfulAttachments,
      attachmentsRequested: attachmentsFromBody.length,
      textMessageSent,
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

app.all("/provider/deliver", handleProviderSend);
app.all("/provider/deliverl", handleProviderSend);
app.post("/send", handleProviderSend);

/* -------------------------------------------------------------------------- */
/* Inbound Webhook - BlueBubbles → Bridge → GHL (Multi-Server)               */
/* -------------------------------------------------------------------------- */

async function handleBlueBubblesWebhook(req, res, serverOverride = null) {
  try {
    if (verifyBearer(req)) return res.status(200).json({ ok: true });

    const src  = req.body || {};
    const data = src.data || {};

    console.log("[inbound] RAW WEBHOOK PAYLOAD:", JSON.stringify(req.body, null, 2));

    const messageText =
      data.text ??
      data.message?.text ??
      src.text ??
      src.message ??
      null;

    const fromRaw =
      data.handle?.address ??
      data.message?.handle?.address ??
      data.sender ??
      src.from ??
      data.handle ??
      null;

    const chatGuid =
      data.chats?.[0]?.guid ??
      data.chat?.guid ??
      src.chatGuid ??
      null;

    const isFromMe = Boolean(
      data.isFromMe ?? data.message?.isFromMe ?? src.isFromMe ?? false
    );

    const timestamp = 
      data.dateCreated ?? 
      data.message?.dateCreated ?? 
      data.date ?? 
      src.timestamp ?? 
      Date.now();

    const attachments = 
      data.attachments ??
      data.message?.attachments ??
      src.attachments ??
      [];

    const hasAttachments = Boolean(
      data.hasAttachments ?? 
      data.message?.hasAttachments ?? 
      (attachments && attachments.length > 0)
    );

    console.log("[inbound] EXTRACTED:", {
      messageText: messageText?.slice(0, 50),
      fromRaw,
      chatGuid,
      isFromMe,
      timestamp,
      hasAttachments,
      attachmentCount: attachments?.length || 0,
      serverOverride: serverOverride ? `${serverOverride.name} (forced)` : 'auto-detect',
    });

    if (!messageText && !hasAttachments && !attachments?.length) {
      console.log("[inbound] no text or attachments - ignoring");
      return res.status(200).json({ ok: true });
    }

    if (!fromRaw) {
      console.log("[inbound] no sender info - ignoring");
      return res.status(200).json({ ok: true });
    }

    if (isOurOutbound(messageText, chatGuid, hasAttachments)) {
      console.log("[inbound] IGNORING - message was sent via bridge (echo prevention)");
      return res.status(200).json({ ok: true, ignored: "bridge-sent" });
    }

    const any = getAnyLocation();
    if (!any) {
      console.error("[inbound] NO OAUTH TOKENS");
      return res.status(200).json({ ok: true, note: "no-oauth" });
    }
    const { locationId } = any;

    let contactE164 = null;
    try { contactE164 = ensureE164(fromRaw); } catch { contactE164 = null; }
    if (!contactE164 && chatGuid) {
      const tail = String(chatGuid).split(";").pop();
      try { contactE164 = ensureE164(tail); } catch {}
    }
    if (!contactE164) {
      console.log("[inbound] CANNOT NORMALIZE PHONE:", { fromRaw, chatGuid });
      return res.status(200).json({ ok: true, note: "bad-contact-number" });
    }

    const server = serverOverride || findServerForPhone(contactE164);
    console.log(`[inbound] message from ${server.name} for contact ${contactE164}`);

    const contactId = await findContactIdByPhone(locationId, contactE164);
    if (!contactId) {
      console.log(`[inbound] CONTACT NOT FOUND IN GHL - ignoring message:`, {
        locationId,
        phone: contactE164,
        isFromMe,
        messagePreview: messageText?.slice(0, 50),
        hasAttachments,
        server: server.name,
        parkingNumber: server.parkingNumbers[0]?.number
      });
      return res.status(200).json({ ok: true, note: "no-contact" });
    }

    const locationNumber = await getAssignedUserParkingNumber(locationId, contactId, server);
    
    if (!locationNumber) {
      console.error(`[inbound] PARKING NUMBER NOT SET for ${server.name}`);
      return res.status(200).json({ ok: true, note: "no-parking-number" });
    }

    console.log(`[inbound] using parking number ${locationNumber} for ${server.name} (based on conversation assignment)`);

    const key = dedupeKey({ text: messageText, from: contactE164, chatGuid });
    if (isRecentInbound(key)) {
      console.log("[inbound] DUPLICATE - already processed");
      return res.status(200).json({ ok: true, ignored: "duplicate" });
    }
    rememberInbound(key);

    const accessToken = await getValidAccessToken(locationId);
    if (!accessToken) {
      console.error("[inbound] NO ACCESS TOKEN");
      return res.status(200).json({ ok: true, note: "no-access-token" });
    }

    if (isFromMe) {
      console.log(`[inbound] IPHONE MESSAGE - pushing to thread ${hasAttachments ? 'with attachments' : ''} via ${server.name} (parking: ${locationNumber})`);
    } else {
      console.log(`[inbound] CONTACT MESSAGE - pushing to thread ${hasAttachments ? 'with attachments' : ''} via ${server.name} (parking: ${locationNumber})`);
    }
    
    const pushed = await pushToGhlThread({
      locationId,
      accessToken,
      contactId,
      text: messageText,
      fromNumber: locationNumber,
      isFromMe,
      timestamp,
      attachments: hasAttachments ? attachments : [],
      server,
    });

    if (!pushed) {
      console.error("[inbound] PUSH TO GHL FAILED");
      return res.status(200).json({ ok: true, note: "push-failed" });
    }

    console.log(`[inbound] ✅ SUCCESS - ${isFromMe ? 'iPhone' : 'contact'} message pushed as iMessage ${hasAttachments ? 'with ' + attachments.length + ' attachment(s)' : ''} via ${server.name} (parking: ${locationNumber})`);

    rememberPush({
      locationId,
      contactId,
      chatGuid,
      text: messageText,
      fromNumber: locationNumber,
      toNumber: contactE164,
      isFromMe,
      hasAttachments,
      attachmentCount: attachments?.length || 0,
      handledAs: "conversation-thread-imessage",
      server: server.name,
      parkingNumber: locationNumber,
    });

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
            isFromMe,
            hasAttachments,
            attachmentCount: attachments?.length || 0,
            handledAs: "conversation-thread-imessage",
            receivedAt: new Date().toISOString(),
            server: server.name,
            parkingNumber: locationNumber,
          },
          { headers: { "Content-Type": "application/json" }, timeout: 10000 }
        );
      } catch (e) {
        console.error("[inbound] forward failed:", e?.message);
      }
    }

    return res.status(200).json({ ok: true, pushed, server: server.name, parkingNumber: locationNumber });
  } catch (err) {
    console.error("[inbound] EXCEPTION:", err?.response?.data || err.message, err.stack);
    return res.status(200).json({ ok: true, error: "ingest-failed" });
  }
}

app.post("/webhook/bluebubbles/bb1", async (req, res) => {
  console.log("[webhook] bb1 (Eden's Mac) endpoint called");
  return handleBlueBubblesWebhook(req, res, BLUEBUBBLES_SERVERS[0]);
});

app.post("/webhook/bluebubbles/bb2", async (req, res) => {
  console.log("[webhook] bb2 (Mario's Mac Mini) endpoint called");
  return handleBlueBubblesWebhook(req, res, BLUEBUBBLES_SERVERS[1]);
});

app.post("/webhook/bluebubbles/bb3", async (req, res) => {
  console.log("[webhook] bb3 (Tiffany's Mac Mini) endpoint called");
  return handleBlueBubblesWebhook(req, res, BLUEBUBBLES_SERVERS[2]);
});

app.post("/webhook/bluebubbles", async (req, res) => {
  console.log("[webhook] generic endpoint called, auto-detecting server...");
  return handleBlueBubblesWebhook(req, res, null);
});

app.post("/webhook", async (req, res) => {
  console.log("[webhook] legacy /webhook endpoint called, processing...");
  return handleBlueBubblesWebhook(req, res, null);
});

/* -------------------------------------------------------------------------- */
/* OAuth Flow                                                                 */
/* -------------------------------------------------------------------------- */

app.get("/oauth/start", (_req, res) => {
  if (!CLIENT_ID || !GHL_REDIRECT_URI) {
    return res.status(400).send("OAuth not configured (missing CLIENT_ID or GHL_REDIRECT_URI).");
  }

  const scope = [
    "conversations/message.write",
    "conversations/message.readonly",
    "conversations.write",
    "conversations.readonly",
    "contacts.readonly",
    "locations.readonly",
    "medias.write",
    "medias.readonly",
  ].join(" ");

  const params = new URLSearchParams({
    client_id: CLIENT_ID,
    response_type: "code",
    redirect_uri: GHL_REDIRECT_URI,
    scope,
  });

  res.redirect(`${OAUTH_AUTHORIZE_BASE}/authorize?${params.toString()}`);
});

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

    console.log("[oauth] tokens saved for location:", locationId);

    const arr = Array.from(tokenStore.entries());
    const base64 = Buffer.from(JSON.stringify(arr)).toString('base64');

    return res
      .status(200)
      .send(`<!doctype html><html><body style="font-family:system-ui;background:#0b0b0c;color:#e5e7eb;padding:20px">
<div style="background:#111827;border:1px solid #1f2937;border-radius:14px;padding:24px;max-width:800px;margin:0 auto;box-shadow:0 10px 30px rgba(0,0,0,.3)">
<h1 style="color:#10b981">✅ Eden iMessage connected</h1>
<p>Location: <code style="background:#1f2937;padding:4px 8px;border-radius:6px">${locationId}</code></p>
<div style="margin-top:20px;padding:16px;background:#1f2937;border-radius:8px">
<strong style="color:#fbbf24">⚠️ IMPORTANT: Add this to Render Environment Variables</strong>
<p style="margin:10px 0 5px;font-size:14px">This will persist your tokens across restarts:</p>
<div style="margin:10px 0"><strong>Key:</strong> <code style="background:#0b0b0c;padding:4px 8px;border-radius:4px">GHL_TOKENS_BASE64</code></div>
<div style="margin:10px 0"><strong>Value:</strong></div>
<textarea readonly style="width:100%;min-height:100px;background:#0b0b0c;color:#e5e7eb;border:1px solid #374151;border-radius:6px;padding:8px;font-family:monospace;font-size:12px;resize:vertical">${base64}</textarea>
<button onclick="navigator.clipboard.writeText('${base64}').then(()=>alert('Copied to clipboard!'))" style="margin-top:10px;background:#10b981;color:#fff;border:none;padding:8px 16px;border-radius:6px;cursor:pointer">📋 Copy Value</button>
</div>
<p style="margin-top:20px;font-size:14px;color:#9ca3af">You can close this window after copying the value.</p>
</div>
<script>setTimeout(()=>{window.close?.();},60000)</script></body></html>`);
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
    parkingNumbers: getAllParkingNumbers(),
    servers: BLUEBUBBLES_SERVERS.map(s => ({
      id: s.id,
      name: s.name,
      baseUrl: s.baseUrl,
      parkingNumbers: s.parkingNumbers,
      phoneCount: s.phoneNumbers.length,
      phoneNumbers: s.phoneNumbers,
    })),
  });
});

/* -------------------------------------------------------------------------- */
/* Debug Endpoints                                                            */
/* -------------------------------------------------------------------------- */

app.get("/", (_req, res) => {
  res.status(200).json({
    ok: true,
    name: "ghl-bluebubbles-bridge",
    version: "3.7.0",
    mode: "single-provider-multi-server-routing-private-api",
    servers: BLUEBUBBLES_SERVERS.map(s => ({
      id: s.id,
      name: s.name,
      baseUrl: s.baseUrl,
      users: s.parkingNumbers.map(p => p.user),
      parkingNumbers: s.parkingNumbers.map(p => p.number),
      phoneNumbers: s.phoneNumbers.map(p => ({ number: p.number, user: p.user })),
    })),
    totalPhoneNumbers: getAllPhoneNumbers().length,
    totalParkingNumbers: getAllParkingNumbers().length,
    oauthConfigured: !!(CLIENT_ID && CLIENT_SECRET),
    conversationProviderId: CONVERSATION_PROVIDER_ID,
    features: {
      multiServer: true,
      threeServers: true,
      dedicatedServersPerUser: true,
      userAssignment: true,
      conversationAssignmentRouting: true,
      privateAPI: true,
      perMessageAccountSelection: true,
      dedicatedParkingNumbers: true,
      envConfigurableParkingNumbers: true,
      singleProviderRouting: true,
      fromFieldRouting: true,
      textMessages: true,
      inboundAttachments: true,
      outboundAttachments: true,
      photos: true,
      files: true,
      privacyFilter: true,
      timezone: TIMEZONE,
    },
    messageFlow: {
      "contact→you": "Thread as iMessage with attachments",
      "you→contact (iPhone)": "Thread as iMessage with attachments + header",
      "ghl→contact": "Delivered via BlueBubbles WITH ATTACHMENTS (routed by 'from' field)",
      "non-contact": "IGNORED (privacy filter)",
    },
    routing: {
      "Eden": {
        parkingNumber: PARKING_NUMBER_EDEN,
        iMessageNumber: "+13058337256",
        server: "bb1 (Original Mac)",
        envVar: "PARKING_NUMBER_EDEN"
      },
      "Mario": {
        parkingNumber: PARKING_NUMBER_MARIO,
        iMessageNumber: "+13059273268",
        server: "bb2 (Mac Mini #1)",
        envVar: "PARKING_NUMBER_MARIO"
      },
      "Tiffany": {
        parkingNumber: PARKING_NUMBER_TIFFANY,
        iMessageNumber: "+19544450020",
        server: "bb3 (Mac Mini #2)",
        envVar: "PARKING_NUMBER_TIFFANY"
      }
    }
  });
});

app.get("/health", async (_req, res) => {
  const serverStatuses = [];
  
  for (const server of BLUEBUBBLES_SERVERS) {
    try {
      const pong = await axios.get(
        `${server.baseUrl}/api/v1/ping?guid=${encodeURIComponent(server.password)}`,
        { timeout: 8000 }
      );
      serverStatuses.push({
        id: server.id,
        name: server.name,
        baseUrl: server.baseUrl,
        users: server.parkingNumbers.map(p => p.user),
        parkingNumbers: server.parkingNumbers.map(p => p.number),
        status: "online",
        ping: pong.data ?? null,
      });
    } catch (e) {
      serverStatuses.push({
        id: server.id,
        name: server.name,
        baseUrl: server.baseUrl,
        users: server.parkingNumbers.map(p => p.user),
        parkingNumbers: server.parkingNumbers.map(p => p.number),
        status: "offline",
        error: e?.response?.data ?? e?.message ?? "Ping failed",
      });
    }
  }
  
  const allOnline = serverStatuses.every(s => s.status === "online");
  
  res.status(allOnline ? 200 : 503).json({
    ok: allOnline,
    servers: serverStatuses,
  });
});

app.get("/debug/last-inbound", (_req, res) => {
  res.json({ ok: true, items: LAST_INBOUND });
});

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

/* -------------------------------------------------------------------------- */
/* Chrome Extension Calling Integration                                       */
/* -------------------------------------------------------------------------- */

app.get("/calling", (req, res) => {
  const phoneNumber = req.query.id || '';
  const origin = req.query.origin || 'extension';
  
  console.log(`[calling] Request from ${origin} for ${phoneNumber}`);
  
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');
  
  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Call ${phoneNumber}</title>
      <style>
        * {
          box-sizing: border-box;
          margin: 0;
          padding: 0;
        }
        
        body {
          font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
          display: flex;
          justify-content: center;
          align-items: center;
          min-height: 100vh;
          background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
          padding: 20px;
        }
        
        .container {
          background: white;
          padding: 40px;
          border-radius: 20px;
          box-shadow: 0 20px 60px rgba(0,0,0,0.3);
          text-align: center;
          max-width: 400px;
          width: 100%;
          animation: slideUp 0.3s ease-out;
        }
        
        @keyframes slideUp {
          from {
            opacity: 0;
            transform: translateY(20px);
          }
          to {
            opacity: 1;
            transform: translateY(0);
          }
        }
        
        h1 {
          color: #333;
          margin-bottom: 10px;
          font-size: 28px;
        }
        
        .phone {
          font-size: 32px;
          font-weight: bold;
          color: #008bff;
          margin: 30px 0;
          letter-spacing: 1px;
        }
        
        .status {
          font-size: 16px;
          color: #666;
          margin: 20px 0;
          min-height: 24px;
          transition: color 0.3s ease;
        }
        
        .status.success {
          color: #2ecc40;
        }
        
        .buttons {
          display: flex;
          gap: 10px;
          margin-top: 30px;
        }
        
        button {
          flex: 1;
          background: #008bff;
          color: white;
          border: none;
          padding: 15px 20px;
          font-size: 16px;
          font-weight: 600;
          border-radius: 10px;
          cursor: pointer;
          transition: all 0.3s ease;
        }
        
        button:hover {
          background: #0066cc;
          transform: translateY(-2px);
          box-shadow: 0 5px 15px rgba(0,139,255,0.3);
        }
        
        button:active {
          transform: translateY(0);
        }
        
        button:disabled {
          background: #ccc;
          cursor: not-allowed;
          transform: none;
        }
        
        button.cancel {
          background: #e0e0e0;
          color: #333;
        }
        
        button.cancel:hover {
          background: #d0d0d0;
          box-shadow: 0 5px 15px rgba(0,0,0,0.1);
        }
        
        .icon {
          font-size: 48px;
          margin-bottom: 20px;
          animation: pulse 2s infinite;
        }
        
        @keyframes pulse {
          0%, 100% { transform: scale(1); }
          50% { transform: scale(1.1); }
        }
        
        .powered-by {
          margin-top: 30px;
          font-size: 12px;
          color: #999;
        }
      </style>
    </head>
    <body>
      <div class="container">
        <div class="icon">📞</div>
        <h1>Click to Call</h1>
        <div class="phone" id="phoneDisplay">${phoneNumber}</div>
        <div class="status" id="status">Ready to call</div>
        <div class="buttons">
          <button id="callBtn" onclick="makeCall()">Call Now</button>
          <button class="cancel" onclick="window.close()">Cancel</button>
        </div>
        <div class="powered-by">Powered by Eden Bridge v3.7.0</div>
      </div>
      
      <script>
        const phoneNumber = "${phoneNumber}";
        const statusEl = document.getElementById('status');
        const callBtn = document.getElementById('callBtn');
        
        function normalizePhone(phone) {
          let clean = phone.replace(/[^0-9+]/g, '');
          
          if (clean.startsWith('+')) {
            return clean;
          }
          
          if (clean.length === 11 && clean.startsWith('1')) {
            return '+' + clean;
          }
          
          if (clean.length === 10) {
            return '+1' + clean;
          }
          
          return clean;
        }
        
        function makeCall() {
          statusEl.textContent = 'Opening phone app...';
          callBtn.disabled = true;
          
          const normalizedPhone = normalizePhone(phoneNumber);
          console.log('Calling:', normalizedPhone);
          
          window.location.href = 'tel:' + normalizedPhone;
          
          fetch('/call-initiated', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              phoneNumber: phoneNumber,
              origin: '${origin}',
              timestamp: new Date().toISOString()
            })
          }).catch(err => console.log('Log failed:', err));
          
          setTimeout(() => {
            statusEl.textContent = 'Call initiated! You can close this window.';
            statusEl.className = 'status success';
          }, 1000);
        }
      </script>
    </body>
    </html>
  `);
});

app.get("/conversations", (req, res) => {
  const phoneNumber = req.query.id || '';
  const origin = req.query.origin || 'extension';
  
  console.log(`[conversations] Request from ${origin} for ${phoneNumber}`);
  
  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Chat ${phoneNumber}</title>
      <style>
        * {
          box-sizing: border-box;
          margin: 0;
          padding: 0;
        }
        
        body {
          font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
          display: flex;
          justify-content: center;
          align-items: center;
          min-height: 100vh;
          background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
          padding: 20px;
        }
        
        .container {
          background: white;
          padding: 40px;
          border-radius: 20px;
          box-shadow: 0 20px 60px rgba(0,0,0,0.3);
          text-align: center;
          max-width: 400px;
          width: 100%;
        }
        
        h1 {
          color: #333;
          margin-bottom: 10px;
          font-size: 28px;
        }
        
        .phone {
          font-size: 24px;
          font-weight: bold;
          color: #008bff;
          margin: 20px 0;
        }
        
        .icon {
          font-size: 48px;
          margin-bottom: 20px;
        }
        
        p {
          color: #666;
          margin: 20px 0;
        }
        
        button {
          background: #008bff;
          color: white;
          border: none;
          padding: 15px 30px;
          font-size: 16px;
          font-weight: 600;
          border-radius: 10px;
          cursor: pointer;
          margin-top: 20px;
        }
        
        button:hover {
          background: #0066cc;
        }
        
        .powered-by {
          margin-top: 30px;
          font-size: 12px;
          color: #999;
        }
      </style>
    </head>
    <body>
      <div class="container">
        <div class="icon">💬</div>
        <h1>Chat</h1>
        <div class="phone">${phoneNumber}</div>
        <p>Send messages from GHL conversations or use the iMessage app on your Mac/iPhone!</p>
        <button onclick="window.close()">Close</button>
        <div class="powered-by">Powered by Eden Bridge v3.7.0</div>
      </div>
    </body>
    </html>
  `);
});

app.post("/call-initiated", async (req, res) => {
  try {
    const { phoneNumber, origin, timestamp } = req.body;
    console.log(`[call-initiated] ${phoneNumber} from ${origin} at ${timestamp}`);
    
    res.json({ ok: true, logged: true, timestamp });
  } catch (error) {
    console.error("[call-initiated] error:", error.message);
    res.status(500).json({ ok: false, error: error.message });
  }
});

/* -------------------------------------------------------------------------- */
/* Server Startup                                                             */
/* -------------------------------------------------------------------------- */

(async function() {
  await loadTokenStore();

  app.listen(PORT, () => {
    console.log(`[bridge] listening on :${PORT}`);
    console.log(`[bridge] VERSION 3.7.0 - Three-Server Architecture Complete! 🎯🚀`);
    console.log("");
    console.log("📋 BlueBubbles Servers:");
    for (const server of BLUEBUBBLES_SERVERS) {
      console.log(`  • ${server.name} (${server.id})`);
      console.log(`    URL: ${server.baseUrl}`);
      console.log(`    Users: ${server.parkingNumbers.map(p => p.user).join(', ')}`);
      console.log(`    Parking Numbers: ${server.parkingNumbers.map(p => p.number).join(', ')}`);
      const phoneList = server.phoneNumbers.map(p => `${p.number} (${p.user})`).join(', ');
      console.log(`    iMessage Numbers: ${phoneList}`);
      console.log(`    Webhook URL: https://ieden-bluebubbles-bridge-1.onrender.com/webhook/bluebubbles/${server.id}`);
      console.log("");
    }
    console.log(`[bridge] Total iMessage Numbers: ${getAllPhoneNumbers().length}`);
    console.log(`[bridge] Total Parking Numbers: ${getAllParkingNumbers().length}`);
    console.log(`[bridge] TIMEZONE = ${TIMEZONE}`);
    console.log(`[bridge] Conversation Provider ID = ${CONVERSATION_PROVIDER_ID}`);
    console.log("");
    console.log("📋 Routing Configuration:");
    console.log(`  Eden (env: PARKING_NUMBER_EDEN):`);
    console.log(`    Parking: ${PARKING_NUMBER_EDEN} → iMessage: +13058337256 → Server: bb1`);
    console.log(`  Mario (env: PARKING_NUMBER_MARIO):`);
    console.log(`    Parking: ${PARKING_NUMBER_MARIO} → iMessage: +13059273268 → Server: bb2`);
    console.log(`  Tiffany (env: PARKING_NUMBER_TIFFANY):`);
    console.log(`    Parking: ${PARKING_NUMBER_TIFFANY} → iMessage: +19544450020 → Server: bb3`);
    console.log("");
    console.log("📋 Features:");
    console.log("  ✅ Three dedicated BlueBubbles servers (bb1, bb2, bb3)");
    console.log("  ✅ Each user has dedicated Mac Mini + iPhone");
    console.log("  ✅ Single conversation provider (like SendBlue)");
    console.log("  ✅ Routes by GHL userId (most reliable!)");
    console.log("  ✅ Conversation assignment routing (bulletproof!)");
    console.log("  ✅ Private API with per-message account selection");
    console.log("  ✅ Dedicated parking numbers per user (via ENV)");
    console.log("  ✅ Text messages (all directions)");
    console.log("  ✅ Photos & images (all directions)");
    console.log("  ✅ Files & documents (all directions)");
    console.log("  ✅ Smart server routing");
    console.log("  ✅ Privacy filter (no auto-contact creation)");
    console.log("  ✅ Click-to-call (Chrome extension integration)");
    console.log("  ✅ Click-to-chat (Chrome extension integration)");
    console.log("");
    if (CLIENT_ID && CLIENT_SECRET) console.log("[bridge] OAuth is configured.");
    if (GHL_SHARED_SECRET) console.log("[bridge] Shared secret checks enabled.");
  });
})();

process.on("SIGTERM", async () => { try { await saveTokenStore(); } finally { process.exit(0); } });
process.on("SIGINT",  async () => { try { await saveTokenStore(); } finally { process.exit(0); } });
