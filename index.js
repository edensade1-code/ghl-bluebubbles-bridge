// index.js - VERSION 2.20 (2025-01-08)
// ============================================================================
// PROJECT: Eden iMessage Bridge - BlueBubbles ↔ GoHighLevel (GHL) Integration
// ============================================================================
//
// 🎯 PURPOSE OF THIS PROJECT:
// ---------------------------
// This bridge connects your iPhone's iMessage (via BlueBubbles relay server) 
// to GoHighLevel CRM, enabling:
// 
// 1. BIDIRECTIONAL MESSAGING:
//    - Send messages from GHL → Contact's iMessage
//    - Receive messages from Contact → Show in GHL
//    - Mirror YOUR iPhone messages → Show in GHL (right side)
//
// 2. PRIVACY FILTERING:
//    - Only contacts that exist in GHL get synced
//    - Random numbers are ignored (keeps personal convos private)
//
// 3. ECHO PREVENTION:
//    - Smart tracking prevents message loops
//    - Outbound tracker remembers messages WE sent
//    - Prevents duplicate messages
//
// 📋 WHAT WE'RE TESTING IN VERSION 2.20:
// ---------------------------------------
// PROGRESS! We're getting different errors which means we're closer!
//
// ERROR EVOLUTION:
// v2.17: 'type must be a valid enum value' (with type: "SMS")
// v2.18: 'type must be a valid enum value', 'type should not be empty' (no type)
// v2.19: 'No call object passed in body' (with type: "Call")
//
// DIAGNOSIS: type: "Call" requires call-specific fields (duration, status, etc.)
// That's not what we need for text messages!
//
// FIX ATTEMPT #3 (this version): Try type: "Custom"
// - GHL docs mention "Custom" type for custom conversation providers
// - Quote from docs: "Add Inbound Message API: Use type 'Custom'"
// - This should be the correct type for our iMessage custom provider
//
// If "Custom" fails, next attempts:
// - Try type: "Live_Chat"
// - Try removing conversationProviderId (maybe it conflicts with type)
// - Search for the actual enum values in GHL API schema
//
// 📝 VERSION HISTORY & WHAT WE TRIED:
// ------------------------------------
// v2.17: Added conversationId lookup for /outbound endpoint
//        - Found conversation via /conversations/search
//        - Included conversationProviderId + conversationId
//        - FAILED: type field rejected as invalid enum
//
// v2.16: Attempted to use /outbound for iPhone messages
//        - FAILED: Missing conversationId (required for /outbound)
//
// v2.15: Used /inbound for all messages
//        - WORKED: Messages appeared in GHL
//        - PROBLEM: All showed on LEFT side (wrong direction)
//
// v2.14: Added echo prevention with outbound tracker
//        - WORKED: Stopped duplicate messages from GHL sends
//
// v2.13: Split message flow into inbound/outbound paths
//        - Introduced isFromMe detection
//
// v2.1-2.12: Various OAuth, token refresh, and contact lookup fixes
//
// 🔧 CURRENT CONFIGURATION (copy to Render env vars):
// ----------------------------------------------------
// BB_BASE=https://relay.asapcashhomebuyers.com
// BB_GUID=[BlueBubbles server password]
// CLIENT_ID=[GHL OAuth client ID]
// CLIENT_SECRET=[GHL OAuth client secret]
// GHL_REDIRECT_URI=https://ieden-bluebubbles-bridge-1.onrender.com/oauth/callback
// PARKING_NUMBER=+17867334163
// CONVERSATION_PROVIDER_ID=68d94718bcd02bcf453ccf46
// GHL_TOKENS_BASE64=[Base64 from /oauth/start - paste here to persist tokens]
// GHL_SHARED_SECRET=1b059e90-9f0d-4c78-81b0-97cd3053aa4a
//
// 🌐 WEBHOOK SETUP:
// -----------------
// BlueBubbles webhook URL: https://ieden-bluebubbles-bridge-1.onrender.com/webhook
// GHL Delivery URL: https://ieden-bluebubbles-bridge-1.onrender.com/provider/deliver?key=[shared_secret]
//
// 📊 MESSAGE FLOW ARCHITECTURE:
// ------------------------------
// 
// OUTBOUND (GHL → Contact):
// 1. User types in GHL → Calls /provider/deliver
// 2. Bridge sends via BlueBubbles → iMessage delivered to contact
// 3. BlueBubbles webhooks back → Bridge ignores (outbound tracker match)
//
// INBOUND (Contact → You):
// 1. Contact sends iMessage → BlueBubbles receives
// 2. BlueBubbles webhooks → Bridge /webhook endpoint
// 3. Bridge posts to GHL /conversations/messages/inbound
// 4. Message appears in GHL (LEFT side - from contact)
//
// IPHONE-INITIATED (You → Contact from your iPhone):
// 1. You send from iPhone → BlueBubbles detects (isFromMe=true)
// 2. BlueBubbles webhooks → Bridge /webhook endpoint
// 3. Bridge finds conversationId via /conversations/search
// 4. Bridge posts to GHL /conversations/messages/outbound
// 5. Message mirrors to GHL (RIGHT side - from you)
//
// 🚨 CRITICAL API REQUIREMENTS:
// ------------------------------
// /inbound endpoint needs:
//   - type: "SMS" (or possibly omit for provider)
//   - locationId, contactId, message
//   - Does NOT need conversationProviderId or conversationId
//
// /outbound endpoint needs:
//   - conversationProviderId (your provider ID)
//   - conversationId (found via /conversations/search)
//   - locationId, contactId, message
//   - type field: TESTING REMOVAL (was causing 422 error)
//
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

const app = express();

/* -------------------------------------------------------------------------- */
/* Middleware                                                                 */
/* -------------------------------------------------------------------------- */
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
/* Config - Environment Variables                                             */
/* -------------------------------------------------------------------------- */
const PORT = Number(process.env.PORT || 8080);

// BlueBubbles relay server (your Mac running BlueBubbles)
const BB_BASE = (process.env.BB_BASE || "https://relay.asapcashhomebuyers.com").trim();
const BB_GUID = (process.env.BB_GUID || "REPLACE_WITH_BLUEBUBBLES_SERVER_PASSWORD").trim();

// GHL inbound webhook (optional - for forwarding messages elsewhere)
const GHL_INBOUND_URL = (process.env.GHL_INBOUND_URL || "").trim();

// OAuth credentials for GHL API
const CLIENT_ID = (process.env.CLIENT_ID || "").trim();
const CLIENT_SECRET = (process.env.CLIENT_SECRET || "").trim();
const GHL_REDIRECT_URI = (
  process.env.GHL_REDIRECT_URI ||
  "https://ieden-bluebubbles-bridge-1.onrender.com/oauth/callback"
).trim();

const OAUTH_AUTHORIZE_BASE = "https://marketplace.gohighlevel.com/oauth";
const OAUTH_TOKEN_BASE     = "https://services.leadconnectorhq.com/oauth";

// Shared secret for webhook authentication
const GHL_SHARED_SECRET = (process.env.GHL_SHARED_SECRET || "").trim();

// Your business phone number (shows as "from" in GHL)
const ENV_PARKING_NUMBER =
  (process.env.PARKING_NUMBER || process.env.BUSINESS_NUMBER || "").trim();

// Token persistence (survives Render restarts when saved as base64 env var)
const TOKENS_FILE = (process.env.TOKENS_FILE || "./tokens.json").trim();
const TOKENS_ENV_KEY = "GHL_TOKENS_BASE64";

// Your conversation provider ID from GHL marketplace app
const CONVERSATION_PROVIDER_ID = (process.env.CONVERSATION_PROVIDER_ID || "68d94718bcd02bcf453ccf46").trim();

/* -------------------------------------------------------------------------- */
/* State & Helper Functions                                                   */
/* -------------------------------------------------------------------------- */

// OAuth token storage (Map: locationId → token object)
const tokenStore = new Map();

// Echo prevention - tracks messages WE sent to prevent loops
// When we send via /provider/deliver, BlueBubbles webhooks back with isFromMe=true
// We check this map to see if it's a message we just sent, and ignore it
const recentOutboundMessages = new Map(); // chatGuid|text → expiry timestamp
const recentInboundKeys = new Map();      // dedupe for inbound messages
const DEDUPE_TTL_MS = 15_000;             // 15 seconds for inbound dedupe
const OUTBOUND_TTL_MS = 30_000;           // 30 seconds for outbound tracking

// Create a dedupe key from message details
const dedupeKey = ({ text, from, chatGuid }) =>
  `${chatGuid || ""}|${from || ""}|${(text || "").slice(0, 128)}`;

// Remember an outbound message we sent (to prevent echo when webhook fires)
const rememberOutbound = (text, chatGuid) => {
  const key = `${chatGuid}|${(text || "").slice(0, 128)}`;
  const expiry = Date.now() + OUTBOUND_TTL_MS;
  recentOutboundMessages.set(key, expiry);
  
  console.log("[outbound-tracker] remembered:", { chatGuid, textPreview: text?.slice(0, 32) });
  
  // Cleanup old entries to prevent memory leak
  if (recentOutboundMessages.size > 100) {
    const now = Date.now();
    for (const [k, exp] of recentOutboundMessages.entries()) {
      if (exp < now) recentOutboundMessages.delete(k);
    }
  }
};

// Check if this message is one we recently sent (for echo prevention)
const isOurOutbound = (text, chatGuid) => {
  const key = `${chatGuid}|${(text || "").slice(0, 128)}`;
  const expiry = recentOutboundMessages.get(key);
  if (!expiry) return false;
  if (expiry < Date.now()) {
    recentOutboundMessages.delete(key);
    return false;
  }
  console.log("[outbound-tracker] MATCH FOUND - this is our message");
  return true;
};

// Remember an inbound message (for dedupe)
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

// Check if we've seen this inbound message recently (dedupe)
const isRecentInbound = (k) => {
  const expiry = recentInboundKeys.get(k);
  if (!expiry) return false;
  if (expiry < Date.now()) {
    recentInboundKeys.delete(k);
    return false;
  }
  return true;
};

// Debug: Store last 25 messages pushed to GHL
const LAST_INBOUND = [];
function rememberPush(p) {
  LAST_INBOUND.push({ at: new Date().toISOString(), ...p });
  if (LAST_INBOUND.length > 25) LAST_INBOUND.shift();
}

/* -------------------------------------------------------------------------- */
/* Token Persistence - Load from env var (survives restarts) or file         */
/* -------------------------------------------------------------------------- */

async function loadTokenStore() {
  // Try loading from env var first (survives Render restarts)
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

  // Fallback to file (ephemeral on Render)
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
  
  // Save to file (ephemeral on Render, but useful for local dev)
  try {
    await fs.writeFile(TOKENS_FILE, JSON.stringify(arr, null, 2), "utf8");
    console.log(`[oauth] tokens persisted to ${TOKENS_FILE}`);
  } catch (e) {
    console.error("[oauth] file persist failed:", e?.message);
  }

  // Print base64 to console so you can copy to env var
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
/* Startup Validation - Check required env vars                              */
/* -------------------------------------------------------------------------- */

if (!BB_GUID || BB_GUID === "REPLACE_WITH_BLUEBUBBLES_SERVER_PASSWORD") {
  console.warn("[WARN] BB_GUID is not set. Set your BlueBubbles server password.");
}
if (!CLIENT_ID || !CLIENT_SECRET) {
  console.log("[bridge] OAuth not configured (CLIENT_ID/CLIENT_SECRET missing).");
}
if (!ENV_PARKING_NUMBER) {
  console.log("[bridge] PARKING_NUMBER/BUSINESS_NUMBER not set — GHL will reject inbound.");
}

/* -------------------------------------------------------------------------- */
/* Phone Number Helpers                                                       */
/* -------------------------------------------------------------------------- */

// Generate a temporary GUID for message tracking
const newTempGuid = (p = "temp") => `${p}-${crypto.randomBytes(6).toString("hex")}`;

// Convert any phone format to E.164 (e.g., +19082655248)
const toE164US = (raw) => {
  if (!raw) return null;
  const d = String(raw).replace(/\D/g, "");
  
  // Handle +1XXXXXXXXXX (11 digits starting with 1)
  if (d.startsWith("1") && d.length === 11) return `+${d}`;
  
  // Handle XXXXXXXXXX (10 digits)
  if (d.length === 10) return `+1${d}`;
  
  // Already has +
  if (String(raw).startsWith("+") && d.length >= 10) return `+${d}`;
  
  return null;
};

// Ensure phone is in E.164 format or throw error
const ensureE164 = (phone) => {
  const e = toE164US(phone);
  if (!e) throw new Error(`Invalid US phone: ${phone}. Use E.164 like +13051234567`);
  return e;
};

// Create BlueBubbles chat GUID from phone number
const chatGuidForPhone = (e164) => `iMessage;-;${e164}`;

// Get the parking/business number in E.164 format
function getIdentityNumber() {
  try {
    return ENV_PARKING_NUMBER ? ensureE164(ENV_PARKING_NUMBER) : null;
  } catch (err) {
    console.error("[identity] invalid PARKING_NUMBER format:", err.message);
    return null;
  }
}

/* -------------------------------------------------------------------------- */
/* BlueBubbles API Helpers                                                    */
/* -------------------------------------------------------------------------- */

// POST to BlueBubbles API
const bbPost = async (path, body) => {
  const url = `${BB_BASE}${path}?guid=${encodeURIComponent(BB_GUID)}`;
  try {
    const { data } = await axios.post(url, body, {
      headers: { "Content-Type": "application/json" },
      timeout: 15000,
    });
    return data;
  } catch (err) {
    console.error("[bbPost] failed:", path, err?.response?.status, err.message);
    throw err;
  }
};

// GET from BlueBubbles API
const bbGet = async (path) => {
  const url = `${BB_BASE}${path}${path.includes("?") ? "&" : "?"}guid=${encodeURIComponent(BB_GUID)}`;
  try {
    const { data } = await axios.get(url, { timeout: 15000 });
    return data;
  } catch (err) {
    console.error("[bbGet] failed:", path, err?.response?.status, err.message);
    throw err;
  }
};

// Verify webhook authentication (Bearer token or ?key= query param)
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

// Create headers for GHL API requests
const lcHeaders = (accessToken) => ({
  Authorization: `Bearer ${accessToken}`,
  "Content-Type": "application/json",
  Accept: "application/json",
  Version: LC_VERSION,
});

// Get any location from token store (for quick access when location doesn't matter)
const getAnyLocation = () => {
  const it = tokenStore.entries().next();
  if (it.done) return null;
  const [locationId, tokens] = it.value;
  return { locationId, tokens };
};

/* -------------------------------------------------------------------------- */
/* OAuth Token Refresh - Prevent concurrent refreshes with lock              */
/* -------------------------------------------------------------------------- */

const tokenRefreshLocks = new Map(); // locationId → Promise (prevents race conditions)

async function getValidAccessToken(locationId) {
  const row = tokenStore.get(locationId);
  if (!row) return null;

  // Check if token is expired
  const created = Number(row._created_at_ms || 0) || Date.now();
  const ttl = Number(row.expires_in || 0) * 1000;
  const slack = 60_000; // Refresh 1 min before expiry
  const isExpired = ttl > 0 ? Date.now() > created + ttl - slack : false;

  if (!isExpired) return row.access_token || null;
  if (!row.refresh_token) return row.access_token || null;

  // Use lock to prevent multiple simultaneous refresh attempts
  const lockKey = `refresh-${locationId}`;
  if (tokenRefreshLocks.has(lockKey)) {
    console.log("[oauth] waiting for existing refresh to complete...");
    await tokenRefreshLocks.get(lockKey);
    const updated = tokenStore.get(locationId);
    return updated?.access_token || null;
  }

  // Create refresh promise and store in lock
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

// Call GHL API with automatic token refresh on 401
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
/* Contact Lookup - Find GHL contact by phone number                         */
/* -------------------------------------------------------------------------- */

const findContactIdByPhone = async (locationId, e164Phone) => {
  // Try multiple phone formats (E.164, digits only, formatted, last 10 digits)
  const digits = (e164Phone || "").replace(/\D/g, "");
  const last10 = digits.slice(-10);

  const tryQueries = [
    e164Phone,
    digits,
    last10,
    `(${last10.slice(0, 3)}) ${last10.slice(3, 6)}-${last10.slice(6)}`,
  ];

  // Normalize phone number for comparison
  const normalize = (p) => {
    if (!p) return null;
    const d = String(p).replace(/\D/g, "");
    if (d.length >= 11 && d.startsWith("1")) return `+${d}`;
    if (d.length === 10) return `+1${d}`;
    return d ? `+${d}` : null;
  };

  // Try each query format
  for (const q of tryQueries) {
    try {
      const r = await withLcCall(locationId, (access) =>
        axios.get(
          `${LC_API}/contacts/?locationId=${encodeURIComponent(locationId)}&query=${encodeURIComponent(q)}`,
          { headers: lcHeaders(access), timeout: 15000 }
        )
      );
      const list = r?.data?.contacts || r?.data?.items || r?.data?.data || [];
      
      // Check each contact for matching phone
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
/* Conversation Lookup - Find existing conversation for a contact            */
/* -------------------------------------------------------------------------- */

const findConversationId = async (locationId, accessToken, contactId) => {
  try {
    const resp = await axios.get(
      `${LC_API}/conversations/search?locationId=${encodeURIComponent(locationId)}&contactId=${encodeURIComponent(contactId)}`,
      { headers: lcHeaders(accessToken), timeout: 15000 }
    );
    
    const conversations = resp?.data?.conversations || [];
    if (conversations.length > 0) {
      console.log("[conversation] found existing:", conversations[0].id);
      return conversations[0].id;
    }
    
    return null;
  } catch (e) {
    console.error("[conversation] search failed:", e?.response?.status, e?.response?.data || e.message);
    return null;
  }
};

/* -------------------------------------------------------------------------- */
/* Push Message to GHL - Different endpoints for inbound vs outbound         */
/* -------------------------------------------------------------------------- */

const pushIntoGhl = async ({
  locationId,
  accessToken,
  contactId,
  text,
  fromNumber,
  toNumber,
  direction,
}) => {
  const body = {
    locationId,
    contactId,
    message: text,
  };

  // VERSION 2.20 CHANGE: Try type: "Custom" for custom providers
  // v2.19 showed that type: "Call" requires call-specific fields
  // Error was: "No call object passed in body" (400 Bad Request)
  //
  // REASONING: GHL documentation specifically mentions:
  // "Add Inbound Message API: Use type 'Custom'. You can also set 'altId'."
  // This is for CUSTOM conversation providers (which is what we are!)
  //
  // Why not "Call"? Because that requires call metadata (duration, status, etc.)
  // Why not "SMS"? Because that's for actual SMS/carrier integrations
  // "Custom" should be the right choice for our iMessage custom provider!

  if (direction === "inbound") {
    // For messages FROM contact TO you
    body.type = "SMS"; // This works fine for inbound
    // conversationProviderId and conversationId NOT required for inbound
  } else {
    // For messages FROM you TO contact (already sent via iPhone, just mirroring)
    body.conversationProviderId = CONVERSATION_PROVIDER_ID;
    
    // Find the conversation for this contact
    const conversationId = await findConversationId(locationId, accessToken, contactId);
    if (!conversationId) {
      console.error("[GHL] could not find conversation for contact:", contactId);
      return null;
    }
    body.conversationId = conversationId;
    
    // VERSION 2.20 TEST: Use type: "Custom" for custom conversation provider
    body.type = "Custom";
    
    // What we've tried so far:
    // ✗ type: "SMS"     → 422 "type must be a valid enum value"
    // ✗ (no type)       → 422 "type should not be empty"
    // ✗ type: "Call"    → 400 "No call object passed in body"
    // ⏳ type: "Custom" → Testing now!
    //
    // If this fails, next attempts:
    // - type: "Live_Chat"
    // - type: "Email" (maybe for generic external messaging?)
    // - Check if conversationProviderId conflicts with type field
  }

  // Choose endpoint based on direction
  // /inbound = contact sent to you (GHL receives it, shows LEFT side)
  // /outbound = you sent externally (already sent, just record it in GHL, shows RIGHT side)
  const endpoint = direction === "inbound" 
    ? `${LC_API}/conversations/messages/inbound`
    : `${LC_API}/conversations/messages/outbound`;

  console.log("[GHL] pushing to:", endpoint, "with body:", JSON.stringify(body, null, 2));

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
      direction,
      endpoint,
    });
    return resp;
  } catch (e) {
    const status = e?.response?.status;
    const data = e?.response?.data;
    
    console.error("[GHL] push failed:", status, data || e.message, "endpoint:", 
      direction === "inbound" ? "/inbound" : "/outbound");
    
    // VERSION 2.18 DEBUG: Log the full request body if failed
    console.error("[GHL] failed request body was:", JSON.stringify(body, null, 2));
    
    return null;
  }
};

/* -------------------------------------------------------------------------- */
/* Provider Send (Delivery URL) - GHL → iMessage                             */
/* -------------------------------------------------------------------------- */
// This endpoint is called when a user sends a message FROM GHL
// We need to:
// 1. Extract phone number and message from GHL payload
// 2. Send via BlueBubbles to iMessage
// 3. Remember the outbound message to prevent echo when webhook fires

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
    // Verify authentication
    if (GHL_SHARED_SECRET && !verifyBearer(req)) {
      return res.status(401).json({ status: "error", error: "Unauthorized" });
    }

    const { to: toRaw, message: messageRaw, body: parsedBody } = extractToAndMessage(req.body || {});
    let to = toRaw ?? req.query.to;
    let message = messageRaw ?? req.query.message;

    console.log("[provider] send request:", { to, messagePreview: message?.slice(0, 50) });

    if (!to) return res.status(400).json({ ok: false, success: false, error: "Missing 'to' phone" });
    
    let e164;
    try {
      e164 = ensureE164(String(to));
    } catch (err) {
      return res.status(400).json({ ok: false, error: err.message });
    }
    
    if (!message || !String(message).trim()) {
      return res.status(400).json({ ok: false, success: false, error: "Missing 'message'" });
    }

    // Send via BlueBubbles
    const payload = {
      chatGuid: chatGuidForPhone(e164),
      tempGuid: newTempGuid("temp-bridge"),
      message: String(message),
      method: "apple-script",
    };
    
    const data = await bbPost("/api/v1/message/text", payload);

    // CRITICAL: Remember this outbound message to prevent echo
    // When BlueBubbles webhooks back with this message, we'll ignore it
    rememberOutbound(String(message), payload.chatGuid);

    // DO NOT mirror outbound to GHL - it creates echo loop
    // GHL already has the message since the user sent it from GHL

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

app.all("/provider/deliver", handleProviderSend);
app.all("/provider/deliverl", handleProviderSend); // typo endpoint for backwards compat
app.post("/send", handleProviderSend);

/* -------------------------------------------------------------------------- */
/* Inbound Webhook - BlueBubbles → Bridge → GHL                              */
/* -------------------------------------------------------------------------- */
// This endpoint receives webhooks from BlueBubbles when:
// 1. Contact sends you an iMessage (isFromMe=false)
// 2. You send from iPhone (isFromMe=true)
//
// We need to:
// 1. Determine if message is from contact or from you
// 2. Check if it's an echo of a message we sent via GHL
// 3. Push to appropriate GHL endpoint (inbound or outbound)

app.post("/webhook", async (req, res) => {
  try {
    // Allow subscription pings
    if (verifyBearer(req)) return res.status(200).json({ ok: true });

    const src  = req.body || {};
    const data = src.data || {};

    // VERSION 2.18 DEBUG: Log full payload to understand structure
    console.log("[inbound] RAW WEBHOOK PAYLOAD:", JSON.stringify(req.body, null, 2));

    // Extract message details from webhook payload
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

    // VERSION 2.18 DEBUG: Log extracted values
    console.log("[inbound] EXTRACTED:", {
      messageText: messageText?.slice(0, 50),
      fromRaw,
      chatGuid,
      isFromMe,
    });

    if (!messageText || !fromRaw) {
      console.log("[inbound] missing data - ignoring");
      return res.status(200).json({ ok: true });
    }

    // CRITICAL: Check if this message was sent via the bridge (from GHL)
    // If so, ignore it to prevent echo loop
    if (isOurOutbound(messageText, chatGuid)) {
      console.log("[inbound] IGNORING - message was sent via bridge (echo prevention)");
      return res.status(200).json({ ok: true, ignored: "bridge-sent" });
    }

    // Get OAuth tokens
    const any = getAnyLocation();
    if (!any) {
      console.error("[inbound] NO OAUTH TOKENS");
      return res.status(200).json({ ok: true, note: "no-oauth" });
    }
    const { locationId } = any;

    // Normalize contact phone number
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

    const locationNumber = getIdentityNumber();
    if (!locationNumber) {
      console.error("[inbound] PARKING_NUMBER NOT SET OR INVALID");
      return res.status(200).json({ ok: true, note: "no-identity-number" });
    }

    // Dedupe check - prevent processing same message twice
    const key = dedupeKey({ text: messageText, from: contactE164, chatGuid });
    if (isRecentInbound(key)) {
      console.log("[inbound] DUPLICATE - already processed");
      return res.status(200).json({ ok: true, ignored: "duplicate" });
    }
    rememberInbound(key);

    // PRIVACY FILTER: Only sync contacts that exist in GHL
    // This keeps personal iPhone conversations private
    const contactId = await findContactIdByPhone(locationId, contactE164);
    if (!contactId) {
      console.log("[inbound] CONTACT NOT FOUND IN GHL:", { locationId, phone: contactE164 });
      return res.status(200).json({ ok: true, dropped: "no-contact" });
    }

    const accessToken = await getValidAccessToken(locationId);
    if (!accessToken) {
      console.error("[inbound] NO ACCESS TOKEN");
      return res.status(200).json({ ok: true, note: "no-access-token" });
    }

    // Determine direction based on isFromMe
    // isFromMe=true → You sent from iPhone (already sent, just mirror to GHL RIGHT side)
    // isFromMe=false → Contact sent to you (push to GHL LEFT side)
    const direction = isFromMe ? "outbound" : "inbound";
    const fromNumber = locationNumber;
    const toNumber = contactE164;

    console.log("[inbound] ATTEMPTING PUSH TO GHL:", {
      contactId,
      direction,
      isFromMe,
      fromNumber,
      toNumber,
      messagePreview: messageText.slice(0, 50)
    });

    // Push to appropriate GHL endpoint
    const pushed = await pushIntoGhl({
      locationId,
      accessToken,
      contactId,
      text: messageText,
      fromNumber,
      toNumber,
      direction,
    });

    if (!pushed) {
      console.error("[inbound] PUSH TO GHL FAILED - check pushIntoGhl logs above");
      return res.status(200).json({ ok: true, note: "push-failed" });
    }

    console.log("[inbound] ✅ SUCCESS - message pushed to GHL:", {
      locationId,
      contactId,
      chatGuid,
      direction
    });
    
    rememberPush({
      locationId,
      contactId,
      chatGuid,
      text: messageText,
      fromNumber,
      toNumber,
      direction
    });

    // Optional: Forward to another webhook (if configured)
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
            direction,
            receivedAt: new Date().toISOString(),
          },
          { headers: { "Content-Type": "application/json" }, timeout: 10000 }
        );
      } catch (e) {
        console.error("[inbound] forward failed:", e?.message);
      }
    }

    return res.status(200).json({ ok: true, pushed });
  } catch (err) {
    console.error("[inbound] EXCEPTION:", err?.response?.data || err.message, err.stack);
    return res.status(200).json({ ok: true, error: "ingest-failed" });
  }
});

/* -------------------------------------------------------------------------- */
/* OAuth Flow - Connect to GHL                                                */
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

    // Generate base64 for persistent storage (survives Render restarts)
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
    parkingNumber: ENV_PARKING_NUMBER || null,
  });
});

/* -------------------------------------------------------------------------- */
/* Embedded UI - Private iMessage inbox                                       */
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
/* Debug Endpoints                                                            */
/* -------------------------------------------------------------------------- */

app.get("/", (_req, res) => {
  res.status(200).json({
    ok: true,
    name: "ghl-bluebubbles-bridge",
    version: "2.20",
    relay: BB_BASE,
    oauthConfigured: !!(CLIENT_ID && CLIENT_SECRET),
    inboundForward: !!GHL_INBOUND_URL,
    parkingNumber: ENV_PARKING_NUMBER || null,
    conversationProviderId: CONVERSATION_PROVIDER_ID,
    routes: [
      "/health",
      "/provider/deliver (GET or POST)",
      "/send (POST)",
      "/webhook (POST from BlueBubbles)",
      "/debug/last-inbound",
      "/debug/ghl/contact-by-phone?phone=+1XXXXXXXXXX",
      "/debug/ghl/thread-by-contact?phone=+1XXXXXXXXXX",
      "/debug/messages?phone=+1XXXXXXXXXX",
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
    res.status(503).json({ ok: false, relay: BB_BASE, error: e?.response?.data ?? e?.message ?? "Ping failed" });
  }
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

    const resp = await withLcCall(locationId, (token) =>
      axios.get(
        `${LC_API}/conversations/search?locationId=${encodeURIComponent(locationId)}&contactId=${encodeURIComponent(contactId)}&limit=25`,
        { headers: lcHeaders(token), timeout: 20000 }
      )
    );

    res.json({ ok: true, locationId, contactId, raw: resp?.data || {} });
  } catch (e) {
    res.status(500).json({ ok: false, error: e?.response?.data || e.message });
  }
});

app.get("/debug/messages", async (req, res) => {
  try {
    const phoneRaw = (req.query.phone || "").trim();
    if (!phoneRaw) return res.status(400).json({ ok: false, error: "phone query param required" });

    const any = getAnyLocation();
    if (!any) return res.status(200).json({ ok: false, error: "no-oauth" });
    const { locationId } = any;

    const phone = phoneRaw.startsWith("+") ? phoneRaw : toE164US(phoneRaw);
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

/* -------------------------------------------------------------------------- */
/* Server Startup                                                             */
/* -------------------------------------------------------------------------- */

(async function() {
  await loadTokenStore();

  app.listen(PORT, () => {
    console.log(`[bridge] listening on :${PORT}`);
    console.log(`[bridge] BB_BASE = ${BB_BASE}`);
    console.log(`[bridge] Tokens file = ${TOKENS_FILE}`);
    console.log(`[bridge] PARKING_NUMBER = ${ENV_PARKING_NUMBER || "(not set!)"}`);
    console.log(`[bridge] Conversation Provider ID = ${CONVERSATION_PROVIDER_ID}`);
    if (GHL_INBOUND_URL) console.log(`[bridge] Forwarding inbound to ${GHL_INBOUND_URL}`);
    if (CLIENT_ID && CLIENT_SECRET) console.log("[bridge] OAuth is configured.");
    if (GHL_SHARED_SECRET) console.log("[bridge] Shared secret checks enabled.");
  });
})();

// Graceful shutdown - persist tokens before exit
process.on("SIGTERM", async () => { try { await saveTokenStore(); } finally { process.exit(0); } });
process.on("SIGINT",  async () => { try { await saveTokenStore(); } finally { process.exit(0); } });
