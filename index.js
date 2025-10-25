// index.js - VERSION 3.0 (2025-10-25)
// ============================================================================
// PROJECT: Eden Bridge - BlueBubbles ↔ GHL + Chrome Extension Calling
// ============================================================================
// LATEST UPDATE: Added click-to-call endpoints for Chrome extension integration!
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
/* Config - Environment Variables                                             */
/* -------------------------------------------------------------------------- */
const PORT = Number(process.env.PORT || 8080);

const BB_BASE = (process.env.BB_BASE || "https://relay.asapcashhomebuyers.com").trim();
const BB_GUID = (process.env.BB_GUID || "REPLACE_WITH_BLUEBUBBLES_SERVER_PASSWORD").trim();

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

const ENV_PARKING_NUMBER =
  (process.env.PARKING_NUMBER || process.env.BUSINESS_NUMBER || "").trim();

const TOKENS_FILE = (process.env.TOKENS_FILE || "./tokens.json").trim();
const TOKENS_ENV_KEY = "GHL_TOKENS_BASE64";

const CONVERSATION_PROVIDER_ID = (process.env.CONVERSATION_PROVIDER_ID || "68d94718bcd02bcf453ccf46").trim();

const TIMEZONE = (process.env.TIMEZONE || "America/New_York").trim();

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
  
  // If this message has attachments, track the chat for grace period
  if (hasAttachments) {
    const attExpiry = Date.now() + ATTACHMENT_GRACE_MS;
    recentOutboundAttachmentChats.set(chatGuid, attExpiry);
    console.log("[outbound-tracker] remembered with attachments:", { chatGuid, textPreview: text?.slice(0, 32) });
  } else {
    console.log("[outbound-tracker] remembered:", { chatGuid, textPreview: text?.slice(0, 32) });
  }
  
  // Clean up old entries
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
  // Check if this is a text message we sent
  const key = `${chatGuid}|${(text || "").slice(0, 128)}`;
  const expiry = recentOutboundMessages.get(key);
  if (expiry && expiry >= Date.now()) {
    console.log("[outbound-tracker] MATCH FOUND - ignoring echo (text)");
    return true;
  }
  if (expiry && expiry < Date.now()) {
    recentOutboundMessages.delete(key);
  }
  
  // Check if this is an attachment-only message in the grace period
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

const bbGetBuffer = async (path) => {
  const url = `${BB_BASE}${path}${path.includes("?") ? "&" : "?"}guid=${encodeURIComponent(BB_GUID)}`;
  try {
    const { data } = await axios.get(url, { 
      timeout: 30000,
      responseType: 'arraybuffer'
    });
    return data;
  } catch (err) {
    console.error("[bbGetBuffer] failed:", path, err?.response?.status, err.message);
    throw err;
  }
};

const bbUploadAttachment = async (chatGuid, buffer, filename) => {
  try {
    const form = new FormData();
    form.append('attachment', buffer, {
      filename: filename || 'attachment',
      contentType: 'application/octet-stream'
    });
    form.append('chatGuid', chatGuid);
    form.append('tempGuid', newTempGuid('att'));
    form.append('name', filename || 'attachment');

    const url = `${BB_BASE}/api/v1/message/attachment?guid=${encodeURIComponent(BB_GUID)}`;
    
    const { data } = await axios.post(url, form, {
      headers: form.getHeaders(),
      maxBodyLength: Infinity,
      maxContentLength: Infinity,
      timeout: 60000,
    });
    
    return data;
  } catch (err) {
    console.error("[bbUploadAttachment] failed:", err?.response?.status, err?.response?.data || err.message);
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
/* Attachment Handling                                                        */
/* -------------------------------------------------------------------------- */

// Detect MIME type from buffer's magic bytes
function detectMimeType(buffer, filename = '') {
  if (!buffer || buffer.length === 0) return 'application/octet-stream';
  
  const bytes = buffer.slice(0, 12);
  
  // PNG
  if (bytes[0] === 0x89 && bytes[1] === 0x50 && bytes[2] === 0x4E && bytes[3] === 0x47) {
    return 'image/png';
  }
  
  // JPEG
  if (bytes[0] === 0xFF && bytes[1] === 0xD8 && bytes[2] === 0xFF) {
    return 'image/jpeg';
  }
  
  // GIF
  if (bytes[0] === 0x47 && bytes[1] === 0x49 && bytes[2] === 0x46) {
    return 'image/gif';
  }
  
  // WEBP
  if (bytes[8] === 0x57 && bytes[9] === 0x45 && bytes[10] === 0x42 && bytes[11] === 0x50) {
    return 'image/webp';
  }
  
  // PDF
  if (bytes[0] === 0x25 && bytes[1] === 0x50 && bytes[2] === 0x44 && bytes[3] === 0x46) {
    return 'application/pdf';
  }
  
  // ZIP
  if (bytes[0] === 0x50 && bytes[1] === 0x4B && (bytes[2] === 0x03 || bytes[2] === 0x05)) {
    return 'application/zip';
  }
  
  // MP4
  if (bytes[4] === 0x66 && bytes[5] === 0x74 && bytes[6] === 0x79 && bytes[7] === 0x70) {
    return 'video/mp4';
  }
  
  // MOV
  if (bytes.indexOf(0x6D6F6F76) !== -1 || bytes.indexOf(0x66726565) !== -1) {
    return 'video/quicktime';
  }
  
  // Fallback to filename extension
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

async function downloadBBAttachment(attachmentGuid) {
  try {
    console.log("[attachment] downloading from BB:", attachmentGuid);
    const buffer = await bbGetBuffer(`/api/v1/attachment/${encodeURIComponent(attachmentGuid)}/download`);
    return buffer;
  } catch (e) {
    console.error("[attachment] download failed:", e.message);
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
    
    // Try to get MIME type from response headers or detect it
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
    console.log("[attachment] uploading to GHL:", filename, mimeType);
    
    const form = new FormData();
    form.append('file', buffer, {
      filename: filename || 'attachment',
      contentType: mimeType || 'application/octet-stream'
    });
    form.append('locationId', locationId);

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
}) => {
  let messageBody;
  
  if (isFromMe) {
    const date = timestamp ? new Date(timestamp) : new Date();
    // Use configured timezone
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
    console.log(`[GHL] processing ${attachments.length} attachment(s)`);
    
    for (const att of attachments) {
      try {
        const attGuid = att.guid || att.id;
        const filename = att.transferName || att.filename || 'attachment';
        let mimeType = att.mimeType || att.mime || null;
        
        const buffer = await downloadBBAttachment(attGuid);
        if (!buffer) {
          console.error("[GHL] failed to download attachment:", attGuid);
          continue;
        }
        
        // Detect MIME type if not provided
        if (!mimeType) {
          mimeType = detectMimeType(buffer, filename);
          console.log("[GHL] detected MIME type:", mimeType, "for", filename);
        }
        
        // Generate proper filename with extension if needed
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

  console.log(`[GHL] pushing to thread (${isFromMe ? 'iPhone' : 'contact'}) with ${mediaUrls.length} attachment(s)`);

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

    // Look for attachments in the request body
    const attachmentsFromBody = 
      parsedBody?.attachments || 
      parsedBody?.mediaUrls || 
      parsedBody?.media || 
      parsedBody?.images || 
      [];

    console.log("[provider] send request:", { 
      to, 
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
    
    if (!message || !String(message).trim()) {
      return res.status(400).json({ ok: false, success: false, error: "Missing 'message'" });
    }

    const chatGuid = chatGuidForPhone(e164);

    // Send text message first
    const payload = {
      chatGuid,
      tempGuid: newTempGuid("temp-bridge"),
      message: String(message),
      method: "apple-script",
    };
    
    const data = await bbPost("/api/v1/message/text", payload);

    // Remember this message BEFORE sending attachments
    rememberOutbound(String(message), chatGuid, attachmentsFromBody.length > 0);

    // Process attachments from request body
    let successfulAttachments = 0;
    if (attachmentsFromBody.length > 0) {
      console.log(`[provider] sending ${attachmentsFromBody.length} attachment(s) to BlueBubbles`);
      
      for (const attachment of attachmentsFromBody) {
        try {
          // Handle different attachment formats
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
          
          // Download from GHL
          const downloadResult = await downloadGHLAttachment(attachmentUrl);
          if (!downloadResult || !downloadResult.buffer) {
            console.error("[provider] download failed for:", attachmentUrl);
            continue;
          }

          const { buffer, mimeType } = downloadResult;
          
          // Add proper extension to filename based on MIME type
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
          
          // Upload to BlueBubbles
          const bbResult = await bbUploadAttachment(chatGuid, buffer, filename);
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
      status: "sent",
      provider: "eden-imessage",
      relay: BB_BASE,
      id: data?.guid || data?.data?.guid || payload.tempGuid,
      attachmentCount: successfulAttachments,
      attachmentsRequested: attachmentsFromBody.length,
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
app.all("/provider/deliverl", handleProviderSend);
app.post("/send", handleProviderSend);

/* -------------------------------------------------------------------------- */
/* Inbound Webhook - BlueBubbles → Bridge → GHL                              */
/* -------------------------------------------------------------------------- */

app.post("/webhook", async (req, res) => {
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

    const locationNumber = getIdentityNumber();
    if (!locationNumber) {
      console.error("[inbound] PARKING_NUMBER NOT SET OR INVALID");
      return res.status(200).json({ ok: true, note: "no-identity-number" });
    }

    const key = dedupeKey({ text: messageText, from: contactE164, chatGuid });
    if (isRecentInbound(key)) {
      console.log("[inbound] DUPLICATE - already processed");
      return res.status(200).json({ ok: true, ignored: "duplicate" });
    }
    rememberInbound(key);

    const contactId = await findContactIdByPhone(locationId, contactE164);
    if (!contactId) {
      console.log("[inbound] CONTACT NOT FOUND IN GHL - ignoring message:", { 
        locationId, 
        phone: contactE164,
        isFromMe,
        messagePreview: messageText?.slice(0, 30),
        hasAttachments
      });
      return res.status(200).json({ ok: true, dropped: "no-contact", reason: "privacy-filter" });
    }

    const accessToken = await getValidAccessToken(locationId);
    if (!accessToken) {
      console.error("[inbound] NO ACCESS TOKEN");
      return res.status(200).json({ ok: true, note: "no-access-token" });
    }

    if (isFromMe) {
      console.log(`[inbound] IPHONE MESSAGE - pushing to thread ${hasAttachments ? 'with attachments' : ''}`);
    } else {
      console.log(`[inbound] CONTACT MESSAGE - pushing to thread ${hasAttachments ? 'with attachments' : ''}`);
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
    });

    if (!pushed) {
      console.error("[inbound] PUSH TO GHL FAILED");
      return res.status(200).json({ ok: true, note: "push-failed" });
    }

    console.log(`[inbound] ✅ SUCCESS - ${isFromMe ? 'iPhone' : 'contact'} message pushed as iMessage ${hasAttachments ? 'with ' + attachments.length + ' attachment(s)' : ''}`);

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
<header><div><strong>📱 iMessage (Private)</strong><span class="status" id="status">checking…</span></div><div class="status">v2.30 - COMPLETE!</div></header>
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
    version: "2.30",
    mode: "full-bidirectional-attachments",
    relay: BB_BASE,
    oauthConfigured: !!(CLIENT_ID && CLIENT_SECRET),
    parkingNumber: ENV_PARKING_NUMBER || null,
    conversationProviderId: CONVERSATION_PROVIDER_ID,
    features: {
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
      "ghl→contact": "Delivered via BlueBubbles WITH ATTACHMENTS (from request body)",
      "non-contact": "IGNORED (privacy filter)",
    },
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

/* -------------------------------------------------------------------------- */
/* Chrome Extension Calling Integration                                       */
/* -------------------------------------------------------------------------- */

/**
 * GET /calling
 * Click-to-call interface for Chrome extension
 * Opens when user clicks call button in GHL/CRM
 */
app.get("/calling", (req, res) => {
  const phoneNumber = req.query.id || '';
  const origin = req.query.origin || 'extension';
  
  console.log(`[calling] Request from ${origin} for ${phoneNumber}`);
  
  // Add no-cache headers to prevent browser from caching
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
        <div class="powered-by">Powered by Eden Bridge</div>
      </div>
      
      <script>
        const phoneNumber = "${phoneNumber}";
        const statusEl = document.getElementById('status');
        const callBtn = document.getElementById('callBtn');
        
        // Normalize phone number - add +1 if missing
        function normalizePhone(phone) {
          // Remove all non-digit characters except +
          let clean = phone.replace(/[^0-9+]/g, '');
          
          // If it starts with +, keep it
          if (clean.startsWith('+')) {
            return clean;
          }
          
          // If it's 11 digits starting with 1, add +
          if (clean.length === 11 && clean.startsWith('1')) {
            return '+' + clean;
          }
          
          // If it's 10 digits, add +1
          if (clean.length === 10) {
            return '+1' + clean;
          }
          
          // Otherwise return as-is
          return clean;
        }
        
        function makeCall() {
          statusEl.textContent = 'Opening phone app...';
          callBtn.disabled = true;
          
          // Normalize the phone number
          const normalizedPhone = normalizePhone(phoneNumber);
          console.log('Calling:', normalizedPhone);
          
          // Trigger tel: URL (opens FaceTime/Phone app)
          window.location.href = 'tel:' + normalizedPhone;
          
          // Log call attempt
          fetch('/call-initiated', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              phoneNumber: phoneNumber,
              origin: '${origin}',
              timestamp: new Date().toISOString()
            })
          }).catch(err => console.log('Log failed:', err));
          
          // Update status
          setTimeout(() => {
            statusEl.textContent = 'Call initiated! You can close this window.';
            statusEl.className = 'status success';
          }, 1000);
        }
        
        // Optional: Auto-call after 2 seconds (uncomment to enable)
        // setTimeout(makeCall, 2000);
      </script>
    </body>
    </html>
  `);
});

/**
 * GET /conversations
 * Click-to-chat interface for Chrome extension
 * Opens when user clicks chat button in GHL/CRM
 */
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
        <div class="powered-by">Powered by Eden Bridge</div>
      </div>
    </body>
    </html>
  `);
});

/**
 * POST /call-initiated
 * Logs call attempts from Chrome extension
 */
app.post("/call-initiated", async (req, res) => {
  try {
    const { phoneNumber, origin, timestamp } = req.body;
    console.log(`[call-initiated] ${phoneNumber} from ${origin} at ${timestamp}`);
    
    // Optional: Log to GHL activity
    // Uncomment and implement if you want to track calls in GHL
    /*
    const any = getAnyLocation();
    if (any) {
      const { locationId } = any;
      const contactId = await findContactIdByPhone(locationId, ensureE164(phoneNumber));
      
      if (contactId) {
        await withLcCall(locationId, async (token) => {
          await axios.post(
            \`\${LC_API}/contacts/\${contactId}/notes\`,
            {
              body: \`📞 Call initiated via Chrome extension to \${phoneNumber}\`,
            },
            {
              headers: lcHeaders(token),
              timeout: 10000
            }
          );
        });
      }
    }
    */
    
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
    console.log(`[bridge] VERSION 3.0 - Chrome Extension Calling Added! 🎉✨`);
    console.log(`[bridge] BB_BASE = ${BB_BASE}`);
    console.log(`[bridge] PARKING_NUMBER = ${ENV_PARKING_NUMBER || "(not set!)"}`);
    console.log(`[bridge] TIMEZONE = ${TIMEZONE}`);
    console.log(`[bridge] Conversation Provider ID = ${CONVERSATION_PROVIDER_ID}`);
    console.log("");
    console.log("📋 Features:");
    console.log("  ✅ Text messages (all directions)");
    console.log("  ✅ Photos & images (all directions)");
    console.log("  ✅ Files & documents (all directions)");
    console.log("  ✅ GHL → Contact WITH attachments (reads from request body)!");
    console.log("  ✅ Privacy filter (no auto-contact creation)");
    console.log("  ✅ Click-to-call (Chrome extension integration)");
    console.log("  ✅ Click-to-chat (Chrome extension integration)");
    console.log("");
    console.log("📋 Message Flow:");
    console.log("  • Contact → You: Thread as iMessage with attachments");
    console.log("  • You → Contact (iPhone): Thread as iMessage with attachments + header");
    console.log("  • GHL → Contact: Delivered via BlueBubbles WITH ATTACHMENTS!");
    console.log("  • Non-Contact: IGNORED (privacy filter)");
    console.log("");
    if (CLIENT_ID && CLIENT_SECRET) console.log("[bridge] OAuth is configured.");
    if (GHL_SHARED_SECRET) console.log("[bridge] Shared secret checks enabled.");
  });
})();

process.on("SIGTERM", async () => { try { await saveTokenStore(); } finally { process.exit(0); } });
process.on("SIGINT",  async () => { try { await saveTokenStore(); } finally { process.exit(0); } });
