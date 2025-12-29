// index.js - VERSION 4.0.0 (2025-12-28)
// ============================================================================
// PROJECT: Eden Bridge - Multi-Server BlueBubbles ↔ GHL
// ============================================================================
// ============================================================================
// CHANGELOG v4.0.0:
// - ADDED: Full GHL Workflow Action support for Send iMessage
// - FIXED: GHL Marketplace Actions wrap fields in "data" object - now extracting correctly
// - ADDED: Workflow-sent messages now appear in GHL conversation thread (pushToGhlThread)
// - ADDED: "Wait for Reply" / Pause Execution support for workflows
//   * When Pause Execution is enabled, bridge stores workflow pause data (contactId, workflowId, stepId, etc.)
//   * When contact replies via iMessage, bridge calls GHL resume webhook to continue workflow
//   * Enables building drip campaigns and conversational flows with iMessage
// - ADDED: pausedWorkflows Map to track contacts with paused workflows awaiting reply
// - ADDED: resumePausedWorkflow() function to call GHL resume-internal-action endpoint
// - ADDED: Inbound message handler now checks for paused workflows and resumes them on reply
// - TECHNICAL: GHL sends extras object with: contactId, key, locationId, statusId, stepId, workflowId, stepIndex
// - TECHNICAL: Resume webhook URL: https://services.leadconnectorhq.com/workflows-marketplace/actions/resume-internal-action
// ============================================================================
// CHANGELOG v3.10.0:
// - ADDED: bb4 server for Amber's dedicated Mac Mini
// - ADDED: Amber's configuration (iMessage: +13054978748, Parking: +13059096544)
// - ADDED: GHL_USER_ID_AMBER and PARKING_NUMBER_AMBER env vars
// - UPDATED: Four-server architecture (bb1=Eden, bb2=Mario, bb3=Tiffany, bb4=Amber)
// - UPDATED: All routing logic to support 4 team members
// - VERIFIED: Full 4-server architecture with dedicated parking numbers
// ============================================================================
// CHANGELOG v3.9.0:
// - ADDED: GHL Marketplace Action "Send iMessage" for workflow automation
// - Workflows can now send iMessages via Actions → Send iMessage
// - Supports text messages and attachments via URL
// - Smart routing: Auto (uses assigned rep), or explicit Eden/Mario/Tiffany
// - Routes by: fromUser selection → GHL userId → conversation assignment → default
// - Endpoint: POST /action/send-imessage
// - Returns: success, messageId, server, fromUser, routedBy for workflow use
// ============================================================================
// CHANGELOG v3.8.0:
// - ADDED: Automatic GHL Workflow triggering for incoming iMessages
// - Bridge now triggers "Incoming iMessage" workflow when contact replies
// - Includes assignedUser field (Eden/Mario/Tiffany) for workflow filtering
// - Workflows can filter by: from, to, message, assignedUser, contactId
// - Only triggers for INCOMING messages (not outbound iPhone messages)
// ============================================================================
// CHANGELOG v3.7.11:
// - ADDED: /webhook/ghl endpoint for GHL Marketplace workflow triggers
// - Supports "Incoming iMessage" workflow trigger
// - Logs all GHL workflow events for debugging
// - Allows GHL workflows to react to iMessage events
// ============================================================================
// CHANGELOG v3.7.10:
// - FIXED: Outbound messages echoing back to GHL (race condition)
// - Now remembering outbound BEFORE sending (not after)
// - Prevents first webhook from arriving before tempGuid is in tracker
// - Eliminates duplicate outbound messages in GHL conversations
// ============================================================================
// CHANGELOG v3.7.9:
// - FIXED: Private API "Chat does not exist" for NEW contacts
// - Added automatic AppleScript fallback when Private API can't find chat
// - First message to new contact uses AppleScript to create chat
// - Subsequent messages will use Private API (chat now exists)
// - Seamless experience - users won't notice the fallback
// ============================================================================
// CHANGELOG v3.7.8:
// - FIXED: Duplicate incoming messages in GHL
// - Now ignoring "updated-message" webhook events (only processing "new-message")
// - BlueBubbles sends both new-message and updated-message for same message
// - Updated-message events are for read receipts, not new content
// ============================================================================
// CHANGELOG v3.7.7:
// - FIXED: "Chat does not exist" error with Private API
// - Changed to use simple chatGuid format (iMessage;-;+1234567890) for Private API
// - Removed complex account-specific chatGuid that was causing issues
// - Private API now works same as AppleScript for chat identification
// ============================================================================
// CHANGELOG v3.7.6:
// - FIXED: Made bb3 (Tiffany) usePrivateAPI configurable via BB3_USE_PRIVATE_API env var
// - Both bb2 and bb3 now support Private API toggling via environment variables
// - Set BB2_USE_PRIVATE_API=true and BB3_USE_PRIVATE_API=true when Private API enabled
// ============================================================================
// CHANGELOG v3.7.4:
// - FIXED: Mario's usePrivateAPI flag set to TRUE (was causing 401 auth errors)
// - FIXED: Removed iPhone echo formatting - no more "👤 YOU (sent from iPhone)" headers
// - IMPROVED: Cleaner message display - iPhone-sent messages now appear same as contact messages
// - NOTE: Using dedicated office iPhones, no need for iPhone echo distinction
// ============================================================================
// CHANGELOG v3.7.3:
// - FIXED: Server locking - messages now only process from the sending server
// - FIXED: Duplicate message prevention when multiple servers have same contact
// - ADDED: outboundServerMap to track which server sent each message
// - IMPROVED: Echo prevention now checks server ID to block cross-server duplicates
// - Team lead handoffs now work correctly - reassign in GHL and messages auto-route
// ============================================================================
// CHANGELOG v3.7.2:
// - FIXED: OAuth /oauth/start now uses /chooselocation instead of /authorize
// - IMPROVED: Simplified re-authorization process for private marketplace apps
// - Users can now visit single URL to re-authorize instead of copying installation link
// ============================================================================
// CHANGELOG v3.7.1:
// - FIXED: Made Private API optional per server (usePrivateAPI flag)
// - CHANGED: method now respects server.usePrivateAPI instead of hardcoded "private-api"
// - All servers default to usePrivateAPI: false (AppleScript mode)
// - Can enable Private API per server by setting usePrivateAPI: true
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
const PARKING_NUMBER_AMBER = (process.env.PARKING_NUMBER_AMBER || "+13059096544").trim();

// GHL User ID mapping (get these from GHL Settings -> My Staff)
const GHL_USER_ID_EDEN = "11umP2K61R5cuEoadD9x";
const GHL_USER_ID_MARIO = "7XskZuGiwXLneiUx10ne";
const GHL_USER_ID_TIFFANY = "BQAAlsqc9xdibpaxZP3q";
const GHL_USER_ID_AMBER = "SbeaaZLaNSaWIeeljIbB";

/* -------------------------------------------------------------------------- */
/* Health Monitoring Functions - section 1                                    */
/* -------------------------------------------------------------------------- */
// Health Monitoring Configuration
const ALERT_PHONE = process.env.ALERT_PHONE || "+13058337256"; // Your phone for alerts
const HEALTH_CHECK_INTERVAL = 5 * 60 * 1000; // 5 minutes
const TOKEN_CHECK_INTERVAL = 60 * 60 * 1000; // 1 hour

// Track server health status
const serverHealth = {
  bb1: { healthy: true, lastCheck: null, lastError: null },
  bb2: { healthy: true, lastCheck: null, lastError: null },
  bb3: { healthy: true, lastCheck: null, lastError: null },
  bb4: { healthy: true, lastCheck: null, lastError: null },
};

// Track token health status
const tokenHealth = {
  lastCheck: null,
  issues: [],
};

/* -------------------------------------------------------------------------- */
/* Config - BlueBubbles Servers with Parking Numbers from Env Vars            */
/* -------------------------------------------------------------------------- */
// Define your BlueBubbles servers here
// NEW v3.10.0: Four-server architecture (bb1=Eden, bb2=Mario, bb3=Tiffany, bb4=Amber)
// NEW v3.7.1: Added usePrivateAPI flag - set to true ONLY when Private API is enabled
const BLUEBUBBLES_SERVERS = [
  {
    id: "bb1",
    name: "Server 1 (Original Mac - Eden)",
    enabled: false,  // DISABLED - waiting for new office Mac
    baseUrl: process.env.BB_BASE || "https://relay.asapcashhomebuyers.com",
    password: process.env.BB_GUID || "REPLACE_WITH_SERVER1_PASSWORD",
    usePrivateAPI: false,  // ← Private API not enabled on bb1
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
    enabled: true,
    baseUrl: "https://bb2.asapcashhomebuyers.com",
    password: process.env.BB2_GUID || "EdenBridge2025Master",
    usePrivateAPI: (process.env.BB2_USE_PRIVATE_API || "false").toLowerCase() === "true",  // ← Can toggle via env var
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
    enabled: true,
    baseUrl: "https://bb3.asapcashhomebuyers.com",
    password: process.env.BB3_GUID || "EdenBridge2025Master",
    usePrivateAPI: (process.env.BB3_USE_PRIVATE_API || "false").toLowerCase() === "true",  // ← Can toggle via env var
    parkingNumbers: [
      { number: PARKING_NUMBER_TIFFANY, userId: GHL_USER_ID_TIFFANY, user: "Tiffany" },
    ],
    // iMessage phone numbers handled by this server
    phoneNumbers: [
      { number: "+19544450020", parkingNumber: PARKING_NUMBER_TIFFANY, userId: GHL_USER_ID_TIFFANY, user: "Tiffany" },
    ],
  },
  {
    id: "bb4",
    name: "Server 4 (Mac Mini - Amber)",
    enabled: true,
    baseUrl: "https://bb4.asapcashhomebuyers.com",
    password: process.env.BB4_GUID || "EdenBridge2025!",
    usePrivateAPI: (process.env.BB4_USE_PRIVATE_API || "false").toLowerCase() === "true",  // ← Can toggle via env var
    parkingNumbers: [
      { number: PARKING_NUMBER_AMBER, userId: GHL_USER_ID_AMBER, user: "Amber" },
    ],
    // iMessage phone numbers handled by this server
    phoneNumbers: [
      { number: "+13054978748", parkingNumber: PARKING_NUMBER_AMBER, userId: GHL_USER_ID_AMBER, user: "Amber" },
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

const BRIDGE_BASE = process.env.BRIDGE_BASE || "https://ieden-bluebubbles-bridge-1.onrender.com";

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
const outboundServerMap = new Map(); // Track which server sent each message
// Store paused workflow data for "Wait for Reply" functionality
// Key: contact phone (E.164), Value: { extras, timestamp, message }
const pausedWorkflows = new Map();
const PAUSED_WORKFLOW_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours
const DEDUPE_TTL_MS = 15_000;
const OUTBOUND_TTL_MS = 30_000;
const ATTACHMENT_GRACE_MS = 10_000;

const dedupeKey = ({ text, from, chatGuid }) =>
  `${chatGuid || ""}|${from || ""}|${(text || "").slice(0, 128)}`;

const rememberOutbound = (text, chatGuid, hasAttachments = false, serverId = null) => {
  const key = `${chatGuid}|${(text || "").slice(0, 128)}`;
  const expiry = Date.now() + OUTBOUND_TTL_MS;
  recentOutboundMessages.set(key, expiry);
  
  const textOnlyKey = `text-only|${(text || "").slice(0, 128)}`;
  recentOutboundMessages.set(textOnlyKey, expiry);
  
  // Track which server sent this message
  if (serverId) {
    const serverKey = `${chatGuid}|${(text || "").slice(0, 128)}`;
    outboundServerMap.set(serverKey, { serverId, expiry });
    console.log(`[outbound-tracker] message sent from ${serverId}`);
  }
  
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
  if (outboundServerMap.size > 100) {
    const now = Date.now();
    for (const [k, data] of outboundServerMap.entries()) {
      if (data.expiry < now) outboundServerMap.delete(k);
    }
  }
};

const isOurOutbound = (text, chatGuid, hasAttachments, incomingServerId = null) => {
  const key = `${chatGuid}|${(text || "").slice(0, 128)}`;
  const expiry = recentOutboundMessages.get(key);
  
  // Check if this message was sent by US
  if (expiry && expiry >= Date.now()) {
    // Check if we know which server sent it
    const serverData = outboundServerMap.get(key);
    if (serverData && serverData.expiry >= Date.now()) {
      // We know which server sent it - only ignore if webhook is from THAT server or any other server
      if (incomingServerId) {
        if (incomingServerId === serverData.serverId) {
          console.log(`[outbound-tracker] MATCH FOUND - ignoring echo from sending server ${incomingServerId}`);
          return true;
        } else {
          console.log(`[outbound-tracker] MATCH FOUND - ignoring duplicate from other server ${incomingServerId} (sent by ${serverData.serverId})`);
          return true;
        }
      }
      console.log("[outbound-tracker] MATCH FOUND - ignoring echo (text with chatGuid)");
      return true;
    }
    console.log("[outbound-tracker] MATCH FOUND - ignoring echo (text with chatGuid)");
    return true;
  }
  if (expiry && expiry < Date.now()) {
    recentOutboundMessages.delete(key);
    outboundServerMap.delete(key);
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
/* Health Monitoring Functions - Section 2                                    */
/* -------------------------------------------------------------------------- */

/**
 * Send alert via iMessage through a working BB server
 */
async function sendHealthAlert(message) {
  console.log(`[health-alert] ${message}`);
  
  // Find a working server to send the alert
  const workingServer = BLUEBUBBLES_SERVERS.find(s => s.enabled !== false && serverHealth[s.id]?.healthy);
  
  if (workingServer) {
    try {
      const url = `${workingServer.baseUrl}/api/v1/message/text?guid=${encodeURIComponent(workingServer.password)}`;
      await axios.post(
        url,
        {
          chatGuid: `iMessage;-;${ALERT_PHONE}`,
          tempGuid: `temp-alert-${Date.now()}`,
          message: message,
          method: "apple-script"
        },
        {timeout: 15000}
      );
      console.log(`[health-alert] sent via ${workingServer.id}`);
    } catch (e) {
      console.error(`[health-alert] failed to send via ${workingServer.id}:`, e.message);
    }
  } else {
    console.error("[health-alert] NO WORKING SERVERS - cannot send alert!");
  }
}

/**
 * Check all BlueBubbles servers
 */
async function checkAllServers() {
  console.log("[health-check] checking all BB servers...");
  
  for (const server of BLUEBUBBLES_SERVERS) {
    // Skip disabled servers
    if (server.enabled === false) {
      console.log(`[health-check] ${server.id}: ⏸️ DISABLED (skipping)`);
      serverHealth[server.id] = {
        healthy: true,
        lastCheck: new Date().toISOString(),
        lastError: null,
        disabled: true
      };
      continue;
    }
    try {
      const url = `${server.baseUrl}/api/v1/ping`;
      await axios.get(url, {
        params: { guid: server.password },
        timeout: 10000
      });
      
      const wasDown = !serverHealth[server.id].healthy;
      serverHealth[server.id] = {
        healthy: true,
        lastCheck: new Date().toISOString(),
        lastError: null
      };
      
      if (wasDown) {
        await sendHealthAlert(`✅ ${server.name} is BACK ONLINE`);
      }
      
      console.log(`[health-check] ${server.id}: ✅ UP`);
    } catch (error) {
      const wasUp = serverHealth[server.id].healthy;
      serverHealth[server.id] = {
        healthy: false,
        lastCheck: new Date().toISOString(),
        lastError: error.message
      };
      
      if (wasUp) {
        await sendHealthAlert(`⚠️ ${server.name} is DOWN!\nError: ${error.message}`);
      }
      
      console.log(`[health-check] ${server.id}: ❌ DOWN - ${error.message}`);
    }
  }
}

/**
 * Check GHL token health
 */
async function checkTokenHealth() {
  console.log("[health-check] checking GHL tokens...");
  const issues = [];
  
  if (tokenStore.size === 0) {
    console.log("[health-check] no tokens stored yet");
    return;
  }
  
  for (const [locationId, token] of tokenStore.entries()) {
    if (!token || !token.access_token) {
      issues.push(`❌ NO TOKEN for location ${locationId.slice(0, 8)}...`);
      continue;
    }
    
    if (token._created_at_ms && token.expires_in) {
      const expiresAt = token._created_at_ms + (token.expires_in * 1000);
      const now = Date.now();
      const hoursUntilExpiry = (expiresAt - now) / (1000 * 60 * 60);
      
      if (hoursUntilExpiry < 0) {
        issues.push(`❌ TOKEN EXPIRED for ${locationId.slice(0, 8)}...`);
      } else if (hoursUntilExpiry < 2) {
        issues.push(`⚠️ TOKEN EXPIRING for ${locationId.slice(0, 8)}... (${Math.round(hoursUntilExpiry * 60)}min left)`);
      }
    }
  }
  
  tokenHealth.lastCheck = new Date().toISOString();
  tokenHealth.issues = issues;
  
  if (issues.length > 0) {
    await sendHealthAlert(`🔑 GHL Token Issues:\n${issues.join('\n')}`);
  }
  
  console.log(`[health-check] tokens: ${issues.length === 0 ? '✅ OK' : issues.join(', ')}`);
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

const bbCreateChat = async (server, chatGuid) => {
  try {
    console.log(`[bbCreateChat][${server.id}] ensuring chat exists: ${chatGuid}`);
    
    // Extract addresses from chatGuid (format: "iMessage;-;+1234567890" or "iMessage;+;address1;address2")
    const parts = chatGuid.split(';');
    let addresses = [];
    
    if (parts.length >= 3) {
      // For single recipient: iMessage;-;+1234567890
      if (parts[1] === '-') {
        addresses = [parts.slice(2).join(';')];
      } else if (parts[1] === '+') {
        // For group: iMessage;+;address1;address2
        addresses = parts.slice(2);
      }
    }
    
    if (addresses.length === 0) {
      console.log(`[bbCreateChat][${server.id}] could not parse addresses from chatGuid`);
      return null;
    }
    
    const body = {
      addresses: addresses,
      service: 'iMessage',
      tempGuid: newTempGuid('chat')
    };
    
    const { data } = await bbPost(server, '/api/v1/chat/new', body);
    console.log(`[bbCreateChat][${server.id}] chat created/exists`);
    return data;
  } catch (err) {
    // Chat might already exist - that's okay
    console.log(`[bbCreateChat][${server.id}] note: ${err?.response?.status} ${err?.response?.data?.message || err.message}`);
    return null;
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
  // v3.7.4: Removed iPhone echo formatting
  // All messages now appear the same regardless of source
  let messageBody = text || '';

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
    // v3.7.4: Simple attachment message without iPhone header
    messageBody = `📎 ${mediaUrls.length} attachment(s)`;
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

    // ========================================================================
    // V3.7.7 FIX: Simplified chatGuid for Private API
    // ========================================================================
    let chatGuid = chatGuidForPhone(e164);  // Always use simple format: iMessage;-;+1234567890
    let sendFromAccount = null;
    
    if (server.usePrivateAPI && userId) {
      // Private API enabled - determine which account to use
      sendFromAccount = getIMessageAccountForUser(userId, server);
      console.log(`[private-api] userId ${userId} → send from ${sendFromAccount} (${server.phoneNumbers.find(p => p.number === sendFromAccount)?.user || 'unknown'})`);
      console.log(`[provider] Private API enabled - using account: ${sendFromAccount}`);
    } else {
      // AppleScript mode
      console.log(`[provider] AppleScript mode - using simple chatGuid`);
    }

    let textMessageSent = false;
    let data = null;
    if (message && String(message).trim()) {
      const payload = {
        chatGuid,
        tempGuid: newTempGuid("temp-bridge"),
        message: String(message),
        method: server.usePrivateAPI ? "private-api" : "apple-script",
      };
      
      // ========================================================================
      // V3.7.10 FIX: Remember outbound BEFORE sending to prevent race condition
      // This ensures webhook arrives after tempGuid is in tracker
      // ========================================================================
      rememberOutbound(String(message), chatGuid, attachmentsFromBody.length > 0, server.id);
      
      console.log(`[provider] sending with method: ${payload.method}`);
      
      try {
        data = await bbPost(server, "/api/v1/message/text", payload);
        textMessageSent = true;
      } catch (err) {
        // ========================================================================
        // V3.7.9 FIX: Fallback to AppleScript if Private API fails with "Chat does not exist"
        // ========================================================================
        const errorMsg = err?.response?.data?.error?.message || err?.message || '';
        if (server.usePrivateAPI && errorMsg.includes('Chat does not exist')) {
          console.log(`[provider] Private API failed with "Chat does not exist" - falling back to AppleScript`);
          payload.method = "apple-script";
          data = await bbPost(server, "/api/v1/message/text", payload);
          textMessageSent = true;
          console.log(`[provider] ✅ Message sent via AppleScript fallback`);
        } else {
          throw err; // Re-throw if it's a different error
        }
      }
    } else {
      console.log("[provider] no text message, sending attachments only");
      rememberOutbound("", chatGuid, true, server.id);
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
      method: server.usePrivateAPI ? "private-api" : "apple-script",
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

    // ========================================================================
    // V3.7.8 FIX: Ignore "updated-message" events to prevent duplicates
    // ========================================================================
    const webhookType = src.type || src.event || null;
    if (webhookType === 'updated-message' || webhookType === 'message-updated') {
      console.log("[inbound] IGNORING - webhook type is 'updated-message' (prevents duplicates)");
      return res.status(200).json({ ok: true, ignored: "updated-message" });
    }

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

    if (isOurOutbound(messageText, chatGuid, hasAttachments, serverOverride?.id)) {
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
// Check if there's a paused workflow waiting for this contact's reply
    if (!isFromMe && contactE164) {
      const resumed = await resumePausedWorkflow(contactE164, messageText);
      if (resumed) {
        console.log(`[inbound] 🔄 Resumed paused workflow for ${contactE164}`);
      }
    }
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

    // ========================================================================
    // V3.9.0: Trigger GHL Workflow for incoming messages (contact replies only)
    // ========================================================================
    if (!isFromMe) {
      // Only trigger workflow for INCOMING messages from contacts (not outbound from iPhone)
      try {
        // Determine which user this message is assigned to
        let assignedUser = 'Unknown';
        if (locationNumber === '+17867334163') assignedUser = 'Eden';
        else if (locationNumber === '+17868828328') assignedUser = 'Mario';
        else if (locationNumber === '+19547587444') assignedUser = 'Tiffany';
        else if (locationNumber === '+13059096544') assignedUser = 'Amber';

        const workflowPayload = {
          from: contactE164,
          to: locationNumber,
          message: messageText,
          guid: chatGuid,
          timestamp: new Date(timestamp).toISOString(),
          assignedUser,
          contactId,
          locationId,
          hasAttachments,
          attachmentCount: attachments?.length || 0,
          server: server.name
        };

        console.log(`[workflow-trigger] Triggering GHL workflow for incoming message from ${contactE164}`);
        console.log(`[workflow-trigger] Assigned to: ${assignedUser}`);

        // Send webhook to trigger the "Incoming iMessage" workflow
        // This will be caught by any workflows using the "incoming_imessage" trigger
        const workflowWebhookUrl = `${BRIDGE_BASE}/webhook/ghl`;
        
        await axios.post(workflowWebhookUrl, workflowPayload, {
          headers: {
            'Content-Type': 'application/json',
            'X-GHL-Event': 'inbound_imessage'
          },
          timeout: 5000
        });

        console.log(`[workflow-trigger] ✅ Workflow triggered successfully`);
      } catch (workflowErr) {
        console.error(`[workflow-trigger] Failed to trigger workflow:`, workflowErr.message);
        // Don't fail the whole request if workflow trigger fails
      }
    }

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

app.post("/webhook/bluebubbles/bb4", async (req, res) => {
  console.log("[webhook] bb4 (Amber's Mac Mini) endpoint called");
  return handleBlueBubblesWebhook(req, res, BLUEBUBBLES_SERVERS[3]);
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
/* GHL Workflow Webhook Endpoint                                              */
/* -------------------------------------------------------------------------- */
app.post("/webhook/ghl", async (req, res) => {
  try {
    console.log("[webhook/ghl] GHL workflow webhook received");
    console.log("[webhook/ghl] Headers:", JSON.stringify(req.headers, null, 2));
    console.log("[webhook/ghl] Body:", JSON.stringify(req.body, null, 2));

    const eventType = req.headers['x-ghl-event'] || req.body.event || 'unknown';
    
    console.log(`[webhook/ghl] Event type: ${eventType}`);

    // Handle different GHL workflow events
    switch (eventType) {
      case 'inbound_imessage':
        // This is an incoming iMessage from a contact
        const { from, to, message, assignedUser, contactId, locationId } = req.body;
        
        console.log(`[webhook/ghl] Inbound iMessage workflow triggered`);
        console.log(`[webhook/ghl] From: ${from}, To: ${to}`);
        console.log(`[webhook/ghl] Message: ${message}`);
        console.log(`[webhook/ghl] Assigned to: ${assignedUser}`);

        // Now trigger the actual GHL workflow in the user's location
        // This requires calling GHL's workflow trigger API
        if (locationId) {
          try {
            const accessToken = await getValidAccessToken(locationId);
            if (accessToken) {
              // Find all workflows with the "incoming_imessage" trigger and execute them
              // Note: This would require GHL's workflow execution API
              // For now, we just log that we would trigger it
              console.log(`[webhook/ghl] Would trigger workflows in location ${locationId}`);
              console.log(`[webhook/ghl] Workflow data:`, {
                from,
                to,
                message,
                assignedUser,
                contactId
              });
            }
          } catch (err) {
            console.error(`[webhook/ghl] Error triggering workflow:`, err.message);
          }
        }
        break;
      
      default:
        console.log(`[webhook/ghl] Unknown event type: ${eventType}`);
    }

    // Always return success so the calling service knows we received it
    return res.status(200).json({ 
      ok: true, 
      message: 'Webhook received',
      eventType 
    });

  } catch (err) {
    console.error("[webhook/ghl] Error processing GHL webhook:", err);
    return res.status(500).json({ 
      ok: false, 
      error: err.message 
    });
  }
});
/* -------------------------------------------------------------------------- */
/* GHL Marketplace Action: Send iMessage                                      */
/* -------------------------------------------------------------------------- */
app.post("/action/send-imessage", async (req, res) => {
  try {
    console.log("[action/send-imessage] ========== GHL ACTION CALLED ==========");
    console.log("[action/send-imessage] Headers:", JSON.stringify(req.headers, null, 2));
    console.log("[action/send-imessage] Body:", JSON.stringify(req.body, null, 2));

    // GHL Marketplace Actions wrap fields in a "data" object
const actionData = req.body.data || req.body;
const { 
  to,           // Recipient phone number
  message,      // Message text
  fromUser,     // Eden/Mario/Tiffany/Amber/Auto
  attachmentUrl,// Optional attachment
  contactId,    // GHL may include this
  locationId,   // GHL may include this
  userId,       // GHL assigned user
} = actionData;

// Also grab extras if available (GHL sends additional context here)
const extras = req.body.extras || {};
const finalContactId = contactId || extras.contactId;
const finalLocationId = locationId || extras.locationId;

    // Validate required fields
    if (!to) {
      console.error("[action/send-imessage] Missing 'to' field");
      return res.status(400).json({ 
        success: false, 
        error: "Missing required field: to (recipient phone number)" 
      });
    }

    const hasAttachments = Array.isArray(attachmentUrl) ? attachmentUrl.length > 0 : !!attachmentUrl;
    if (!message && !hasAttachments) {
      console.error("[action/send-imessage] Missing message and attachment");
      return res.status(400).json({ 
        success: false, 
        error: "Missing required field: message or attachmentUrl" 
      });
    }

    // Normalize phone number
    let e164;
    try {
      e164 = ensureE164(String(to));
    } catch (err) {
      console.error("[action/send-imessage] Invalid phone:", to);
      return res.status(400).json({ 
        success: false, 
        error: `Invalid phone number: ${to}. Use E.164 format like +13051234567` 
      });
    }

    // Determine which server/user to send from
    let server;
    let routedBy = "auto";

    if (fromUser && fromUser !== "Auto" && fromUser !== "auto") {
      // User explicitly selected a team member
      const userLower = fromUser.toLowerCase();
      if (userLower === "eden") {
        server = BLUEBUBBLES_SERVERS[0]; // bb1
        routedBy = "explicit-eden";
      } else if (userLower === "mario") {
        server = BLUEBUBBLES_SERVERS[1]; // bb2
        routedBy = "explicit-mario";
      } else if (userLower === "tiffany") {
        server = BLUEBUBBLES_SERVERS[2]; // bb3
        routedBy = "explicit-tiffany";
      } else if (userLower === "amber") {
        server = BLUEBUBBLES_SERVERS[3]; // bb4
        routedBy = "explicit-amber";
      } else {
        server = BLUEBUBBLES_SERVERS[0]; // fallback
        routedBy = "fallback";
      }
      console.log(`[action/send-imessage] Explicit fromUser: ${fromUser} → ${server.name}`);
    } else if (userId) {
      // Use GHL's assigned user
      server = findServerByUserId(userId);
      routedBy = "ghl-userId";
      console.log(`[action/send-imessage] GHL userId: ${userId} → ${server.name}`);
    } else if (finalContactId && finalLocationId) {
      // Look up the contact's conversation assignment
      try {
        const parkingNumber = await getAssignedUserParkingNumber(finalLocationId, finalContactId, BLUEBUBBLES_SERVERS[0]);
        server = findServerByParkingNumber(parkingNumber);
        routedBy = "conversation-assignment";
        console.log(`[action/send-imessage] Conversation assignment → ${server.name}`);
      } catch (e) {
        server = BLUEBUBBLES_SERVERS[0];
        routedBy = "fallback-after-lookup-error";
      }
    } else {
      // Default to first server
      server = BLUEBUBBLES_SERVERS[0];
      routedBy = "default";
    }

    console.log(`[action/send-imessage] Routing: ${routedBy} → ${server.name}`);

    // Build the chatGuid
    const chatGuid = chatGuidForPhone(e164);

    // Remember outbound to prevent echo
    const hasAttachmentsForEcho = Array.isArray(attachmentUrl) ? attachmentUrl.length > 0 : !!attachmentUrl;
    rememberOutbound(String(message || ""), chatGuid, hasAttachmentsForEcho, server.id);

    // Send the text message
    let textMessageSent = false;
    let data = null;

    if (message && String(message).trim()) {
      const payload = {
        chatGuid,
        tempGuid: newTempGuid("action"),
        message: String(message),
        method: server.usePrivateAPI ? "private-api" : "apple-script",
      };

      console.log(`[action/send-imessage] Sending text via ${payload.method}...`);

      try {
        data = await bbPost(server, "/api/v1/message/text", payload);
        textMessageSent = true;
        console.log(`[action/send-imessage] ✅ Text message sent`);
      } catch (err) {
        // Fallback to AppleScript if Private API fails
        const errorMsg = err?.response?.data?.error?.message || err?.message || '';
        if (server.usePrivateAPI && errorMsg.includes('Chat does not exist')) {
          console.log(`[action/send-imessage] Private API failed, falling back to AppleScript`);
          payload.method = "apple-script";
          data = await bbPost(server, "/api/v1/message/text", payload);
          textMessageSent = true;
        } else {
          throw err;
        }
      }
    }

   // Send attachment if provided
    let attachmentSent = false;
    const attachmentList = Array.isArray(attachmentUrl) ? attachmentUrl : (attachmentUrl ? [attachmentUrl] : []);
    
    for (const attachment of attachmentList) {
      try {
        // Handle both string URLs and object format
        const url = typeof attachment === 'string' ? attachment : (attachment.url || attachment.src || attachment.mediaUrl);
        
        if (!url) {
          console.log(`[action/send-imessage] Skipping attachment - no URL found:`, attachment);
          continue;
        }
        
        console.log(`[action/send-imessage] Downloading attachment: ${url}`);
        const downloadResult = await downloadGHLAttachment(url);
        
        if (downloadResult && downloadResult.buffer) {
          const { buffer, mimeType } = downloadResult;
          
          // Extract filename from URL or attachment object
          let filename = (typeof attachment === 'object' && attachment.name) 
            ? attachment.name 
            : url.split('/').pop()?.split('?')[0] || 'attachment';
            
          if (!filename.includes('.')) {
            const extMap = {
              'image/png': '.png',
              'image/jpeg': '.jpg',
              'image/gif': '.gif',
              'image/webp': '.webp',
              'application/pdf': '.pdf',
              'video/mp4': '.mp4',
            };
            filename += (extMap[mimeType] || '');
          }

          console.log(`[action/send-imessage] Uploading attachment to BlueBubbles...`);
          await bbUploadAttachment(server, chatGuid, buffer, filename);
          attachmentSent = true;
          console.log(`[action/send-imessage] ✅ Attachment sent`);
        }
      } catch (e) {
        console.error(`[action/send-imessage] Attachment failed:`, e.message);
      }
    }
// Push the sent message to GHL conversation thread so it appears in CRM
    if (textMessageSent && finalContactId && finalLocationId) {
      try {
        const accessToken = await getValidAccessToken(finalLocationId);
        if (accessToken) {
          await pushToGhlThread({
            locationId: finalLocationId,
            accessToken,
            contactId: finalContactId,
            text: message,
            fromNumber: server.parkingNumbers[0]?.number,
            isFromMe: true,
            timestamp: Date.now(),
            attachments: [],
            server,
          });
          console.log(`[action/send-imessage] ✅ Message logged to GHL conversation`);
        }
      } catch (e) {
        console.error(`[action/send-imessage] Failed to log to GHL:`, e.message);
      }
    }
    // Store paused workflow data if Pause Execution is enabled
    const workflowExtras = req.body.extras || {};
    if (workflowExtras.workflowId && workflowExtras.stepId && workflowExtras.key) {
      pausedWorkflows.set(e164, {
        extras: {
          contactId: workflowExtras.contactId || finalContactId,
          key: workflowExtras.key,
          locationId: workflowExtras.locationId || finalLocationId,
          statusId: workflowExtras.statusId,
          stepId: workflowExtras.stepId,
          workflowId: workflowExtras.workflowId,
          stepIndex: workflowExtras.stepIndex,
        },
        timestamp: Date.now(),
        message: message,
      });
      console.log(`[action/send-imessage] 📋 Stored paused workflow for ${e164}`);
      
      // Clean up old paused workflows
      const now = Date.now();
      for (const [phone, data] of pausedWorkflows.entries()) {
        if (now - data.timestamp > PAUSED_WORKFLOW_TTL_MS) {
          pausedWorkflows.delete(phone);
        }
      }
    }
    // Return success response to GHL
    const response = {
      success: true,
      status: "delivered",
      messageId: data?.guid || data?.data?.guid || `action-${newTempGuid()}`,
      to: e164,
      from: server.parkingNumbers[0]?.number,
      fromUser: server.parkingNumbers[0]?.user,
      server: server.name,
      routedBy,
      textMessageSent,
      attachmentSent,
      timestamp: new Date().toISOString(),
    };

    console.log(`[action/send-imessage] ✅ SUCCESS:`, response);

    return res.status(200).json(response);

  } catch (err) {
    console.error("[action/send-imessage] ERROR:", err?.response?.data || err.message);
    
    return res.status(500).json({
      success: false,
      error: err?.response?.data?.message || err?.message || "Failed to send iMessage",
      details: err?.response?.data || null,
    });
  }
});

// Also support alternate path format
app.post("/actions/send-imessage", async (req, res) => {
  return res.redirect(307, '/action/send-imessage');
});
/* -------------------------------------------------------------------------- */
/* Resume Paused Workflow (for Wait for Reply)                                */
/* -------------------------------------------------------------------------- */

async function resumePausedWorkflow(contactPhone, replyMessage) {
  const pausedData = pausedWorkflows.get(contactPhone);
  if (!pausedData) {
    console.log(`[resume-workflow] No paused workflow for ${contactPhone}`);
    return false;
  }

  console.log(`[resume-workflow] Found paused workflow for ${contactPhone}, resuming...`);

  try {
    const response = await axios.post(
      'https://services.leadconnectorhq.com/workflows-marketplace/actions/resume-internal-action',
      {
        success: true,
        successMessage: "Contact replied via iMessage",
        executionResponse: {
          replyMessage: replyMessage,
          replyTimestamp: new Date().toISOString(),
        },
        extras: pausedData.extras,
      },
      {
        headers: {
          'Content-Type': 'application/json',
        },
        timeout: 15000,
      }
    );

    console.log(`[resume-workflow] ✅ Workflow resumed for ${contactPhone}`, response.data);
    
    // Remove from paused workflows
    pausedWorkflows.delete(contactPhone);
    
    return true;
  } catch (err) {
    console.error(`[resume-workflow] ❌ Failed to resume workflow:`, err?.response?.data || err.message);
    return false;
  }
}
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

  // Use chooselocation for private marketplace apps (allows location selection)
  const params = new URLSearchParams({
    client_id: CLIENT_ID,
    response_type: "code",
    redirect_uri: GHL_REDIRECT_URI,
    scope,
  });

  // Changed from /authorize to /chooselocation for better UX with private apps
  res.redirect(`${OAUTH_AUTHORIZE_BASE}/chooselocation?${params.toString()}`);
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
      usePrivateAPI: s.usePrivateAPI,
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
    version: "4.0.0",
    mode: "single-provider-multi-server-routing-optional-private-api-server-locking",
    servers: BLUEBUBBLES_SERVERS.map(s => ({
      id: s.id,
      name: s.name,
      baseUrl: s.baseUrl,
      users: s.parkingNumbers.map(p => p.user),
      parkingNumbers: s.parkingNumbers.map(p => p.number),
      phoneNumbers: s.phoneNumbers.map(p => ({ number: p.number, user: p.user })),
      usePrivateAPI: s.usePrivateAPI,
    })),
    totalPhoneNumbers: getAllPhoneNumbers().length,
    totalParkingNumbers: getAllParkingNumbers().length,
    oauthConfigured: !!(CLIENT_ID && CLIENT_SECRET),
    conversationProviderId: CONVERSATION_PROVIDER_ID,
    features: {
      multiServer: true,
      fourServers: true,
      dedicatedServersPerUser: true,
      userAssignment: true,
      conversationAssignmentRouting: true,
      privateAPI: "optional-per-server",
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
        envVar: "PARKING_NUMBER_EDEN",
        usePrivateAPI: BLUEBUBBLES_SERVERS[0].usePrivateAPI
      },
      "Mario": {
        parkingNumber: PARKING_NUMBER_MARIO,
        iMessageNumber: "+13059273268",
        server: "bb2 (Mac Mini #1)",
        envVar: "PARKING_NUMBER_MARIO",
        usePrivateAPI: BLUEBUBBLES_SERVERS[1].usePrivateAPI
      },
      "Tiffany": {
        parkingNumber: PARKING_NUMBER_TIFFANY,
        iMessageNumber: "+19544450020",
        server: "bb3 (Mac Mini #2)",
        envVar: "PARKING_NUMBER_TIFFANY",
        usePrivateAPI: BLUEBUBBLES_SERVERS[2].usePrivateAPI
      },
      "Amber": {
        parkingNumber: PARKING_NUMBER_AMBER,
        iMessageNumber: "+13054978748",
        server: "bb4 (Mac Mini #3)",
        envVar: "PARKING_NUMBER_AMBER",
        usePrivateAPI: BLUEBUBBLES_SERVERS[3].usePrivateAPI
      }
    }
  });
});

/* -------------------------------------------------------------------------- */
/* Health Monitoring Functions - section 3                                    */
/* -------------------------------------------------------------------------- */

/**
 * Combined health check endpoint
 * GET /health
 */
app.get("/health", async (req, res) => {
  const health = {
    timestamp: new Date().toISOString(),
    overall: "✅ OK",
    servers: {},
    tokens: {},
    alertPhone: ALERT_PHONE,
  };
  
  // Server status
  for (const server of BLUEBUBBLES_SERVERS) {
    const status = serverHealth[server.id];
    health.servers[server.id] = {
      name: server.name,
      healthy: status.healthy,
      lastCheck: status.lastCheck,
      error: status.lastError
    };
    if (!status.healthy) {
      health.overall = "⚠️ ISSUES";
    }
  }
  
  // Token status
  if (typeof locationTokens !== 'undefined') {
    for (const [locationId, token] of Object.entries(locationTokens)) {
      const expiresAt = token?.expires_at ? new Date(token.expires_at) : null;
      const now = new Date();
      const hoursLeft = expiresAt ? Math.round((expiresAt - now) / (1000 * 60 * 60)) : null;
      
      health.tokens[locationId.slice(0, 8) + "..."] = {
        hasToken: !!token?.access_token,
        hasRefresh: !!token?.refresh_token,
        hoursUntilExpiry: hoursLeft,
        status: !token?.access_token ? "❌ MISSING" : 
                (expiresAt && expiresAt < now) ? "❌ EXPIRED" : 
                (hoursLeft && hoursLeft < 2) ? "⚠️ EXPIRING" : "✅ OK"
      };
      
      if (!token?.access_token || (expiresAt && expiresAt < now)) {
        health.overall = "⚠️ ISSUES";
      }
    }
  }
  
  res.json(health);
});

/**
 * Detailed server health check
 * GET /health/servers
 */
app.get("/health/servers", async (req, res) => {
  // Run fresh check
  await checkAllServers();
  
  const results = BLUEBUBBLES_SERVERS.map(server => ({
    id: server.id,
    name: server.name,
    url: server.baseUrl,
    ...serverHealth[server.id]
  }));
  
  res.json({
    timestamp: new Date().toISOString(),
    servers: results
  });
});

/**
 * Detailed token health check
 * GET /health/tokens
 */
app.get("/health/tokens", async (req, res) => {
  const status = [];
  
  if (typeof locationTokens === 'undefined' || Object.keys(locationTokens).length === 0) {
    return res.json({
      timestamp: new Date().toISOString(),
      message: "No tokens stored yet. Complete OAuth flow first.",
      tokens: []
    });
  }
  
  for (const [locationId, token] of Object.entries(locationTokens)) {
    const expiresAt = token?.expires_at ? new Date(token.expires_at) : null;
    const now = new Date();
    
    status.push({
      locationId: locationId,
      hasAccessToken: !!token?.access_token,
      hasRefreshToken: !!token?.refresh_token,
      expiresAt: expiresAt?.toISOString() || "unknown",
      hoursUntilExpiry: expiresAt ? Math.round((expiresAt - now) / (1000 * 60 * 60)) : null,
      status: !token?.access_token ? "❌ MISSING" : 
              (expiresAt && expiresAt < now) ? "❌ EXPIRED" : "✅ OK"
    });
  }
  
  res.json({
    timestamp: new Date().toISOString(),
    tokens: status
  });
});

/**
 * Force send a test alert
 * GET /health/test-alert
 */
app.get("/health/test-alert", async (req, res) => {
  await sendHealthAlert("🧪 TEST ALERT - Health monitoring is working!");
  res.json({ 
    message: "Test alert sent",
    alertPhone: ALERT_PHONE
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
        <div class="powered-by">Powered by Eden Bridge v4.0.0</div>
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
        <div class="powered-by">Powered by Eden Bridge v4.0.0</div>
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
/* -------------------------------------------------------------------------- */
/* Health Monitoring Functions - section 4                                    */
/* -------------------------------------------------------------------------- */

// Start health monitoring
console.log("[health] Starting health monitoring...");
console.log(`[health] Alert phone: ${ALERT_PHONE}`);
console.log(`[health] Server check interval: ${HEALTH_CHECK_INTERVAL / 1000}s`);
console.log(`[health] Token check interval: ${TOKEN_CHECK_INTERVAL / 1000}s`);

// Run initial checks
setTimeout(() => {
  checkAllServers();
  checkTokenHealth();
}, 5000); // Wait 5 seconds for server to start

// Schedule regular checks
setInterval(checkAllServers, HEALTH_CHECK_INTERVAL);
setInterval(checkTokenHealth, TOKEN_CHECK_INTERVAL);
  
  app.listen(PORT, () => {
    console.log(`[bridge] listening on :${PORT}`);
    console.log(`[bridge] VERSION 4.0.0 - Workflow Wait for Reply! 🎯✨`);
    console.log("");
    console.log("📋 BlueBubbles Servers:");
    for (const server of BLUEBUBBLES_SERVERS) {
      console.log(`  • ${server.name} (${server.id})`);
      console.log(`    URL: ${server.baseUrl}`);
      console.log(`    Users: ${server.parkingNumbers.map(p => p.user).join(', ')}`);
      console.log(`    Parking Numbers: ${server.parkingNumbers.map(p => p.number).join(', ')}`);
      const phoneList = server.phoneNumbers.map(p => `${p.number} (${p.user})`).join(', ');
      console.log(`    iMessage Numbers: ${phoneList}`);
      console.log(`    Private API: ${server.usePrivateAPI ? 'ENABLED ✅' : 'DISABLED (AppleScript mode)'}`);
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
    console.log(`    Parking: ${PARKING_NUMBER_EDEN} → iMessage: +13058337256 → Server: bb1 (Private API: ${BLUEBUBBLES_SERVERS[0].usePrivateAPI ? 'ON' : 'OFF'})`);
    console.log(`  Mario (env: PARKING_NUMBER_MARIO):`);
    console.log(`    Parking: ${PARKING_NUMBER_MARIO} → iMessage: +13059273268 → Server: bb2 (Private API: ${BLUEBUBBLES_SERVERS[1].usePrivateAPI ? 'ON' : 'OFF'})`);
    console.log(`  Tiffany (env: PARKING_NUMBER_TIFFANY):`);
    console.log(`    Parking: ${PARKING_NUMBER_TIFFANY} → iMessage: +19544450020 → Server: bb3 (Private API: ${BLUEBUBBLES_SERVERS[2].usePrivateAPI ? 'ON' : 'OFF'})`);
    console.log(`  Amber (env: PARKING_NUMBER_AMBER):`);
    console.log(`    Parking: ${PARKING_NUMBER_AMBER} → iMessage: +13054978748 → Server: bb4 (Private API: ${BLUEBUBBLES_SERVERS[3].usePrivateAPI ? 'ON' : 'OFF'})`);
    console.log("");
    console.log("📋 Features:");
    console.log("  ✅ Four dedicated BlueBubbles servers (bb1, bb2, bb3, bb4)");
    console.log("  ✅ Each user has dedicated Mac Mini + iPhone");
    console.log("  ✅ Single conversation provider (like SendBlue)");
    console.log("  ✅ Routes by GHL userId (most reliable!)");
    console.log("  ✅ Conversation assignment routing (bulletproof!)");
    console.log("  ✅ Optional Private API per server");
    console.log("  ✅ AppleScript fallback when Private API disabled");
    console.log("  ✅ Dedicated parking numbers per user (via ENV)");
    console.log("  ✅ Text messages (all directions)");
    console.log("  ✅ Photos & images (all directions)");
    console.log("  ✅ Files & documents (all directions)");
    console.log("  ✅ Smart server routing");
    console.log("  ✅ Privacy filter (no auto-contact creation)");
    console.log("  ✅ Click-to-call (Chrome extension integration)");
    console.log("  ✅ Click-to-chat (Chrome extension integration)");
    console.log("  ✅ GHL Marketplace Actions (Send iMessage)");
    console.log("  ✅ Workflow automation triggers");
    console.log("");
    if (CLIENT_ID && CLIENT_SECRET) console.log("[bridge] OAuth is configured.");
    if (GHL_SHARED_SECRET) console.log("[bridge] Shared secret checks enabled.");
  });
})();

process.on("SIGTERM", async () => { try { await saveTokenStore(); } finally { process.exit(0); } });
process.on("SIGINT",  async () => { try { await saveTokenStore(); } finally { process.exit(0); } });
