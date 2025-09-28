// index.js
// Tiny bridge between GHL (or anything) and your BlueBubbles relay.
// Use env vars: BB_BASE, BB_GUID, PORT, (optional) GHL_INBOUND_URL.

import express from "express";
import cors from "cors";
import helmet from "helmet";
import morgan from "morgan";
import axios from "axios";
import crypto from "crypto";

// ---------- Config ----------
const app = express();
app.use(express.json({ limit: "1mb" }));
app.use(cors());
app.use(helmet());
app.use(morgan("tiny"));

const BB_BASE =
  process.env.BB_BASE?.trim() ||
  "https://relay.asapcashhomebuyers.com"; // your permanent URL

const BB_GUID =
  process.env.BB_GUID?.trim() ||
  "REPLACE_WITH_BLUEBUBBLES_SERVER_PASSWORD"; // the server password you pass as ?guid=

const GHL_INBOUND_URL = process.env.GHL_INBOUND_URL?.trim() || ""; // optional – where to forward inbound BB events

const PORT = Number(process.env.PORT || 8080);

// Sanity check at boot
if (!BB_GUID || BB_GUID === "REPLACE_WITH_BLUEBUBBLES_SERVER_PASSWORD") {
  console.warn(
    "[WARN] BB_GUID is not set. Set the BlueBubbles server password via env."
  );
}

if (!GHL_INBOUND_URL) {
  console.log(
    "[bridge] GHL_INBOUND_URL not set. /webhook will log & 200 but not forward."
  );
}

// ---------- Helpers ----------
const newTempGuid = (prefix = "temp") =>
  `${prefix}-${crypto.randomBytes(6).toString("hex")}`;

const ensureE164 = (phone) => {
  // expects +1XXXXXXXXXX (US). Light normalization; adjust to your needs.
  if (!phone) throw new Error("Missing 'to' phone number");
  const p = String(phone).replace(/[^\d+]/g, "");
  if (!p.startsWith("+"))
    throw new Error("Phone must be in E.164 format (e.g. +13051234567)");
  return p;
};

const chatGuidForPhone = (e164) => `iMessage;-;${e164}`;

// Low-level BlueBubbles call
const bbPost = async (path, body) => {
  const url = `${BB_BASE}${path}?guid=${encodeURIComponent(BB_GUID)}`;
  const { data } = await axios.post(url, body, {
    headers: { "Content-Type": "application/json" },
    timeout: 15000,
  });
  return data;
};

// Optional: forward inbound events (from BlueBubbles) to GHL
const forwardToGhl = async (payload) => {
  if (!GHL_INBOUND_URL) return;
  try {
    await axios.post(GHL_INBOUND_URL, payload, {
      headers: { "Content-Type": "application/json" },
      timeout: 10000,
    });
  } catch (err) {
    console.error("[bridge] Failed to forward to GHL:", err?.message);
  }
};

// ---------- Routes ----------

// Root: simple landing
app.get("/", (_req, res) => {
  res.status(200).json({
    ok: true,
    name: "ghl-bluebubbles-bridge",
    relay: BB_BASE,
    inboundForward: !!GHL_INBOUND_URL,
  });
});

// Health for load balancers/Render/etc.
app.get("/health", async (_req, res) => {
  try {
    const pong = await axios.get(
      `${BB_BASE}/api/v1/ping?guid=${encodeURIComponent(BB_GUID)}`,
      { timeout: 8000 }
    );
    return res.status(200).json({
      ok: true,
      relay: BB_BASE,
      ping: pong.data ?? null,
    });
  } catch (e) {
    return res.status(503).json({
      ok: false,
      relay: BB_BASE,
      error: e?.response?.data ?? e?.message ?? "Ping failed",
    });
  }
});

// Simple send endpoint for GHL / webhooks
// Body: { to:"+1305...", message:"Hello world" }
app.post("/send", async (req, res) => {
  try {
    const { to, message } = req.body || {};
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

// Power-user passthrough (optional): POST raw to BlueBubbles
// Body is sent as-is, path string is required (e.g. "/api/v1/message/text")
app.post("/bb", async (req, res) => {
  try {
    const { path, body } = req.body || {};
    if (!path || typeof path !== "string" || !path.startsWith("/api/")) {
      return res
        .status(400)
        .json({ ok: false, error: "Provide valid 'path' starting with /api/" });
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

// ---------- NEW: BlueBubbles -> Bridge webhook receiver ----------
// Configure in BlueBubbles UI: API & Webhooks → Webhooks
// URL: https://<your-render-app>.onrender.com/webhook
// Subscribe at least to: “New Messages”, “Message Send Errors”
app.post("/webhook", async (req, res) => {
  try {
    // BB sends JSON. We'll ACK quickly, then (optionally) forward to GHL.
    const event = req.body || {};

    // Basic console audit
    const evtName =
      event?.event ||
      event?.type ||
      event?.name ||
      (event?.data?.message ? "new-message" : "webhook");
    console.log("[bridge] /webhook:", evtName);

    // Useful normalization for GHL (keep the full original too)
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

    // Fire & forget forwarding (if configured)
    forwardToGhl(normalized).catch(() => {});

    // Immediate ACK to BB
    return res.status(200).json({ ok: true });
  } catch (err) {
    console.error("[bridge] /webhook error:", err?.message);
    return res.status(200).json({ ok: true }); // keep BB happy
  }
});

// ---------- Start ----------
app.listen(PORT, () => {
  console.log(`[bridge] listening on :${PORT}`);
  console.log(`[bridge] BB_BASE = ${BB_BASE}`);
  if (GHL_INBOUND_URL) {
    console.log(`[bridge] Forwarding inbound BB events to ${GHL_INBOUND_URL}`);
  }
});
