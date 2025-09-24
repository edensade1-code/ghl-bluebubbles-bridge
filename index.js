// index.js
import express from "express";
import fetch from "node-fetch";

const app = express();
app.use(express.json());

// ---------------------
// CONFIG (use env vars)
// ---------------------
const PORT      = process.env.PORT || 8787;
const API_KEY   = process.env.API_KEY || "change-me"; // Required header: x-api-key
const BB_BASE   = process.env.BB_BASE || "https://monday-relocation-considering-glance.trycloudflare.com";
const BB_GUID   = process.env.BB_GUID || "6k7nUHzHorFk4rXdEANi"; // this is your BlueBubbles server password

// simple auth
app.use((req, res, next) => {
  if (req.path === "/health") return next();
  if (req.headers["x-api-key"] !== API_KEY) {
    return res.status(401).json({ error: "unauthorized" });
  }
  next();
});

// health
app.get("/health", (_req, res) => res.json({ ok: true }));

// GHL -> SEND iMessage via BlueBubbles
// Body expected: { "to":"+1XXXXXXXXXX", "text":"hello" }
app.post("/send", async (req, res) => {
  try {
    const { to, text } = req.body || {};
    if (!to || !text) return res.status(400).json({ error: "missing to/text" });

    // BlueBubbles expects chatGuid like: iMessage;-;+1XXXXXXXXXX
    const payload = {
      chatGuid: `iMessage;-;${to}`,
      tempGuid: `temp-${Date.now()}`,
      message: text,
      method: "apple-script"
    };

    const url = `${BB_BASE}/api/v1/message/text?guid=${encodeURIComponent(BB_GUID)}`;
    const r = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });

    const data = await r.json().catch(() => ({}));
    return res.status(r.status).json(data);
  } catch (e) {
    return res.status(500).json({ error: e.message });
  }
});

// BlueBubbles -> inbound webhook (we’ll map to GHL later)
app.post("/inbound", async (req, res) => {
  // TODO: upsert contact + append conversation in GHL
  console.log("Inbound from BlueBubbles:", JSON.stringify(req.body));
  res.sendStatus(200);
});

app.listen(PORT, () => {
  console.log(`Bridge listening on :${PORT}`);
  console.log(`Expect header: x-api-key: ${API_KEY}`);
});

