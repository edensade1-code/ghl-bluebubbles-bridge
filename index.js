// index.js
import express from "express";

const app = express();
app.use(express.json());

// ⚙️ Env from Render
const BASE = process.env.BLUEBUBBLES_URL;   // e.g. https://organisations-canvas-surrounding-timer.trycloudflare.com
const PASS = process.env.BLUEBUBBLES_PASS;  // your BlueBubbles server password

// Health check
app.get("/health", (req, res) => {
  res.json({ ok: true, base: BASE || null });
});

// Send a message via BlueBubbles
app.post("/message/send", async (req, res) => {
  try {
    const { to, message } = req.body || {};
    if (!to || !message) {
      return res.status(400).json({ error: "`to` and `message` are required" });
    }
    if (!BASE || !PASS) {
      return res.status(500).json({ error: "Server not configured (missing BASE or PASS)" });
    }

    const url = `${BASE.replace(/\/+$/, "")}/api/v1/message/send`;

    const bbRes = await fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${PASS}`
      },
      body: JSON.stringify({
        address: to,        // BlueBubbles expects "address"
        message: message
      })
    });

    // Forward BlueBubbles result
    const text = await bbRes.text();
    let data;
    try { data = JSON.parse(text); } catch { data = { raw: text }; }

    if (!bbRes.ok) {
      return res.status(bbRes.status).json({
        error: "BlueBubbles error",
        status: bbRes.status,
        data
      });
    }

    return res.status(200).json({ ok: true, data });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Bridge failure", details: String(err) });
  }
});

const PORT = process.env.PORT || 10000;
app.listen(PORT, () => {
  console.log(`Bridge running on port ${PORT}`);
});
