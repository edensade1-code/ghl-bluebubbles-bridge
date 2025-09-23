// index.js
import express from "express";

const app = express();
app.use(express.json());

// env from Render
const BASE = process.env.BLUEBUBBLES_URL;   // e.g. https://organisations-canvas-surrounding-timer.trycloudflare.com
const PASS = process.env.BLUEBUBBLES_PASS;  // your BlueBubbles server password

// simple health
app.get("/health", (req, res) => {
  res.json({ ok: true, base: BASE ?? null });
});

// one function to forward to BlueBubbles
async function forwardToBlueBubbles(to, message) {
  if (!BASE || !PASS) {
    const err = new Error("Bridge not configured (missing BASE or PASS)");
    err.status = 500;
    throw err;
  }

  // ✅ Correct BlueBubbles endpoint (no /send)
  const baseTrimmed = BASE.replace(/\/+$/, "");
  const url = `${baseTrimmed}/api/v1/message?password=${encodeURIComponent(PASS)}`;

  const bbRes = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ address: to, message }), // BlueBubbles expects "address"
  });

  const raw = await bbRes.text();
  let data;
  try { data = JSON.parse(raw); } catch { data = { raw }; }

  if (!bbRes.ok) {
    const err = new Error("BlueBubbles error");
    err.status = bbRes.status;
    err.data = data;
    throw err;
  }
  return data;
}

// alias routes: /message/send and /send
async function handleSend(req, res) {
  try {
    const { to, message } = req.body || {};
    if (!to || !message) {
      return res.status(400).json({ error: "to and message required" });
    }
    const data = await forwardToBlueBubbles(to, message);
    return res.status(200).json({ ok: true, data });
  } catch (e) {
    const status = e.status || 500;
    return res.status(status).json({
      error: e.message || "Bridge failure",
      ...(e.data ? { data: e.data } : {}),
    });
  }
}

app.post("/message/send", handleSend);
app.post("/send", handleSend);

// start
const PORT = process.env.PORT || 10000;
app.listen(PORT, () => {
  console.log(`Bridge running on port ${PORT}`);
});
