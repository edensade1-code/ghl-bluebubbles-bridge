const express = require("express");
const axios = require("axios");

const app = express();
app.use(express.json());

const BLUEBUBBLES_URL = process.env.BLUEBUBBLES_URL;
const BLUEBUBBLES_PASS = process.env.BLUEBUBBLES_PASS;

app.get("/health", (req, res) => {
  res.json({ ok: true, base: BLUEBUBBLES_URL });
});

app.post("/send", async (req, res) => {
  try {
    const { to, message } = req.body || {};
    if (!to || !message) {
      return res.status(400).json({ error: "to and message required" });
    }

    const r = await axios.post(
      `${BLUEBUBBLES_URL}/api/v1/message/send?password=${encodeURIComponent(BLUEBUBBLES_PASS)}`,
      { address: to, message },
      { headers: { "Content-Type": "application/json" } }
    );
    res.json(r.data);
  } catch (e) {
    console.error(e.response?.data || e.message);
    res.status(500).json({ error: e.message, details: e.response?.data });
  }
});

app.post("/incoming", (req, res) => {
  console.log("INBOUND:", JSON.stringify(req.body));
  // TODO: forward inbound messages to GHL webhook here
  res.json({ ok: true });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Bridge running on port ${PORT}`));
