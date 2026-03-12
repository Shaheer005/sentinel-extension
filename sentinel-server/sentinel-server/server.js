require("dotenv").config();
const express   = require("express");
const cors      = require("cors");
const helmet    = require("helmet");
const rateLimit = require("express-rate-limit");
const crypto    = require("crypto");

const app  = express();
const PORT = process.env.PORT || 3000;

app.use(helmet());
app.use(cors());
app.use(express.json());

const chatLimit = rateLimit({ windowMs: 60*1000, max: 30, message: { error:"Rate limit reached" } });

// Token store
const tokens = new Map();

function today() { return new Date().toISOString().slice(0,10); }
function generateToken() {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const seg = (n) => Array.from({length:n}, ()=>chars[Math.floor(Math.random()*chars.length)]).join("");
  return `SNT-${seg(4)}-${seg(4)}-${seg(4)}`;
}
function normalizeToken(t) { return (t||"").trim().toUpperCase(); }

// ── Health ────────────────────────────────────────────────────
app.get("/health", (_req, res) => {
  res.json({
    status: "ok",
    service: "Sentinel API",
    version: "1.0.0",
    tokens: tokens.size,
    uptime: Math.floor(process.uptime()),
    claude: !!process.env.ANTHROPIC_API_KEY,
    stripe: !!process.env.STRIPE_SECRET_KEY
  });
});

// ── Validate token ────────────────────────────────────────────
app.post("/validate", (req, res) => {
  const { token } = req.body;
  if (!token) return res.status(400).json({ valid:false, error:"No token provided" });
  const data = tokens.get(normalizeToken(token));
  if (!data)        return res.json({ valid:false, error:"Token not found" });
  if (!data.active) return res.json({ valid:false, error:"Token inactive" });
  res.json({ valid:true, plan:data.plan, usageToday:data.usageToday, dailyLimit:50 });
});

// ── AI Chat ───────────────────────────────────────────────────
app.post("/chat", chatLimit, async (req, res) => {
  const token = req.headers["x-sentinel-token"];
  if (!token) return res.status(401).json({ error:"No token. Subscribe at sentinel-app.com" });

  const data = tokens.get(normalizeToken(token));
  if (!data || !data.active) return res.status(401).json({ error:"Invalid or expired token" });

  if (data.lastReset !== today()) { data.usageToday = 0; data.lastReset = today(); }
  if (data.usageToday >= 50) return res.status(429).json({ error:"Daily limit reached (50 messages). Resets at midnight." });

  const { messages, context } = req.body;
  if (!messages?.length) return res.status(400).json({ error:"No messages" });

  try {
    const r = await fetch("https://api.anthropic.com/v1/messages", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-api-key": process.env.ANTHROPIC_API_KEY,
        "anthropic-version": "2023-06-01"
      },
      body: JSON.stringify({
        model: "claude-haiku-4-5-20251001",
        max_tokens: 600,
        system: `You are Sentinel's AI security assistant. Context: ${context||""}. Explain phishing threats clearly and conversationally. Keep responses to 2-3 paragraphs.`,
        messages: messages.slice(-10)
      })
    });

    if (!r.ok) return res.status(502).json({ error:"AI service unavailable. Try again." });
    const d = await r.json();
    const reply = d.content?.[0]?.text || "Could not generate response.";
    data.usageToday++;
    res.json({ reply, usageToday:data.usageToday, dailyLimit:50 });
  } catch(e) {
    res.status(500).json({ error:"Server error. Try again." });
  }
});

// ── Admin: create token ───────────────────────────────────────
app.post("/admin/token", (req, res) => {
  const adminKey = req.headers["x-admin-key"];
  if (adminKey !== process.env.ADMIN_KEY) return res.status(403).json({ error:"Forbidden" });
  const { email, plan } = req.body;
  if (!email) return res.status(400).json({ error:"Email required" });
  const token = generateToken();
  tokens.set(token, { active:true, email, usageToday:0, lastReset:today(), plan:plan||"pro" });
  console.log(`[Admin] Created token for ${email}: ${token}`);
  res.json({ token, email, plan:plan||"pro" });
});

app.listen(PORT, () => {
  console.log(`\n🛡  Sentinel Server running on port ${PORT}`);
  console.log(`   Claude API: ${process.env.ANTHROPIC_API_KEY ? "✅ Connected" : "❌ Missing key"}`);
  console.log(`   Admin key:  ${process.env.ADMIN_KEY ? "✅ Set" : "❌ Missing"}\n`);
});
