// routes/chat.js — AI chat proxy
import { Router } from "express";
import { validateToken, incrementRequests } from "../lib/db.js";
import { callClaude } from "../lib/claude.js";

const router = Router();
const DAILY_LIMIT = 50; // messages per day per user

router.post("/", async (req, res) => {
  const token = req.headers["x-sentinel-token"];
  if (!token) return res.status(401).json({ error: "No token provided." });

  // Validate token
  const tokenRow = await validateToken(token);
  if (!tokenRow) return res.status(401).json({ error: "Invalid or expired token. Check your subscription." });

  // Daily rate limit
  if (tokenRow.requests_today >= DAILY_LIMIT) {
    return res.status(429).json({ error: `Daily limit of ${DAILY_LIMIT} AI messages reached. Resets at midnight.` });
  }

  const { messages, context } = req.body;
  if (!messages || !Array.isArray(messages) || messages.length === 0) {
    return res.status(400).json({ error: "No messages provided." });
  }

  // Sanitize — only pass role + content, no email body
  const safe = messages.slice(-10).map(m => ({
    role:    m.role === "assistant" ? "assistant" : "user",
    content: String(m.content || "").slice(0, 2000)
  }));

  try {
    const reply = await callClaude(safe, context);
    await incrementRequests(token);
    res.json({ reply, remaining: DAILY_LIMIT - tokenRow.requests_today - 1 });
  } catch(e) {
    console.error("[Chat] Claude error:", e.message);
    res.status(500).json({ error: "AI unavailable. Please try again shortly." });
  }
});

export default router;
