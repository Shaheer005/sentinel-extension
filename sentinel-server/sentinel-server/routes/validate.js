// routes/validate.js
import { Router }        from "express";
import { validateToken } from "../lib/db.js";

const router = Router();

router.post("/", async (req, res) => {
  const { token } = req.body;
  if (!token) return res.json({ valid: false, error: "No token provided." });

  const row = await validateToken(token);
  if (!row)  return res.json({ valid: false, error: "Token not found or subscription inactive." });

  res.json({
    valid:     true,
    email:     row.email.replace(/(.{2}).*(@.*)/, "$1***$2"), // mask email
    remaining: Math.max(0, 50 - row.requests_today)
  });
});

export default router;
