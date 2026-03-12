// lib/email.js — Send token emails via Resend
export async function sendTokenEmail(to, token) {
  const res = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      "Content-Type":  "application/json",
      "Authorization": `Bearer ${process.env.RESEND_API_KEY}`
    },
    body: JSON.stringify({
      from:    process.env.FROM_EMAIL || "sentinel@your-domain.com",
      to:      [to],
      subject: "Your Sentinel Pro Token 🛡️",
      html: `
<!DOCTYPE html>
<html>
<body style="background:#080b10;color:#c9d8e8;font-family:'IBM Plex Mono',monospace;padding:40px 20px;max-width:480px;margin:0 auto;">
  <div style="text-align:center;margin-bottom:32px;">
    <div style="font-size:36px;margin-bottom:8px;">🛡️</div>
    <h1 style="font-size:22px;letter-spacing:.12em;color:#fff;margin:0;">SENTINEL PRO</h1>
    <p style="color:#4a6070;font-size:11px;letter-spacing:.1em;text-transform:uppercase;">AI Phishing Defender</p>
  </div>

  <p style="margin-bottom:20px;line-height:1.6;">Thank you for subscribing! Here is your Sentinel Pro token:</p>

  <div style="background:#0d1117;border:1px solid rgba(0,212,255,.3);border-radius:12px;padding:20px;text-align:center;margin-bottom:24px;">
    <p style="color:#4a6070;font-size:10px;letter-spacing:.1em;text-transform:uppercase;margin:0 0 10px;">YOUR TOKEN</p>
    <p style="color:#00d4ff;font-size:20px;font-weight:700;letter-spacing:.1em;margin:0;">${token}</p>
  </div>

  <p style="line-height:1.6;margin-bottom:16px;"><strong style="color:#fff;">How to activate:</strong></p>
  <ol style="color:#c9d8e8;line-height:2;padding-left:20px;margin-bottom:24px;">
    <li>Open Gmail in Chrome</li>
    <li>Click the Sentinel shield icon</li>
    <li>Go to <strong style="color:#00d4ff;">Settings</strong></li>
    <li>Paste your token and click <strong style="color:#00d4ff;">Validate Token</strong></li>
    <li>AI chat unlocked! 🎉</li>
  </ol>

  <p style="color:#4a6070;font-size:10px;line-height:1.6;border-top:1px solid #1e2d3d;padding-top:16px;margin:0;">
    Keep this token safe. It's tied to your subscription and will stop working if you cancel.
    Questions? Reply to this email.
  </p>
</body>
</html>`
    })
  });

  if (!res.ok) {
    const err = await res.text();
    console.error("[Email] Failed to send:", err);
    throw new Error("Failed to send token email");
  }
  return true;
}
