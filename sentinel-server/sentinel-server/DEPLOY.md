# Sentinel Server — Deployment Guide

## 1. Railway Deployment (free tier)

```bash
# Install Railway CLI
npm install -g @railway/cli

# Login
railway login

# Create project
railway new
cd sentinel-server
railway up
```

Then set environment variables in Railway dashboard:
- ANTHROPIC_API_KEY
- STRIPE_SECRET_KEY
- STRIPE_WEBHOOK_SECRET
- ADMIN_KEY

Your server URL will be: https://your-project.up.railway.app

## 2. Update Extension

In `background.js`, line 2:
```javascript
const SERVER_URL = "https://your-project.up.railway.app";
```

## 3. Stripe Setup

1. Create account at stripe.com
2. Create a Product: "Sentinel Pro" — £3/month recurring
3. Get your Checkout link: Products → Share payment link
4. Set up webhook: Developers → Webhooks → Add endpoint
   - URL: https://your-project.up.railway.app/webhook
   - Events: checkout.session.completed, customer.subscription.deleted, invoice.payment_failed
5. Copy webhook signing secret → STRIPE_WEBHOOK_SECRET

## 4. Resend (email token delivery)

1. Create account at resend.com
2. Get API key
3. In server.js, uncomment sendTokenEmail and implement:

```javascript
async function sendTokenEmail(email, token) {
  await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: { "Authorization": `Bearer ${process.env.RESEND_API_KEY}`, "Content-Type": "application/json" },
    body: JSON.stringify({
      from: "Sentinel <hello@sentinel-app.com>",
      to: email,
      subject: "Your Sentinel Pro Token",
      html: `<h2>Welcome to Sentinel Pro! 🛡</h2><p>Your access token:</p><h1 style="font-family:monospace;letter-spacing:2px">${token}</h1><p>Paste this into the extension Settings tab to unlock AI chat.</p>`
    })
  });
}
```

## 5. Test

```bash
# Create test token manually
curl -X POST https://your-server.up.railway.app/admin/token \
  -H "Content-Type: application/json" \
  -H "x-admin-key: your-admin-key" \
  -d '{"email":"test@example.com","plan":"pro"}'

# Returns: { "token": "SNT-XXXX-XXXX-XXXX" }
# Paste this into the extension to test AI chat
```
