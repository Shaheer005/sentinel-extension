# 🛡️ Sentinel — Gmail Phishing Defender

> Silently scans every email before you open it. Free forever.

[![Version](https://img.shields.io/badge/version-1.0.0-6366f1?style=flat-square)](https://github.com/Shaheer005/sentinel-extension)
[![License](https://img.shields.io/badge/license-GPLv3-4ade80?style=flat-square)](LICENSE)
[![Store](https://img.shields.io/badge/Edge%20Add--ons-Live-4ade80?style=flat-square)](https://microsoftedge.microsoft.com/addons/detail/mfnljldmnmldodakhllljomemndfageo)
[![Website](https://img.shields.io/badge/website-sentinel--app.com-818cf8?style=flat-square)](https://sentinel-web-two.vercel.app/)

---

## The Problem

Most people open phishing emails before they realize they're dangerous. By then it's too late — you've already loaded the tracking pixel, hovered over the link, or worse, clicked it.

Existing tools react *after* the damage. Sentinel acts *before*.

---


<img width="1895" height="891" alt="Screenshot 2026-03-25 233041" src="https://github.com/user-attachments/assets/c4473643-9ec8-4c91-b104-26ddd6a3d490" />

<img width="1900" height="864" alt="Screenshot 2026-03-25 233050" src="https://github.com/user-attachments/assets/f91b92b9-fc09-4802-9d0e-d4d6814786f3" />

<img width="1896" height="909" alt="Screenshot 2026-03-25 233059" src="https://github.com/user-attachments/assets/51765191-4c87-471f-bcd6-3c3139687659" />

<img width="1894" height="877" alt="Screenshot 2026-03-25 233119" src="https://github.com/user-attachments/assets/2d508e60-0dcb-4ce2-8c90-ae2ec2e1f303" />

<img width="1904" height="858" alt="Screenshot 2026-03-25 233128" src="https://github.com/user-attachments/assets/3e1dd0bb-8679-4005-afdd-d48bb14116ff" />




## What Sentinel Does

The moment an email arrives in your Gmail inbox, Sentinel scans it automatically in the background and shows a verdict badge — before you click anything.

| Badge | Meaning |
|-------|---------|
| 🟢 `✓ Safe` | Email looks clean |
| 🟡 `⚠ SUSPICIOUS` | Something looks off — proceed carefully |
| 🔴 `🛡 PHISHING` | Dangerous email detected |

Click any flagged email to see a detailed breakdown of exactly what was detected, explained in plain English.

---

## Detection Rules (15 Total)

| Rule | What it catches |
|------|----------------|
| **Tracking pixels** | Invisible 1x1 images that spy on when you open emails |
| **Display name spoofing** | "PayPal" sent from paypa1-support.ru |
| **Lookalike domains** | amaz0n.com, g00gle.net, paypa1.net |
| **Redirect chains** | Links that bounce through unknown servers before the real destination |
| **Credential harvesting** | Forms and password fields embedded inside emails |
| **Urgency language** | "Act now", "Account suspended", "24 hours remaining" |
| **Reply-To hijacking** | Replies secretly redirected to attacker-controlled addresses |
| **Hidden text** | Invisible content used to bypass spam filters |
| **Suspicious attachments** | .exe, .bat, .ps1, .vbs file links |
| **Newly registered domains** | Sites registered days ago specifically to run scams |
| **IP-based links** | Direct links to IP addresses instead of domain names |
| **URL obfuscation** | Encoded or obfuscated URLs hiding true destinations |
| **HTML patterns** | Dangerous HTML structures used in phishing kits |
| **Email header anomalies** | Mismatched From/Reply-To, missing authentication headers |
| **Phishing phrases** | Known phishing language patterns |

---

## Architecture

```
sentinel-v5/          ← Chrome/Edge Extension (Manifest V3)
  content.js          ← Gmail DOM scanner, badge injection
  background.js       ← Service worker, API bridge
  popup.js/html       ← Extension popup UI
  rules/              ← Detection rule modules
    links.js          ← URL & redirect analysis
    pixels.js         ← Tracking pixel detection
    phrases.js        ← Language pattern matching
    headers.js        ← Email header analysis
    html.js           ← HTML structure analysis

sentinel-server/      ← Node.js Backend
  server.js           ← Express API server
  lib/                ← Token validation, Claude proxy
  routes/             ← API route handlers

sentinel-web/         ← Landing Website
  index.html          ← Marketing page (deployed on Vercel)
```

---

## How It Works

```
Gmail loads email list
        ↓
content.js detects tr.zA rows (Gmail inbox rows)
        ↓
Extracts: subject, sender, snippet, URLs
        ↓
Runs through 15 local detection rules
        ↓
Calculates risk score (0-100)
        ↓
Injects badge into inbox row
        ↓
User opens email → full panel with flag breakdown
```

All detection is **100% local** — your emails never leave your browser.

---

## Privacy

- All scanning runs locally in your browser
- No email content is ever sent to any server
- No account required to use the free tier
- No data collection, no analytics, no tracking
- Open source — audit the code yourself

The only network request Sentinel makes is when a Pro subscriber uses the AI chat feature — and even then, only the user's typed question is sent, never the email content itself.

---

## Tech Stack

- **Extension**: Vanilla JavaScript, Chrome Extension Manifest V3
- **Backend**: Node.js, Express
- **AI (Pro tier)**: Claude Haiku via Anthropic API
- **Website**: HTML/CSS, deployed on Vercel

---

## Installation

### From Edge Add-ons Store (Recommended)
Search "Sentinel Gmail Phishing Defender" on the Microsoft Edge Add-ons Store

### Manual (Developer Mode)
```bash
# 1. Clone this repo
git clone https://github.com/Shaheer005/sentinel-extension.git

# 2. Open Edge/Chrome extensions page
#    edge://extensions  or  chrome://extensions

# 3. Enable "Developer mode" (top right toggle)

# 4. Click "Load unpacked" → select the sentinel-v5 folder

# 5. Open Gmail — badges appear automatically
```

---

## Running the Server Locally

```bash
cd sentinel-server/sentinel-server
npm install
cp .env.example .env
# Add your ANTHROPIC_API_KEY to .env
node server.js
# Runs on http://localhost:3000
```

---

## Free vs Pro

| Feature | Free | Pro (£3/mo) |
|---------|------|-------------|
| Silent inbox scanning | ✅ | ✅ |
| 15 detection rules | ✅ | ✅ |
| Plain-English explanations | ✅ | ✅ |
| AI chat about flagged emails | ❌ | ✅ |
| "Why is this dangerous?" | ❌ | ✅ |
| Unlimited AI questions | ❌ | ✅ (50/day) |

---

## Roadmap

- [x] Core detection engine (15 rules)
- [x] Inbox badge injection
- [x] Detailed email panel
- [x] Edge Add-ons Store submission
- [ ] Chrome Web Store submission
- [ ] Payment integration
- [ ] Outlook/Hotmail support
- [ ] Firefox extension

---

## Built By

**Shaheer Ahmed** — Karachi, Pakistan

Building in public. First real shipped product.

[LinkedIn](https://www.linkedin.com/in/shaheer-ahmed-64055223b/) · [Website](https://sentinel-app.com)

---

## License

Copyright © 2026 Shaheer Ahmed. All Rights Reserved. The source code is available for transparency and auditing purposes only.
---

*If this helped you, give it a ⭐ — it means a lot for a solo developer.*
