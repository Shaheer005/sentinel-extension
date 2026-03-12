// SENTINEL v5 — Tracking Pixel Detection

export function detectTrackingPixels(html) {
  const findings = [];

  const TRACKER_DOMAINS = [
    "getnotify.com","mailtrack.io","yesware.com","hubspot.com",
    "salesforce.com","marketo.com","sendgrid.net","bananatag.com",
    "postmastery.com","emailopened.com","readnotify.com","trackemail.com",
    "openedornot.com","streaklinks.com","spy-pixel.com","spyonweb.com"
  ];

  // 1x1 images
  if (/<img[^>]*(width=["']?1["']?)[^>]*(height=["']?1["']?)[^>]*>/i.test(html) ||
      /<img[^>]*(height=["']?1["']?)[^>]*(width=["']?1["']?)[^>]*>/i.test(html)) {
    findings.push({
      type:"TRACKING_PIXEL", severity:"HIGH",
      title:"Tracking pixel detected",
      detail:"A 1×1 invisible image was found. Opening this email silently notifies the sender, revealing your IP address, location, device type, and that your email is active.",
      advice:"Do not open this email. The sender is monitoring who reads it."
    });
  }

  // Zero-size hidden elements
  if (/<img[^>]*(width=["']?0["']?|height=["']?0["']?)[^>]*>/i.test(html)) {
    findings.push({
      type:"HIDDEN_BEACON", severity:"HIGH",
      title:"Hidden spy beacon detected",
      detail:"A zero-size invisible element was found — designed to track email opens without you noticing.",
      advice:"This email is built to spy on you silently."
    });
  }

  // Known tracker domains
  for (const d of TRACKER_DOMAINS) {
    if (html.toLowerCase().includes(d)) {
      findings.push({
        type:"KNOWN_TRACKER", severity:"MEDIUM",
        title:`Known tracker service: ${d}`,
        detail:`Content loads from ${d}, a known email tracking platform. Your reading activity is being logged by a third party.`,
        advice:"This sender is using a commercial tracking service to monitor you."
      });
      break;
    }
  }

  // Many external images
  const extImgs = (html.match(/<img[^>]+src=["']https?:\/\/(?!mail\.google\.com)[^"']+["'][^>]*>/gi) || []).length;
  if (extImgs > 4) {
    findings.push({
      type:"EXTERNAL_BEACONS", severity:"LOW",
      title:`${extImgs} external resources auto-load`,
      detail:"Multiple external servers are contacted the moment you open this email. Each can act as a tracking beacon.",
      advice:"Consider using Gmail's 'Plain text' view for this email."
    });
  }

  return findings;
}
