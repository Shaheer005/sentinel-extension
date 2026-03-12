// SENTINEL v5 — HTML Threat Detection

export function analyseHTML(html) {
  const findings = [];

  // Hidden text (white on white, font-size 0, display none)
  if (/color:\s*(#fff(fff)?|white)\s*;[^}]*background[^}]*#fff/i.test(html) ||
      /font-size\s*:\s*0(px|pt|em)?/i.test(html) ||
      /visibility\s*:\s*hidden/i.test(html)) {
    findings.push({
      type:"HIDDEN_TEXT", severity:"HIGH",
      title:"Hidden text detected",
      detail:"This email contains invisible text — a technique used to confuse spam filters while hiding content from you. The email shows you one thing while telling spam filters something else.",
      advice:"This email is deliberately deceptive in its construction."
    });
  }

  // Form fields inside email
  if (/<form[\s>]/i.test(html) || /<input[\s>]/i.test(html)) {
    findings.push({
      type:"FORM_IN_EMAIL", severity:"CRITICAL",
      title:"Form/input field inside email body",
      detail:"This email contains an interactive form or input field — something legitimate emails never do. This is almost certainly a credential harvesting attack designed to steal your password or payment details without you visiting a separate website.",
      advice:"Never enter any information into a form inside an email. This is a phishing attack."
    });
  }

  // Iframes
  if (/<iframe[\s>]/i.test(html)) {
    findings.push({
      type:"IFRAME", severity:"HIGH",
      title:"Hidden iframe embedded in email",
      detail:"An iframe (invisible embedded webpage) was found. Iframes in emails can silently load malicious content, execute scripts, or fingerprint your browser.",
      advice:"This email embeds external content that could be malicious."
    });
  }

  // JavaScript
  if (/<script[\s>]/i.test(html) || /javascript:/i.test(html)) {
    findings.push({
      type:"JAVASCRIPT", severity:"CRITICAL",
      title:"JavaScript code in email",
      detail:"This email contains JavaScript code. While most email clients block it, its presence indicates the sender is attempting to run code on your device.",
      advice:"This email is attempting to execute code. Do not open it."
    });
  }

  // Data URIs (can encode malicious content)
  if (/src=["']data:/i.test(html)) {
    findings.push({
      type:"DATA_URI", severity:"HIGH",
      title:"Encoded data embedded in email",
      detail:"This email uses data URIs to embed encoded content directly. This technique is used to bypass content filters and hide malicious payloads.",
      advice:"Encoded embedded content is a red flag for evasion techniques."
    });
  }

  // CSS import (can load external resources)
  if (/@import/i.test(html)) {
    findings.push({
      type:"CSS_IMPORT", severity:"MEDIUM",
      title:"External CSS import detected",
      detail:"This email imports external stylesheets which can be used to track you or load malicious content without obvious indicators.",
      advice:"External imports in emails can be used for sophisticated tracking."
    });
  }

  // Meta refresh (auto-redirect)
  if (/<meta[^>]+refresh/i.test(html)) {
    findings.push({
      type:"META_REFRESH", severity:"HIGH",
      title:"Auto-redirect detected",
      detail:"This email attempts to automatically redirect your browser to another page. Legitimate emails don't do this.",
      advice:"Do not interact with this email — it attempts to redirect you automatically."
    });
  }

  // Base64 encoded content (evasion)
  const b64Blocks = (html.match(/[A-Za-z0-9+/]{100,}={0,2}/g)||[]).length;
  if (b64Blocks > 2) {
    findings.push({
      type:"ENCODED_CONTENT", severity:"MEDIUM",
      title:"Large amounts of encoded content",
      detail:"This email contains unusually large blocks of encoded data — a technique sometimes used to hide malicious content from security scanners.",
      advice:"Heavily encoded emails are sometimes used to evade detection."
    });
  }

  return findings;
}
