// SENTINEL v5 — Email Header Analysis

export function analyseHeaders(headerObj) {
  // headerObj: { from, replyTo, returnPath, subject, receivedSpf, dkim, dmarc, date, messageId }
  const findings = [];
  const { from="", replyTo="", returnPath="", subject="", receivedSpf="", dkim="", dmarc="", date="", messageId="" } = headerObj;

  // Extract display name vs actual email
  const fromMatch   = from.match(/^(.+?)\s*<([^>]+)>/);
  const displayName = fromMatch ? fromMatch[1].replace(/['"]/g,"").trim() : "";
  const fromEmail   = fromMatch ? fromMatch[2].trim() : from.trim();
  const fromDomain  = fromEmail.split("@")[1] || "";

  // SPF fail
  if (receivedSpf && /fail|softfail/i.test(receivedSpf)) {
    findings.push({
      type:"SPF_FAIL", severity:"HIGH",
      title:"Email failed sender verification (SPF)",
      detail:`This email claims to be from ${fromDomain} but failed the SPF check — meaning it was NOT sent from that domain's authorised servers. This is a strong sign of spoofing.`,
      advice:"This email is almost certainly not from who it claims to be."
    });
  }

  // DKIM fail
  if (dkim && /fail|invalid|none/i.test(dkim)) {
    findings.push({
      type:"DKIM_FAIL", severity:"HIGH",
      title:"Email signature invalid (DKIM)",
      detail:"The email's cryptographic signature is missing or invalid. Legitimate senders sign their emails. Attackers cannot forge valid signatures.",
      advice:"This email may have been tampered with or forged."
    });
  }

  // DMARC fail
  if (dmarc && /fail/i.test(dmarc)) {
    findings.push({
      type:"DMARC_FAIL", severity:"HIGH",
      title:"DMARC policy violated",
      detail:"The sending domain has a policy that this email violates. The domain owner has explicitly stated emails like this should be rejected.",
      advice:"The domain owner's own policy marks this as suspicious."
    });
  }

  // Reply-To mismatch
  if (replyTo && fromEmail) {
    const replyDomain = (replyTo.match(/@([^>"\s]+)/) || [])[1] || "";
    if (replyDomain && replyDomain !== fromDomain) {
      findings.push({
        type:"REPLY_TO_MISMATCH", severity:"HIGH",
        title:"Reply goes to different address than sender",
        detail:`Email appears to be from ${fromDomain} but replies go to ${replyDomain}. This is a classic phishing trick — you think you're replying to a legitimate company but responses go to the attacker.`,
        advice:"Do not reply to this email. The reply address is controlled by someone else."
      });
    }
  }

  // Display name impersonation
  const IMPERSONATION_TARGETS = ["paypal","amazon","apple","google","microsoft","netflix","bank","chase","wells fargo","citibank","hsbc","barclays","irs","fbi","dhl","fedex","ups","whatsapp","facebook","instagram"];
  for (const target of IMPERSONATION_TARGETS) {
    if (displayName.toLowerCase().includes(target) && !fromDomain.toLowerCase().includes(target)) {
      findings.push({
        type:"DISPLAY_NAME_SPOOF", severity:"HIGH",
        title:`Display name impersonates ${target.toUpperCase()}`,
        detail:`The email shows "${displayName}" as the sender, but the actual sending address is ${fromEmail}. ${target} would send from their own domain, not ${fromDomain}.`,
        advice:`This is not from ${target}. Do not click any links or provide any information.`
      });
      break;
    }
  }

  // Suspicious sender domain patterns
  if (/\d{3,}/.test(fromDomain)) {
    findings.push({
      type:"SUSPICIOUS_DOMAIN", severity:"MEDIUM",
      title:"Sender domain contains unusual numbers",
      detail:`The sending domain (${fromDomain}) contains long number sequences — often seen in automatically generated phishing domains.`,
      advice:"Be cautious of emails from domains with random numbers."
    });
  }

  // Free email for business claims
  const FREE_PROVIDERS = ["gmail.com","yahoo.com","hotmail.com","outlook.com","protonmail.com"];
  const businesKeywords = ["bank","support","service","security","account","noreply","notification","alert"];
  if (FREE_PROVIDERS.some(p => fromDomain === p) && businesKeywords.some(k => fromEmail.toLowerCase().includes(k))) {
    findings.push({
      type:"FREE_EMAIL_BUSINESS",severity:"MEDIUM",
      title:"Business claim from free email provider",
      detail:`This email claims to be from a business/service (${fromEmail}) but uses a free email provider (${fromDomain}). Legitimate businesses use their own domain.`,
      advice:"Real companies don't send account/security alerts from free email addresses."
    });
  }

  return findings;
}
