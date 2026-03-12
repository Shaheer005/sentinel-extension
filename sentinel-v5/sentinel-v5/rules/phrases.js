// SENTINEL v5 — Phishing Phrase Detection

export function detectPhishingPhrases(text) {
  const findings = [];
  const t = text.toLowerCase();
  let score = 0;
  const triggers = [];

  const RULES = [
    // Urgency
    { re:/\b(act now|respond immediately|urgent(ly)?|action required|immediate(ly)?|last chance|final notice|expires? (today|in \d+ hours?))\b/, score:15, label:"Urgency language" },
    { re:/\b(your account (will be|has been|is) (suspended|locked|disabled|terminated|compromised|hacked))\b/, score:20, label:"Account threat" },
    { re:/\b(verify (your|account|identity|email|information) (now|immediately|within \d+))\b/, score:18, label:"Forced verification" },

    // Credential harvesting
    { re:/\b(enter|provide|confirm|update|submit).{0,25}(password|pin|ssn|credit card|card number|cvv|bank|account number)\b/, score:25, label:"Credential request" },
    { re:/\b(click (here|below|the link|button) to (verify|confirm|update|access|login|sign in))\b/, score:15, label:"Click-to-verify" },
    { re:/\bsign.?in (to|with) your account\b/, score:10, label:"Sign-in prompt" },

    // Financial
    { re:/\b(wire transfer|send (money|funds|payment)|western union|moneygram|cryptocurrency|bitcoin|gift card)\b/, score:25, label:"Money transfer request" },
    { re:/\b(you (have|'ve) (won|been selected|been chosen)|lottery|prize|winner|claim (your|prize|reward))\b/, score:20, label:"Prize/lottery scam" },
    { re:/\b(unpaid (invoice|balance|bill|fee)|overdue (payment|account)|payment (required|needed|due))\b/, score:12, label:"Fake payment demand" },

    // Authority impersonation
    { re:/\b(irs|fbi|interpol|police|court|legal action|lawsuit|arrest|warrant)\b/, score:20, label:"Authority impersonation" },
    { re:/\b(ceo|executive|management|hr department) (request|asking|needs|requires)\b/, score:15, label:"Executive impersonation" },

    // Threats
    { re:/\b(failure to (respond|comply|verify|confirm) will result in)\b/, score:20, label:"Consequence threat" },
    { re:/\b(account (will be|is being) (closed|deleted|suspended) in \d+)\b/, score:18, label:"Account deletion threat" },

    // Deceptive
    { re:/\b(this is not a spam|this is a legitimate|100% (safe|secure|legit))\b/, score:15, label:"Over-assurance of legitimacy" },
    { re:/\b(do not (ignore|delete) this (email|message))\b/, score:12, label:"Deletion pressure" },
    { re:/\bdear (valued customer|account holder|user|member|client)\b/, score:10, label:"Generic non-personal greeting" },
  ];

  for (const rule of RULES) {
    if (rule.re.test(t)) {
      score += rule.score;
      triggers.push(rule.label);
    }
  }

  if (triggers.length > 0) {
    const severity = score >= 50 ? "HIGH" : score >= 25 ? "MEDIUM" : "LOW";
    findings.push({
      type:"PHISHING_PHRASES", severity,
      title:`${triggers.length} phishing language pattern(s) detected`,
      detail:`This email uses language commonly found in phishing attacks: ${triggers.join(", ")}. Attackers use these patterns to create urgency, fear, or false authority to make you act without thinking.`,
      advice:"Legitimate organisations don't pressure you with threats or urgent demands via email. Verify through official channels.",
      score,
      triggers
    });
  }

  return findings;
}
