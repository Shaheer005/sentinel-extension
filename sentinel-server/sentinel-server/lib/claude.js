// lib/claude.js — Claude API wrapper
const CLAUDE_URL = "https://api.anthropic.com/v1/messages";
const MODEL      = "claude-haiku-4-5-20251001"; // cheapest, fastest

const SYSTEM = `You are Sentinel AI, a cybersecurity expert assistant embedded in the Sentinel Gmail phishing defender.

Your role is to EDUCATE users about threats found in their emails. When given scan results:
1. Explain clearly what each threat means in plain English
2. Describe what the attacker was trying to achieve
3. Explain what would have happened if the user had interacted with the email
4. Give specific, actionable advice

Be conversational, clear, and genuinely helpful. Avoid technical jargon unless you explain it.
Use structure (bold, bullet points) to make explanations easy to scan.
Always end with a clear "What to do" recommendation.`;

export async function callClaude(messages, context) {
  // Build enriched messages with context if available
  const enrichedMessages = [...messages];
  if (context && enrichedMessages.length === 1) {
    // First message — inject context
    enrichedMessages[0] = {
      role: "user",
      content: enrichedMessages[0].content
    };
  }

  const res = await fetch(CLAUDE_URL, {
    method: "POST",
    headers: {
      "Content-Type":    "application/json",
      "x-api-key":       process.env.CLAUDE_API_KEY,
      "anthropic-version":"2023-06-01"
    },
    body: JSON.stringify({
      model:      MODEL,
      max_tokens: 1024,
      system:     SYSTEM,
      messages:   enrichedMessages
    })
  });

  if (!res.ok) {
    const err = await res.text();
    throw new Error(`Claude API ${res.status}: ${err.slice(0, 200)}`);
  }

  const data = await res.json();
  return data.content?.[0]?.text || "No response generated.";
}
