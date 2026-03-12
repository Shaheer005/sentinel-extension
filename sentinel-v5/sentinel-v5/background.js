// SENTINEL v5 — background.js
const SERVER_URL = "https://unprovisional-elba-unmeasurably.ngrok-free.dev";

const PHRASE_RULES = [
  { re:/\b(urgent|immediately|act now|action required)\b/i,                                    score:15, flag:"Urgency language",             explain:"Uses time pressure to prevent careful thinking — hallmark of social engineering." },
  { re:/\b(expires? (today|in \d+ hours?)|last chance|final notice)\b/i,                       score:15, flag:"Artificial deadline",           explain:"Creates a false deadline to pressure you into acting without verification." },
  { re:/\b(account.{0,20}(suspended|locked|disabled|terminated|restricted))\b/i,               score:20, flag:"Account suspension threat",     explain:"Threatens to disable your account to create panic." },
  { re:/\b(verify|confirm|validate).{0,30}(password|account|details|identity)\b/i,             score:20, flag:"Credential verification request",explain:"Legitimate services never ask you to verify credentials via email." },
  { re:/\b(enter|provide|submit).{0,20}(password|ssn|credit card|bank|pin)\b/i,               score:30, flag:"Sensitive data request",         explain:"Requesting sensitive info in email is a serious phishing indicator." },
  { re:/\b(wire transfer|send money|western union|moneygram)\b/i,                              score:25, flag:"Money transfer request",         explain:"Requesting money transfers via email is a primary fraud indicator." },
  { re:/\b(you (have|ve) won|lottery|prize|claim your|free gift|winner)\b/i,                   score:20, flag:"Prize/lottery scam",             explain:"Classic advance-fee fraud — you have not won anything." },
  { re:/\b(dear (customer|user|member|account holder|valued))[,\s]/i,                          score:10, flag:"Generic greeting",               explain:"Real companies know your name. Generic greetings indicate mass phishing." },
  { re:/\b(security (alert|warning|breach|incident))\b/i,                                      score:12, flag:"Fake security alert",            explain:"Fake security alerts create fear to make you act without thinking." },
  { re:/\.(exe|bat|cmd|scr|pif|vbs|jar|ps1)\b/i,                                               score:30, flag:"Dangerous file type",            explain:"Executable files mentioned — these can run malicious code on your device." },
  { re:/\b(your account.{0,20}(compromised|hacked|breached|stolen))\b/i,                       score:20, flag:"Account compromise claim",       explain:"Claiming your account was hacked to create urgency." },
  { re:/https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/i,                                      score:25, flag:"IP address URL",                 explain:"Links to IP addresses instead of domains are almost exclusively used in phishing." },
  { re:/(bit\.ly|tinyurl|t\.co|goo\.gl|ow\.ly|short\.io)/i,                                   score:15, flag:"URL shortener detected",          explain:"Shortened URLs hide the real destination — used to disguise malicious links." },
  { re:/paypa[l1]|amaz[o0]n|g[o0]{2}gle|micr[o0]s[o0]ft|[a4]pple|netfl[i1]x/i,               score:30, flag:"Lookalike brand name",           explain:"Character substitution to mimic a trusted brand (paypa1 instead of paypal)." },
  { re:/\b(login|sign.?in).{0,20}(here|link|button|below|click)/i,                            score:15, flag:"Login prompt in email",          explain:"Legitimate services don't ask you to log in via email links." },
];

const SHORTENERS = ["bit.ly","tinyurl.com","t.co","goo.gl","ow.ly","short.io","rebrand.ly","cutt.ly"];
const BAD_TLDS   = [".tk",".ml",".ga",".cf",".gq",".pw",".top",".xyz",".click",".link",".loan"];
const BRANDS     = ["paypal","amazon","apple","google","microsoft","netflix","facebook","instagram","twitter","linkedin","dropbox","chase","wellsfargo","bankofamerica","citibank","hsbc"];

async function getCfg() {
  return new Promise(r => chrome.storage.local.get(["sentinelToken","enabled","scanHistory"], r));
}

function scanEmail({ subject, bodyText, htmlContent, fromEmail, fromName, replyTo, urls }) {
  const allFlags = [];
  let totalScore = 0;
  const text = `${subject||""} ${bodyText||""}`;

  // Language rules
  const matched = new Set();
  for (const rule of PHRASE_RULES) {
    if (rule.re.test(text) && !matched.has(rule.flag)) {
      matched.add(rule.flag);
      totalScore += rule.score;
      allFlags.push({ type:"LANGUAGE", severity:rule.score>=25?"HIGH":rule.score>=15?"MEDIUM":"LOW", detail:rule.flag, explain:rule.explain });
    }
  }

  // Sender spoofing
  if (fromEmail && fromName) {
    const nameLow = fromName.toLowerCase();
    const domLow  = extractDomain(fromEmail).toLowerCase();
    for (const brand of BRANDS) {
      if (nameLow.includes(brand) && !domLow.includes(brand)) {
        totalScore += 30;
        allFlags.push({ type:"SPOOFING", severity:"CRITICAL", detail:`"${fromName}" sent from "${domLow}"`, explain:`Display name claims to be ${brand} but actual domain is "${domLow}" — classic display name spoofing.` });
        break;
      }
    }
  }

  if (replyTo && fromEmail && !domainsMatch(fromEmail, replyTo)) {
    totalScore += 20;
    allFlags.push({ type:"SPOOFING", severity:"HIGH", detail:`Reply-To (${extractDomain(replyTo)}) ≠ Sender (${extractDomain(fromEmail)})`, explain:"Replies go to a different address — used to intercept your responses." });
  }

  // URL analysis
  for (const url of (urls||[])) {
    let parsed; try { parsed = new URL(url); } catch { continue; }
    const host = parsed.hostname.toLowerCase();
    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(host)) { totalScore+=30; allFlags.push({ type:"URL", severity:"CRITICAL", detail:`IP address URL: ${host}`, explain:"Links to raw IP addresses are used in phishing to hide destinations." }); }
    if (SHORTENERS.some(s=>host===s||host.endsWith("."+s))) { totalScore+=15; allFlags.push({ type:"URL", severity:"MEDIUM", detail:`Shortened URL: ${host}`, explain:"URL shorteners hide the real destination." }); }
    if (BAD_TLDS.some(t=>host.endsWith(t))) { totalScore+=20; allFlags.push({ type:"URL", severity:"HIGH", detail:`Suspicious TLD: ${host}`, explain:"Domain extension commonly used for free anonymous registrations by attackers." }); }
    if (url.includes("@")) { totalScore+=35; allFlags.push({ type:"URL", severity:"CRITICAL", detail:"URL contains @ obfuscation", explain:"Everything before @ is ignored by browsers — real destination hidden after @." }); }
    for (const brand of BRANDS) {
      if (host.includes(brand) && !host.endsWith(brand+".com") && !host.endsWith(brand+".co.uk")) {
        totalScore+=35; allFlags.push({ type:"URL", severity:"CRITICAL", detail:`Brand lookalike: ${host}`, explain:`Contains "${brand}" but is NOT the real ${brand} website.` }); break;
      }
    }
  }

  // HTML analysis
  if (htmlContent) {
    try {
      const doc = new DOMParser().parseFromString(htmlContent,"text/html");
      doc.querySelectorAll("img").forEach(img => {
        const w=parseInt(img.getAttribute("width")||"100"), h=parseInt(img.getAttribute("height")||"100"), s=img.getAttribute("style")||"";
        if ((w<=2&&h<=2)||s.includes("width:1px")||s.includes("width: 1px")) { totalScore+=20; allFlags.push({ type:"TRACKING", severity:"HIGH", detail:"Tracking pixel (invisible 1x1 image)", explain:"Invisible image that fires when you open the email, leaking your IP, location, device and confirming your email is active to the attacker." }); }
      });
      if (doc.querySelectorAll("form").length>0) { totalScore+=40; allFlags.push({ type:"HTML", severity:"CRITICAL", detail:"HTML form inside email", explain:"Legitimate services never collect info via email forms — this is credential harvesting." }); }
      if (doc.querySelectorAll("input[type='password']").length>0) { totalScore+=50; allFlags.push({ type:"HTML", severity:"CRITICAL", detail:"Password field in email", explain:"No legitimate service asks for your password inside an email." }); }
      if (doc.querySelectorAll("iframe").length>0) { totalScore+=25; allFlags.push({ type:"HTML", severity:"HIGH", detail:"Iframe in email", explain:"Iframes load external pages — can display fake login forms within the email." }); }
      if (doc.querySelectorAll("script").length>0) { totalScore+=35; allFlags.push({ type:"HTML", severity:"CRITICAL", detail:"JavaScript in email HTML", explain:"No legitimate email contains JavaScript. Can exploit vulnerable email clients." }); }
      let hiddenFound=false;
      doc.querySelectorAll("*").forEach(el => {
        if (hiddenFound) return;
        const st=el.getAttribute("style")||"";
        if (st.includes("display:none")||st.includes("visibility:hidden")||st.includes("opacity:0")) { hiddenFound=true; totalScore+=15; allFlags.push({ type:"HTML", severity:"MEDIUM", detail:"Hidden content in email", explain:"Content invisible to human readers but visible to machines — used to manipulate spam filters." }); }
      });
    } catch {}
  }

  // Verdict
  const flags = dedup(allFlags);
  let verdict, riskLevel, summary, advice;
  if (totalScore>=70) {
    verdict="PHISHING"; riskLevel=totalScore>=100?"Critical":"High";
    summary=`${flags.length} threat(s) detected. Risk score: ${totalScore}. Do not interact with this email.`;
    advice="Do not click links, open attachments, or reply. Report as phishing and delete immediately.";
  } else if (totalScore>=25) {
    verdict="SUSPICIOUS"; riskLevel=totalScore>=50?"High":"Medium";
    summary=`${flags.length} suspicious pattern(s). Risk score: ${totalScore}. Proceed with caution.`;
    advice="Verify the sender through official channels before clicking any links or replying.";
  } else {
    verdict="SAFE"; riskLevel="Low";
    summary=`No significant threats. Risk score: ${totalScore}.`;
    advice="Looks clean. Always stay cautious with unexpected emails.";
  }

  return { verdict, riskLevel, summary, advice, flags: flags.slice(0,8), score:totalScore };
}

chrome.runtime.onMessage.addListener((msg, _s, sendResponse) => {
  if (msg.type==="SCAN_EMAIL") {
    try { const result=scanEmail(msg.payload); saveToHistory({...msg.payload,...result}); sendResponse({success:true,result}); }
    catch(e) { sendResponse({success:false,error:e.message}); }
    return false;
  }
  if (msg.type==="CHAT_MESSAGE") { handleChat(msg.payload).then(r=>sendResponse({success:true,reply:r})).catch(e=>sendResponse({success:false,error:e.message})); return true; }
  if (msg.type==="VALIDATE_TOKEN") { validateToken(msg.token).then(r=>sendResponse(r)).catch(()=>sendResponse({valid:false})); return true; }
  if (msg.type==="GET_HISTORY") { chrome.storage.local.get(["scanHistory"],d=>sendResponse({history:d.scanHistory||[]})); return true; }
  if (msg.type==="CLEAR_HISTORY") { chrome.storage.local.set({scanHistory:[]},()=>sendResponse({ok:true})); return true; }
  if (msg.type==="GET_STATS") { chrome.storage.local.get(["scanHistory"],d=>{ const h=d.scanHistory||[]; sendResponse({stats:{total:h.length,phishing:h.filter(x=>x.verdict==="PHISHING").length,suspicious:h.filter(x=>x.verdict==="SUSPICIOUS").length,safe:h.filter(x=>x.verdict==="SAFE").length}}); }); return true; }
});

async function handleChat({messages,context}) {
  const cfg=await getCfg();
  if (!cfg.sentinelToken) throw new Error("No Sentinel token. Subscribe at sentinel-app.com to unlock AI chat.");
  const res=await fetch(`${SERVER_URL}/chat`,{method:"POST",headers:{"Content-Type":"application/json","x-sentinel-token":cfg.sentinelToken},body:JSON.stringify({messages,context})});
  if (!res.ok) { const e=await res.json().catch(()=>({})); if(res.status===401) throw new Error("Invalid or expired token. Check your subscription."); if(res.status===429) throw new Error("Daily AI limit reached. Resets at midnight."); throw new Error(e.error||`Server error ${res.status}`); }
  const data=await res.json(); return data.reply||"No response.";
}

async function validateToken(token) {
  try { const res=await fetch(`${SERVER_URL}/validate`,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({token})}); return await res.json(); }
  catch { return {valid:false,error:"Could not reach server"}; }
}

function saveToHistory(entry) {
  chrome.storage.local.get(["scanHistory"],d=>{
    const h=[{subject:entry.subject||"(no subject)",verdict:entry.verdict,riskLevel:entry.riskLevel,score:entry.score,flagCount:(entry.flags||[]).length,timestamp:Date.now()},...(d.scanHistory||[])].slice(0,200);
    chrome.storage.local.set({scanHistory:h});
  });
}

function extractDomain(email) { if(!email) return ""; const m=email.match(/@([^>)\s]+)/); return m?m[1].toLowerCase():email.toLowerCase(); }
function domainsMatch(a,b) { const da=extractDomain(a).split(".").slice(-2).join("."),db=extractDomain(b).split(".").slice(-2).join("."); return da===db; }
function dedup(flags) { const seen=new Set(); return flags.filter(f=>{ const k=f.type+f.detail; if(seen.has(k)) return false; seen.add(k); return true; }); }

console.log("[Sentinel v5] Background ready.");
