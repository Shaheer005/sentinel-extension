// SENTINEL v5 — content.js (fixed selectors)
(function() {
  if (window.__sentinelLoaded) return;
  window.__sentinelLoaded = true;

  const scanned = new Map();
  let scanTimeout = null;

  function init() {
    // Start scanning once Gmail rows exist
    const check = setInterval(() => {
      if (document.querySelectorAll("tr.zA").length > 0) {
        clearInterval(check);
        scanInbox();
        startObserver();
        watchOpenEmail();
      }
    }, 800);
    setTimeout(() => clearInterval(check), 20000);
  }

  function startObserver() {
    new MutationObserver(() => {
      clearTimeout(scanTimeout);
      scanTimeout = setTimeout(scanInbox, 500);
    }).observe(document.body, { childList: true, subtree: true });
  }

  // ── Scan all inbox rows ───────────────────────────────────────
  function scanInbox() {
    document.querySelectorAll("tr.zA").forEach(processRow);
  }

  function processRow(row) {
    if (row.querySelector(".sentinel-badge")) return;

    // ✅ Confirmed working selectors from debug
    const subjectEl = row.querySelector(".bog");
    const senderEl  = row.querySelector(".yW span[email]") || row.querySelector(".yP[email]");
    const snippetEl = row.querySelector(".y2");

    const subject   = subjectEl?.textContent?.trim() || "";
    const fromEmail = senderEl?.getAttribute("email") || "";
    const fromName  = row.querySelector(".yW")?.textContent?.trim() || "";
    const bodyText  = snippetEl?.textContent?.trim() || "";

    if (!subject) return;

    const fp = btoa(unescape(encodeURIComponent((subject + fromEmail).slice(0, 150)))).slice(0, 20);

    // Use cached result instantly
    if (scanned.has(fp)) {
      const cached = scanned.get(fp);
      if (cached) applyBadge(row, cached);
      return;
    }

    // Mark in progress
    scanned.set(fp, null);

    chrome.runtime.sendMessage({
      type: "SCAN_EMAIL",
      payload: { subject, fromEmail, fromName, bodyText, urls: extractUrls(bodyText) }
    }, res => {
      if (chrome.runtime.lastError || !res?.success) {
        scanned.delete(fp);
        return;
      }
      scanned.set(fp, res.result);
      applyBadge(row, res.result);
    });
  }

  // ── Badge injection ───────────────────────────────────────────
  function applyBadge(row, result) {
    if (!result) return;
    row.querySelector(".sentinel-badge")?.remove();

    const badge = document.createElement("span");
    badge.className = `sentinel-badge sentinel-${result.verdict.toLowerCase()}`;
    badge.title = result.summary || "";

    if (result.verdict === "PHISHING")         badge.textContent = "🛡 PHISHING";
    else if (result.verdict === "SUSPICIOUS")  badge.textContent = "⚠ SUS";
    else                                        badge.textContent = "✓ Safe";

    // ✅ td.a4W is the subject cell — confirmed working
    const subjectCell = row.querySelector("td.a4W");
    const subjectSpan = row.querySelector(".bog");

    if (subjectSpan) {
      subjectSpan.appendChild(badge);
    } else if (subjectCell) {
      subjectCell.appendChild(badge);
    }
  }

  // ── Open email panel ──────────────────────────────────────────
  function watchOpenEmail() {
    window.addEventListener("hashchange", () => setTimeout(scanOpenEmail, 1500));
    document.addEventListener("click", e => {
      if (e.target.closest("tr.zA")) setTimeout(scanOpenEmail, 1500);
    });
  }

  function scanOpenEmail() {
    const emailBody = document.querySelector(".a3s.aiL");
    const container = document.querySelector(".adn.ads");
    if (!emailBody || !container) return;
    if (container.querySelector(".sentinel-panel")) return;

    const subject   = document.querySelector("h2.hP")?.textContent?.trim() || "";
    const fromEl    = document.querySelector(".go span[email], .gD");
    const fromEmail = fromEl?.getAttribute("email") || "";
    const fromName  = fromEl?.textContent?.trim() || "";
    const bodyText  = emailBody.textContent;
    const htmlContent = emailBody.innerHTML;
    const urls      = extractUrls(htmlContent);

    chrome.runtime.sendMessage({
      type: "SCAN_EMAIL",
      payload: { subject, fromEmail, fromName, bodyText, htmlContent, urls }
    }, res => {
      if (chrome.runtime.lastError || !res?.success) return;
      injectPanel(container, res.result, { subject, fromEmail });
    });
  }

  function injectPanel(container, result, meta) {
    document.querySelector(".sentinel-panel")?.remove();
    const icon  = result.verdict==="PHISHING"?"🛡":result.verdict==="SUSPICIOUS"?"⚠":"✓";
    const label = result.verdict==="PHISHING"?"PHISHING DETECTED":result.verdict==="SUSPICIOUS"?"SUSPICIOUS EMAIL":"EMAIL LOOKS SAFE";

    const panel = document.createElement("div");
    panel.className = `sentinel-panel sentinel-panel-${result.verdict.toLowerCase()}`;
    panel.innerHTML = `
      <div class="sp-header">
        <span class="sp-icon">${icon}</span>
        <div class="sp-verdict"><strong>${label}</strong><span class="sp-meta">Score: ${result.score} · ${result.flags?.length||0} flag(s)</span></div>
        <button class="sp-toggle">▾</button>
      </div>
      <div class="sp-body">
        <p class="sp-summary">${result.summary||""}</p>
        ${result.flags?.length ? `<div class="sp-flags">${result.flags.map(f=>`
          <div class="sp-flag sp-sev-${(f.severity||"low").toLowerCase()}">
            <div class="sp-flag-title">${f.severity==="CRITICAL"?"🔴":f.severity==="HIGH"?"🟠":f.severity==="MEDIUM"?"🟡":"🔵"} ${f.detail}</div>
            <div class="sp-flag-explain">${f.explain||""}</div>
          </div>`).join("")}</div>` : ""}
        <p class="sp-advice">💡 ${result.advice||"Be cautious with this email."}</p>
        <div class="sp-ai-section">
          <div class="sp-ai-header">🤖 Ask AI about this email</div>
          <div class="sp-ai-messages"></div>
          <div class="sp-ai-input">
            <input type="text" class="sp-input" placeholder="Why is this dangerous?" />
            <button class="sp-send">Ask</button>
          </div>
          <p class="sp-ai-unlock" style="display:none"><a href="https://sentinel-app.com" target="_blank">🔓 Subscribe to unlock AI →</a></p>
        </div>
      </div>`;

    container.insertBefore(panel, container.firstChild);

    panel.querySelector(".sp-toggle").addEventListener("click", () => {
      const body = panel.querySelector(".sp-body");
      body.style.display = body.style.display==="none" ? "" : "none";
      panel.querySelector(".sp-toggle").textContent = body.style.display==="none" ? "▸" : "▾";
    });

    // AI chat
    const msgs    = panel.querySelector(".sp-ai-messages");
    const input   = panel.querySelector(".sp-input");
    const sendBtn = panel.querySelector(".sp-send");
    const unlock  = panel.querySelector(".sp-ai-unlock");
    const inputRow= panel.querySelector(".sp-ai-input");
    const history = [];
    const context = `Subject: "${meta.subject}". From: ${meta.fromEmail}. Verdict: ${result.verdict} score ${result.score}. Flags: ${result.flags?.map(f=>f.detail).join(", ")||"none"}.`;

    sendBtn.addEventListener("click", send);
    input.addEventListener("keydown", e => { if(e.key==="Enter") send(); });

    function send() {
      const text = input.value.trim();
      if (!text) return;
      input.value = "";
      addMsg("user", text);
      history.push({ role:"user", content:text });
      const t = addMsg("assistant", "Thinking...", true);
      chrome.runtime.sendMessage({ type:"CHAT_MESSAGE", payload:{ messages:history, context } }, res => {
        t.remove();
        if (res?.success) {
          addMsg("assistant", res.reply);
          history.push({ role:"assistant", content:res.reply });
        } else if (res?.error?.toLowerCase().includes("token") || res?.error?.toLowerCase().includes("subscribe")) {
          unlock.style.display = "block";
          inputRow.style.display = "none";
        } else {
          addMsg("assistant", `⚠ ${res?.error||"Error. Try again."}`);
        }
      });
    }

    function addMsg(role, text, typing=false) {
      const el = document.createElement("div");
      el.className = `sp-msg sp-msg-${role}${typing?" sp-typing":""}`;
      el.textContent = text;
      msgs.appendChild(el);
      msgs.scrollTop = msgs.scrollHeight;
      return el;
    }
  }

  function extractUrls(text) {
    return (text.match(/https?:\/\/[^\s<>"']+/gi)||[]).slice(0, 20);
  }

  init();
})();
