// SENTINEL v5 — popup.js

document.addEventListener("DOMContentLoaded", () => {

  // ── Tabs ──────────────────────────────────────────────────────
  document.querySelectorAll(".tab").forEach(tab => {
    tab.addEventListener("click", () => {
      document.querySelectorAll(".tab").forEach(el => el.classList.remove("active"));
      document.querySelectorAll(".panel").forEach(el => el.classList.remove("active"));
      tab.classList.add("active");
      const panel = document.getElementById("tab-" + tab.dataset.tab);
      if (panel) panel.classList.add("active");
      if (tab.dataset.tab === "history") loadHistory();
      if (tab.dataset.tab === "dashboard") loadStats();
    });
  });

  // ── Load settings on open ─────────────────────────────────────
  chrome.storage.local.get(["enabled", "showBadges", "sentinelToken"], d => {
    const enabled = d.enabled !== false;
    const badges  = d.showBadges !== false;
    setToggle("toggleEnabled", enabled);
    setToggle("toggleBadges", badges);
    if (d.sentinelToken) {
      const ti = document.getElementById("tokenInput");
      if (ti) ti.value = d.sentinelToken;
    }
    if (!enabled) {
      const pill = document.getElementById("statusPill");
      const dot  = document.getElementById("statusDot");
      const txt  = document.getElementById("statusText");
      if (pill) pill.className = "status-pill status-off";
      if (dot)  dot.className  = "status-dot dot-off";
      if (txt)  txt.textContent = "PAUSED";
    }
    const aiStatus = document.getElementById("aiStatus");
    if (aiStatus && d.sentinelToken) aiStatus.textContent = "✅ Unlocked";
  });

  loadStats();

  // ── Stats ─────────────────────────────────────────────────────
  function loadStats() {
    chrome.runtime.sendMessage({ type: "GET_STATS" }, res => {
      if (!res?.stats) return;
      const s = res.stats;
      setText("st-total", s.total);
      setText("st-phish", s.phishing);
      setText("st-sus",   s.suspicious);
      setText("st-safe",  s.safe);
    });
  }

  // ── History ───────────────────────────────────────────────────
  function loadHistory() {
    chrome.runtime.sendMessage({ type: "GET_HISTORY" }, res => {
      const list = document.getElementById("historyList");
      if (!list) return;
      const h = res?.history || [];
      if (!h.length) {
        list.innerHTML = '<div class="no-history"><span style="font-size:32px">📭</span><p>No emails scanned yet.<br>Open Gmail to start.</p></div>';
        return;
      }
      list.innerHTML = h.slice(0, 50).map(item => {
        const vClass = item.verdict === "PHISHING" ? "hi-phishing" : item.verdict === "SUSPICIOUS" ? "hi-suspicious" : "hi-safe";
        const label  = item.verdict === "PHISHING" ? "🛡 PHISHING" : item.verdict === "SUSPICIOUS" ? "⚠ SUS" : "✓ Safe";
        const time   = new Date(item.timestamp).toLocaleDateString("en-GB", { day: "numeric", month: "short", hour: "2-digit", minute: "2-digit" });
        return `<div class="history-item">
          <div class="hi-top">
            <span class="hi-subject">${escHtml(item.subject)}</span>
            <span class="hi-verdict ${vClass}">${label}</span>
          </div>
          <div class="hi-meta">Score: ${item.score} · ${item.flagCount} flag(s) · ${time}</div>
        </div>`;
      }).join("");
    });
  }

  // ── Toggles ───────────────────────────────────────────────────
  const toggleEnabled = document.getElementById("toggleEnabled");
  if (toggleEnabled) {
    toggleEnabled.addEventListener("click", function () {
      const cur = this.classList.contains("on");
      setToggle("toggleEnabled", !cur);
      chrome.storage.local.set({ enabled: !cur });
      const txt  = document.getElementById("statusText");
      const dot  = document.getElementById("statusDot");
      const pill = document.getElementById("statusPill");
      if (!cur) {
        if (txt)  txt.textContent = "ACTIVE";
        if (dot)  dot.className = "status-dot dot-on";
        if (pill) pill.className = "status-pill status-on";
      } else {
        if (txt)  txt.textContent = "PAUSED";
        if (dot)  dot.className = "status-dot dot-off";
        if (pill) pill.className = "status-pill status-off";
      }
    });
  }

  const toggleBadges = document.getElementById("toggleBadges");
  if (toggleBadges) {
    toggleBadges.addEventListener("click", function () {
      const cur = this.classList.contains("on");
      setToggle("toggleBadges", !cur);
      chrome.storage.local.set({ showBadges: !cur });
    });
  }

  // ── Token ─────────────────────────────────────────────────────
  const saveTokenBtn = document.getElementById("saveToken");
  if (saveTokenBtn) {
    saveTokenBtn.addEventListener("click", () => {
      const tokenInput = document.getElementById("tokenInput");
      const status     = document.getElementById("tokenStatus");
      const aiEl       = document.getElementById("aiStatus");
      const token      = (tokenInput?.value || "").trim().toUpperCase();
      if (!token) { setStatus(status, "Enter a token first.", "ts-invalid"); return; }
      if (!token.match(/^SNT-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$/)) {
        setStatus(status, "Invalid format (SNT-XXXX-XXXX-XXXX)", "ts-invalid"); return;
      }
      setStatus(status, "Verifying...", "ts-checking");
      chrome.runtime.sendMessage({ type: "VALIDATE_TOKEN", token }, res => {
        if (res?.valid) {
          chrome.storage.local.set({ sentinelToken: token });
          setStatus(status, "✅ Token verified — AI chat unlocked!", "ts-valid");
          if (aiEl) aiEl.textContent = "✅ Unlocked";
        } else {
          setStatus(status, `❌ ${res?.error || "Invalid token. Check your subscription."}`, "ts-invalid");
        }
      });
    });
  }

  const goSubscribeBtn = document.getElementById("goSubscribe");
  if (goSubscribeBtn) {
    goSubscribeBtn.addEventListener("click", () => {
      chrome.tabs.create({ url: "https://sentinel-app.com" });
    });
  }

  const clearHistoryBtn = document.getElementById("clearHistory");
  if (clearHistoryBtn) {
    clearHistoryBtn.addEventListener("click", () => {
      if (!confirm("Clear all scan history?")) return;
      chrome.runtime.sendMessage({ type: "CLEAR_HISTORY" }, () => loadStats());
    });
  }

  // ── Helpers ───────────────────────────────────────────────────
  function setToggle(id, on) {
    const el = document.getElementById(id);
    if (el) el.classList.toggle("on", on);
  }
  function setText(id, val) {
    const el = document.getElementById(id);
    if (el) el.textContent = val ?? 0;
  }
  function setStatus(el, msg, cls) {
    if (!el) return;
    el.textContent = msg;
    el.className = "token-status " + cls;
  }
  function escHtml(s) {
    return (s || "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  }

}); // end DOMContentLoaded
