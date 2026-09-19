(() => {
  const SESSION_KEY = "tabRiskState";
  const DISMISS_MS = 10 * 60 * 1000;

  async function getConfig() {
    return await chrome.storage.sync.get({
      geminiEnabled: false,
      aiProxyEnabled: true,
      aiProxyUrl: "http://localhost:3000/scan",
      aiProxyToken: "blue-team-ploy"
    });
  }

  async function setConfig(next) {
    await chrome.storage.sync.set(next);
  }

  async function getActiveTabId() {
    try {
      const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
      return tabs?.[0]?.id ?? null;
    } catch {
      return null;
    }
  }

  async function getActiveTab() {
    try {
      const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
      return tabs?.[0] || null;
    } catch {
      return null;
    }
  }

  async function getLatestEntryFromBackground(tabId) {
    try {
      const res = await chrome.runtime.sendMessage({ type: "GET_TAB_STATE", tabId });
      if (!res?.ok) return null;
      return res.entry || null;
    } catch {
      return null;
    }
  }

  function isRestrictedUrl(url) {
    const u = String(url || "");
    return (
      u.startsWith("chrome://") ||
      u.startsWith("edge://") ||
      u.startsWith("about:") ||
      u.startsWith("chrome-extension://") ||
      u.startsWith("view-source:")
    );
  }

  async function getState() {
    try {
      const out = await chrome.storage.session.get({ [SESSION_KEY]: {} });
      return out[SESSION_KEY] || {};
    } catch {
      const out = await chrome.storage.local.get({ [SESSION_KEY]: {} });
      return out[SESSION_KEY] || {};
    }
  }

  async function setState(state) {
    try {
      await chrome.storage.session.set({ [SESSION_KEY]: state });
    } catch {
      await chrome.storage.local.set({ [SESSION_KEY]: state });
    }
  }

  const $ = (id) => document.getElementById(id);

  function setRiskBadge(level) {
    const el = $("riskLevel");
    if (!el) return;
    el.textContent = (level || "unknown").toUpperCase();
    el.dataset.level = level || "unknown";
  }

  function pad2(n) {
    return String(n).padStart(2, "0");
  }

  function formatTime(ts) {
    if (!ts || !Number.isFinite(Number(ts))) return "—";
    const d = new Date(Number(ts));
    return `${pad2(d.getHours())}:${pad2(d.getMinutes())}:${pad2(d.getSeconds())}`;
  }

  function toEnglishLevel(level) {
    if (level === "high") return "High";
    if (level === "medium") return "Medium";
    if (level === "low") return "Low";
    return "Unknown";
  }

  function defaultAdvice(level, summary) {
    const lines = [];
    const s = summary || {};
    const protocol = s?.page?.protocol;
    const hasPw = !!s?.fields?.hasPasswordField;
    const hasSensitive = !!s?.fields?.hasSensitiveInputs;
    const formExt = !!s?.fields?.formActionExternal;
    const keywordHits = Number(s?.keywords?.totalKeywordHits || 0);
    const downloads = Number(s?.downloads?.suspiciousDownloadLinks || 0);

    if (level === "high") {
      lines.push("- Stop: Do NOT enter passwords, OTP, or financial information.");
      lines.push("- Verify the domain name carefully before logging in.");
      if (protocol === "http:") lines.push("- This page does not use HTTPS.");
      if (formExt) lines.push("- Form submits data to an external domain.");
      if (downloads > 0) lines.push("- Suspicious download links detected.");
    }
    else if (level === "medium") {
      lines.push("- Be cautious when entering sensitive information.");
      if (hasPw || hasSensitive) lines.push("- Login or sensitive forms detected.");
      if (keywordHits > 0) lines.push("- Urgency or threatening language detected.");
      if (downloads > 0) lines.push("- Suspicious download links present.");
    }
    else {
      lines.push("- No major threats detected.");
      lines.push("- Always verify domains before entering sensitive data.");
    }

    if (lines.length === 0) return "—";
    return lines.join("\n");
  }

  function pill(text, variant) {
    const el = document.createElement("span");
    el.className = `pill ${variant}`;
    el.textContent = text;
    return el;
  }

  function card(title, valueText, pillEl) {
    const el = document.createElement("div");
    el.className = "card";

    const t = document.createElement("div");
    t.className = "cardTitle";
    t.textContent = title;

    const v = document.createElement("div");
    v.className = "cardValue";

    const left = document.createElement("span");
    left.textContent = valueText;
    v.appendChild(left);
    if (pillEl) v.appendChild(pillEl);

    el.appendChild(t);
    el.appendChild(v);
    return el;
  }

  function showToast(message, timeoutMs = 2600) {
    const el = $("toast");
    if (!el) return;
    el.textContent = message;
    el.classList.remove("hidden");
    window.clearTimeout(showToast._t);

    // If timeoutMs is 0/falsey, keep it visible until next call.
    if (!timeoutMs) return;

    showToast._t = window.setTimeout(() => {
      el.classList.add("hidden");
    }, timeoutMs);
  }

  function hideToast() {
    const el = $("toast");
    if (!el) return;
    window.clearTimeout(showToast._t);
    el.classList.add("hidden");
  }

  function render(entry) {
    const hostname = entry?.hostname || "unknown";
    const assessment = entry?.assessment || {};
    const level = assessment.level || "unknown";
    const score = Number.isFinite(assessment.score) ? assessment.score : null;
    const reasons = Array.isArray(assessment.reasons) ? assessment.reasons : [];
    const updatedAt = entry?.updatedAt;

    $("hostname").textContent = hostname;
    setRiskBadge(level);
    $("score").textContent = score ?? "—";
    $("updatedAt").textContent = formatTime(updatedAt);

    // Checks dashboard
    const checksEl = $("checks");
    if (checksEl) {
      checksEl.innerHTML = "";
      const summary = entry?.signalsSummary || {};

      const protocol = summary?.page?.protocol || "—";
      const isHttps = protocol === "https:";
      checksEl.appendChild(
        card(
          "Connection",
          isHttps ? "HTTPS" : (protocol === "http:" ? "HTTP" : "Unknown"),
          pill(isHttps ? "OK" : "Warning", isHttps ? "ok" : "warn")
        )
      );

      const hasPw = !!summary?.fields?.hasPasswordField;
      checksEl.appendChild(
        card(
          "Password Field",
          hasPw ? "Detected" : "Not Found",
          pill(hasPw ? "Warning" : "OK", hasPw ? "warn" : "ok")
        )
      );

      const hasSensitive = !!summary?.fields?.hasSensitiveInputs;
      checksEl.appendChild(
        card(
          "Sensitive Inputs",
          hasSensitive ? "Form Present" : "Not Found",
          pill(hasSensitive ? "Warning" : "OK", hasSensitive ? "warn" : "ok")
        )
      );

      const formExt = !!summary?.fields?.formActionExternal;
      checksEl.appendChild(
        card(
          "External Form",
          formExt ? "Detected" : "Not Found",
          pill(formExt ? "Danger" : "OK", formExt ? "danger" : "ok")
        )
      );

      const keywordHits = Number(summary?.keywords?.totalKeywordHits || 0);
      checksEl.appendChild(
        card(
          "Urgency Keywords",
          keywordHits ? `${keywordHits} hits` : "None",
          pill(keywordHits ? "Warning" : "OK", keywordHits ? "warn" : "ok")
        )
      );

      const downloads = Number(summary?.downloads?.suspiciousDownloadLinks || 0);
      checksEl.appendChild(
        card(
          "Suspicious Downloads",
          downloads ? `${downloads} links` : "None",
          pill(downloads ? "Warning" : "OK", downloads ? "warn" : "ok")
        )
      );
    }

    const reasonsEl = $("reasons");
    reasonsEl.innerHTML = "";
    if (reasons.length === 0) {
      reasonsEl.innerHTML = "<li>ยังไม่พบสัญญาณเฉพาะเจาะจง</li>";
    } else {
      reasons.slice(0, 6).forEach(r => {
        const li = document.createElement("li");
        li.textContent = r;
        reasonsEl.appendChild(li);
      });
    }

    const adviceText = defaultAdvice(level, entry?.signalsSummary);
    $("advice").textContent = adviceText;

    const aiAdviceWrap = $("aiAdviceWrap");
    const aiAdvice = entry?.geminiAdvice || "";
    if (aiAdviceWrap && $("aiAdvice")) {
      if (aiAdvice) {
        aiAdviceWrap.classList.remove("hidden");
        $("aiAdvice").textContent = aiAdvice;
      } else {
        aiAdviceWrap.classList.add("hidden");
        $("aiAdvice").textContent = "";
      }
    }

    const suppressed = entry?.suppressUntil && Date.now() < entry.suppressUntil;
    $("suppressed").textContent = suppressed
      ? "Warnings temporarily dismissed for this tab (10 minutes)"
      : `Risk Level: ${toEnglishLevel(level)}`
  }

  function buildReport(entry) {
    const hostname = entry?.hostname || "unknown";
    const assessment = entry?.assessment || {};
    const level = assessment.level || "unknown";
    const score = Number.isFinite(assessment.score) ? assessment.score : "—";
    const reasons = Array.isArray(assessment.reasons) ? assessment.reasons : [];
    const updatedAt = formatTime(entry?.updatedAt);
    const s = entry?.signalsSummary || {};

    const lines = [];
    lines.push("AI Blue Team – รายงานสรุปความปลอดภัย");
    lines.push(`ไซต์: ${hostname}`);
    lines.push(`ความเสี่ยง: ${toThaiLevel(level)} (${String(level).toUpperCase()})`);
    lines.push(`คะแนน: ${score}`);
    lines.push(`อัปเดต: ${updatedAt}`);
    lines.push("");
    lines.push("สรุปเช็ค:");
    lines.push(`- โปรโตคอล: ${s?.page?.protocol || "—"}`);
    lines.push(`- ช่องรหัสผ่าน: ${s?.fields?.hasPasswordField ? "พบ" : "ไม่พบ"}`);
    lines.push(`- ฟอร์มข้อมูลสำคัญ: ${s?.fields?.hasSensitiveInputs ? "พบ" : "ไม่พบ"}`);
    lines.push(`- ฟอร์มส่งออกนอกโดเมน: ${s?.fields?.formActionExternal ? "พบ" : "ไม่พบ"}`);
    lines.push(`- คำเร่งด่วน/ข่มขู่: ${Number(s?.keywords?.totalKeywordHits || 0)}`);
    lines.push(`- ลิงก์ดาวน์โหลดเสี่ยง: ${Number(s?.downloads?.suspiciousDownloadLinks || 0)}`);
    lines.push("");
    lines.push("สัญญาณที่ตรวจพบ:");
    if (reasons.length === 0) {
      lines.push("- (ไม่มี)");
    } else {
      reasons.slice(0, 10).forEach(r => lines.push(`- ${r}`));
    }
    if (entry?.geminiAdvice) {
      lines.push("");
      lines.push("AI อธิบายความเสี่ยง:");
      lines.push(entry.geminiAdvice);
    }
    return lines.join("\n");
  }

  async function copyToClipboard(text) {
    try {
      await navigator.clipboard.writeText(text);
      return true;
    } catch {
      try {
        const ta = document.createElement("textarea");
        ta.value = text;
        ta.setAttribute("readonly", "true");
        ta.style.position = "fixed";
        ta.style.left = "-9999px";
        document.body.appendChild(ta);
        ta.select();
        const ok = document.execCommand("copy");
        document.body.removeChild(ta);
        return ok;
      } catch {
        return false;
      }
    }
  }

  async function dismissForTab(tabId) {
    const state = await getState();
    state[String(tabId)] = {
      ...(state[String(tabId)] || {}),
      suppressUntil: Date.now() + DISMISS_MS
    };
    await setState(state);
  }

  async function init() {
    const activeTab = await getActiveTab();
    const tabId = activeTab?.id ?? null;
    if (!tabId) return render(null);

    const state = await getState();
    render(state[String(tabId)] || null);

    // Try to re-render with the freshest state from the service worker.
    const latest = await getLatestEntryFromBackground(tabId);
    if (latest) render(latest);

    // Load AI settings
    try {
      const cfg = await getConfig();
      if ($("geminiEnabled")) $("geminiEnabled").checked = !!cfg.geminiEnabled;
      if ($("aiProxyEnabled")) $("aiProxyEnabled").checked = cfg.aiProxyEnabled !== false;
      if ($("aiProxyUrl")) $("aiProxyUrl").value = cfg.aiProxyUrl || "http://localhost:3000/scan";
      if ($("aiProxyToken")) $("aiProxyToken").value = cfg.aiProxyToken || "blue-team-ploy";
    } catch {
      // ignore
    }

    $("btnDismiss")?.addEventListener("click", async () => {
      await dismissForTab(tabId);
      const state2 = await getState();
      render(state2[String(tabId)] || null);
      showToast("ปิดการเตือน 10 นาทีแล้ว");
    });

    $("btnContinue")?.addEventListener("click", () => window.close());

    $("btnRescan")?.addEventListener("click", async () => {
      try {
        const tab = await getActiveTab();
        const url = tab?.url || "";
        if (isRestrictedUrl(url)) {
          showToast("แท็บนี้สแกนไม่ได้ (chrome:// / edge:// ฯลฯ)");
          return;
        }

        const before = await getLatestEntryFromBackground(tabId);
        const beforeTs = Number(before?.updatedAt || 0);

        try {
          await chrome.tabs.sendMessage(tabId, { type: "REQUEST_PHISHING_SIGNALS" });
        } catch (e) {
          const msg = String(e?.message || e || "");
          const missingReceiver = /Receiving end does not exist|Could not establish connection/i.test(msg);
          if (!missingReceiver) throw e;

          // If the tab existed before the extension (re)loaded, the content script may not be present.
          // Inject it and retry once.
          try {
            if (chrome?.scripting?.executeScript) {
              await chrome.scripting.executeScript({
                target: { tabId },
                files: ["content.js"]
              });
              await chrome.tabs.sendMessage(tabId, { type: "REQUEST_PHISHING_SIGNALS" });
            } else {
              throw new Error("scripting_api_unavailable");
            }
          } catch (injErr) {
            const injMsg = String(injErr?.message || injErr || "");
            throw new Error(`inject_failed: ${injMsg}`);
          }
        }
        showToast("กำลังสแกนใหม่...", 0);

        // Poll a few times for updated state (background writes to storage after receiving signals)
        let updated = null;
        for (let i = 0; i < 10; i++) {
          await new Promise(r => setTimeout(r, 250));
          const entry = await getLatestEntryFromBackground(tabId);
          const ts = Number(entry?.updatedAt || 0);
          if (entry && ts && ts > beforeTs) {
            updated = entry;
            break;
          }
        }

        if (updated) {
          render(updated);
          showToast("อัปเดตผลสแกนแล้ว", 2000);

          // Optional: trigger AI right after a successful rescan (helps confirm proxy logs)
          const cfg = await getConfig();
          if (cfg?.geminiEnabled) {
            showToast("กำลังถาม AI...", 0);
            const res = await chrome.runtime.sendMessage({ type: "REQUEST_GEMINI_ADVICE", tabId });
            if (res?.ok) {
              const state2 = await getState();
              state2[String(tabId)] = {
                ...(state2[String(tabId)] || {}),
                geminiAdvice: res.advice,
                updatedAt: Date.now()
              };
              await setState(state2);
              render(state2[String(tabId)] || null);
              showToast("ได้คำตอบจาก AI แล้ว", 2200);
            } else if (res?.details) {
              showToast(`AI ไม่สำเร็จ: ${String(res.details).slice(0, 120)}`, 4200);
            } else {
              showToast("AI ไม่สำเร็จ", 3200);
            }
          }
        } else {
          // fall back to local read
          const state2 = await getState();
          render(state2[String(tabId)] || null);
          showToast("ยังไม่เห็นผลสแกนใหม่ ลองรีเฟรชหน้าเว็บหรือเปิดเว็บ http/https ทั่วไป", 4200);
        }
      } catch (err) {
        const msg = String(err?.message || err || "");
        showToast(msg
          ? `สแกนใหม่ไม่สำเร็จ: ${msg.slice(0, 120)}`
          : "สแกนใหม่ไม่สำเร็จ (แท็บนี้อาจบล็อกสคริปต์)",
          4200);
      }
    });

    $("btnSaveGemini")?.addEventListener("click", async () => {
      try {
        const enabled = !!$("geminiEnabled")?.checked;
        const proxyEnabled = !!$("aiProxyEnabled")?.checked;
        const proxyUrl = String($("aiProxyUrl")?.value || "").trim() || "http://localhost:3000/scan";
        const proxyToken = String($("aiProxyToken")?.value || "").trim() || "blue-team-ploy";
        await setConfig({
          geminiEnabled: enabled,
          aiProxyEnabled: proxyEnabled,
          aiProxyUrl: proxyUrl,
          aiProxyToken: proxyToken
        });
        showToast("บันทึกการตั้งค่า AI แล้ว");
      } catch {
        showToast("บันทึกไม่สำเร็จ");
      }
    });

    $("btnAskAI")?.addEventListener("click", async () => {
      try {
        showToast("กำลังถาม AI...", 0);
        const res = await chrome.runtime.sendMessage({ type: "REQUEST_GEMINI_ADVICE", tabId });

        if (!res) {
          showToast("ไม่มีการตอบกลับจากระบบ AI (ลอง Reload extension และเปิด ai-proxy)", 4200);
          return;
        }
        if (!res?.ok) {
          const err = res?.error || "unknown";
          if (err === "no_scan_data") showToast("ยังไม่มีผลสแกน ลองกด “สแกนใหม่” ก่อน");
          else if (err === "no_ai_response") {
            const details = String(res?.details || "").trim();
            showToast(details
              ? `AI ไม่สำเร็จ: ${details.slice(0, 120)}`
              : "AI ยังไม่ตอบ (เช็คว่า ai-proxy รันอยู่ และคีย์ใน .env ถูกต้อง)",
              4200);
          }
          else if (err === "missing_tab") showToast("หาแท็บไม่เจอ");
          else showToast("ถาม AI ไม่สำเร็จ");
          return;
        }

        const state2 = await getState();
        state2[String(tabId)] = {
          ...(state2[String(tabId)] || {}),
          geminiAdvice: res.advice,
          updatedAt: Date.now()
        };
        await setState(state2);
        render(state2[String(tabId)] || null);
        showToast("ได้คำตอบจาก AI แล้ว", 2200);
      } catch (err) {
        const msg = String(err?.message || err || "").trim();
        showToast(msg
          ? `ถาม AI ไม่สำเร็จ: ${msg.slice(0, 120)}`
          : "ถาม AI ไม่สำเร็จ (service worker อาจยังไม่พร้อม)",
          4200);
      }
    });

    $("btnCopy")?.addEventListener("click", async () => {
      const state2 = await getState();
      const entry = state2[String(tabId)] || null;
      const report = buildReport(entry);
      const ok = await copyToClipboard(report);
      showToast(ok ? "คัดลอกรายงานแล้ว" : "คัดลอกไม่สำเร็จ");
    });
  }

  document.addEventListener("DOMContentLoaded", init);
})();
