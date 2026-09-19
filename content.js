// content.js
// Blue Team content script: extract minimal security signals only (NO HTML, NO PII)

(function () {
  function safeLowerTextSample() {
    try {
      return (document.body?.innerText || "").slice(0, 800).toLowerCase();
    } catch {
      return "";
    }
  }

  function countInputsByType(type) {
    try {
      return document.querySelectorAll(`input[type="${type}"]`).length;
    } catch {
      return 0;
    }
  }

  function countCreditCardLikeInputs() {
    try {
      const inputs = Array.from(document.querySelectorAll("input"));
      return inputs.filter(i => {
        const ac = (i.autocomplete || "").toLowerCase();
        return ["cc-number", "cardnumber", "credit-card"].includes(ac);
      }).length;
    } catch {
      return 0;
    }
  }

  function hasExternalFormAction() {
    try {
      const forms = Array.from(document.querySelectorAll("form"));
      const pageHost = location.hostname;
      return forms.some(f => {
        const action = f.getAttribute("action") || "";
        if (!action) return false;
        let u;
        try {
          u = new URL(action, location.href);
        } catch {
          return false;
        }
        return !!u.hostname && u.hostname !== pageHost;
      });
    } catch {
      return false;
    }
  }

  function countSuspiciousDownloadLinks() {
    try {
      const links = Array.from(document.querySelectorAll("a"));
      return links
        .map(a => a.getAttribute("href") || "")
        .filter(href => /\.(exe|msi|bat|scr|ps1|jar|apk|zip|rar)$/i.test(href))
        .length;
    } catch {
      return 0;
    }
  }

  function keywordStats(textSample, list) {
    const hits = [];
    for (const k of list) {
      if (textSample.includes(k)) hits.push(k);
    }
    return { total: hits.length, unique: hits.length };
  }

  function collectSignals() {
    const hostname = location.hostname;
    const protocol = location.protocol;
    const text = safeLowerTextSample();

    const urgentKeywords = [
      "urgent",
      "immediately",
      "act now",
      "within 24 hours",
      "ด่วน",
      "เร่งด่วน",
      "ทันที",
      "ภายใน 24 ชั่วโมง"
    ];
    const threatKeywords = [
      "account will be suspended",
      "account locked",
      "security alert",
      "suspicious login",
      "บัญชีจะถูกระงับ",
      "บัญชีถูกล็อก",
      "ความปลอดภัย",
      "ตรวจพบการเข้าสู่ระบบผิดปกติ"
    ];
    const downloadKeywords = [
      "download",
      "install",
      "update required",
      "ดาวน์โหลด",
      "ติดตั้ง",
      "ต้องอัปเดต"
    ];

    const urgent = keywordStats(text, urgentKeywords);
    const threat = keywordStats(text, threatKeywords);
    const down = keywordStats(text, downloadKeywords);

    const passwordInputs = countInputsByType("password");
    const emailInputs = countInputsByType("email");
    const phoneInputs = countInputsByType("tel");
    const creditCardLikeInputs = countCreditCardLikeInputs();

    const hasPasswordField = passwordInputs > 0;
    const hasSensitiveInputs = (emailInputs + phoneInputs + creditCardLikeInputs) > 0;
    const formActionExternal = hasExternalFormAction();

    const suspiciousDownloadLinks = countSuspiciousDownloadLinks();

    return {
      page: { hostname, protocol },
      fields: {
        hasPasswordField,
        hasSensitiveInputs,
        formActionExternal,
        passwordInputs,
        emailInputs,
        creditCardLikeInputs
      },
      keywords: {
        urgentLanguage: urgent.total > 0,
        accountThreats: threat.total > 0,
        downloadExecutable: down.total > 0 || suspiciousDownloadLinks > 0,
        totalKeywordHits: urgent.total + threat.total + down.total,
        uniqueKeywordsHit: urgent.unique + threat.unique + down.unique
      },
      downloads: {
        suspiciousDownloadLinks
      }
    };
  }

  function sendSignals() {
    try {
      const signals = collectSignals();
      chrome.runtime.sendMessage({ type: "phishing_signals", signals });
    } catch (err) {
      // Fail silently – never break the page
      console.warn("Security content script error:", err);
    }
  }

  // Initial + post-load refresh (text and forms are often not ready at document_start)
  sendSignals();
  document.addEventListener("DOMContentLoaded", () => setTimeout(sendSignals, 250), { once: true });
  window.addEventListener("load", () => setTimeout(sendSignals, 250), { once: true });

  chrome.runtime.onMessage.addListener((msg) => {
    if (msg?.type !== "REQUEST_PHISHING_SIGNALS") return;
    sendSignals();
  });
})();
