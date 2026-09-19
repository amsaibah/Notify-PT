import { assessPhishingRisk } from "./rules/phishingRules.js";
import { getSecurityRiskExplanation } from "./ai/geminiClient.js";

const WARNING_COOLDOWN_MS = 10 * 60 * 1000;
const SESSION_KEY = "tabRiskState";

const NOTIFY_ICON_DATA_URL =
  "data:image/svg+xml;charset=utf-8," +
  encodeURIComponent(
    `<svg xmlns="http://www.w3.org/2000/svg" width="128" height="128" viewBox="0 0 128 128">
      <rect width="128" height="128" rx="24" fill="#0b1220"/>
      <path d="M64 16l34 14v30c0 28-18 48-34 52C48 108 30 88 30 60V30l34-14z" fill="#1a73e8"/>
      <path d="M64 32l22 9v19c0 19-12 33-22 36-10-3-22-17-22-36V41l22-9z" fill="#e8eefc" opacity="0.20"/>
      <path d="M58 66l-8-8 5-5 3 3 15-15 5 5-20 20z" fill="#e8eefc"/>
    </svg>`
  );

async function getConfig() {
  return await chrome.storage.sync.get({
    geminiEnabled: false,
    geminiApiKey: "",
    aiProxyEnabled: true,
    aiProxyUrl: "http://localhost:3000/scan",
    aiProxyToken: "blue-team-ploy"
  });
}

async function getSessionState() {
  try {
    const out = await chrome.storage.session.get({ [SESSION_KEY]: {} });
    return out[SESSION_KEY] || {};
  } catch {
    const out = await chrome.storage.local.get({ [SESSION_KEY]: {} });
    return out[SESSION_KEY] || {};
  }
}

async function setSessionState(state) {
  try {
    await chrome.storage.session.set({ [SESSION_KEY]: state });
  } catch {
    await chrome.storage.local.set({ [SESSION_KEY]: state });
  }
}

function badgeForLevel(level) {
  if (level === "high") return { text: "!", color: "#d93025" };
  if (level === "medium") return { text: "?", color: "#f29900" };
  return { text: "", color: "#1a73e8" };
}

async function setBadge(tabId, level) {
  const b = badgeForLevel(level);
  await chrome.action.setBadgeText({ tabId, text: b.text });
  await chrome.action.setBadgeBackgroundColor({ tabId, color: b.color });
}

async function maybeNotify(tabId, hostname, assessment) {
  const state = await getSessionState();
  const now = Date.now();

  const prev = state[String(tabId)] || {};
  if (assessment.level !== "high") return;
  if (now - (prev.lastWarnAt || 0) < WARNING_COOLDOWN_MS) return;

  try {
    await chrome.notifications.create(`warn:${tabId}:${now}`, {
      type: "basic",
      iconUrl: NOTIFY_ICON_DATA_URL,
      title: "Security Warning",
      message:
        `Potential phishing detected.\n` +
        `Site: ${hostname}\n` +
        `Risk: HIGH`,
      priority: 2
    });
  } catch (err) {
    // Never block scanning/AI because of notification failures.
    console.warn("Notification failed:", err);
  }

  state[String(tabId)] = { ...prev, lastWarnAt: now };
  await setSessionState(state);
}

async function callGemini(summary) {
  const { geminiEnabled, geminiApiKey } = await getConfig();
  if (!geminiEnabled || !geminiApiKey) return null;

  const endpoint =
    `https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key=${geminiApiKey}`;

  const body = {
    contents: [{
      role: "user",
      parts: [
        { text: "You are a blue-team security assistant." },
        { text: JSON.stringify(summary) }
      ]
    }],
    generationConfig: { temperature: 0.2, maxOutputTokens: 150 }
  };

  let res;
  try {
    res = await fetch(endpoint, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body)
    });
  } catch (err) {
    console.warn("Gemini fetch failed:", err);
    return null;
  }

  if (!res.ok) {
    let details = "";
    try {
      details = await res.text();
    } catch {
      // ignore
    }
    console.warn("Gemini HTTP error:", res.status, details);
    return null;
  }

  let json;
  try {
    json = await res.json();
  } catch (err) {
    console.warn("Gemini JSON parse failed:", err);
    return null;
  }

  return json?.candidates?.[0]?.content?.parts?.[0]?.text || null;
}

async function callAiDetailed(summary) {
  const { geminiEnabled, aiProxyEnabled, aiProxyUrl, aiProxyToken } = await getConfig();
  if (!geminiEnabled) return { text: null, error: "disabled" };
  if (!aiProxyEnabled) return { text: null, error: "proxy_disabled" };

  try {
    const text = await getSecurityRiskExplanation(summary, {
      proxyUrl: aiProxyUrl,
      extensionToken: aiProxyToken
    });
    return { text, error: null };
  } catch (err) {
    const msg = err?.message || String(err);
    console.warn("AI proxy call failed:", msg);
    return { text: null, error: msg };
  }
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg?.type === "GET_TAB_STATE") {
    (async () => {
      try {
        const tabId = msg?.tabId;
        if (typeof tabId !== "number") return sendResponse({ ok: false, error: "missing_tab" });

        const state = await getSessionState();
        return sendResponse({ ok: true, entry: state[String(tabId)] || null });
      } catch (err) {
        console.warn("GET_TAB_STATE failed:", err);
        return sendResponse({ ok: false, error: "internal_error" });
      }
    })();
    return true;
  }

  if (msg?.type === "REQUEST_GEMINI_ADVICE") {
    (async () => {
      try {
        const tabId = msg?.tabId;
        if (typeof tabId !== "number") return sendResponse({ ok: false, error: "missing_tab" });

        const state = await getSessionState();
        const entry = state[String(tabId)] || null;
        const hostname = entry?.hostname;
        const assessment = entry?.assessment;

        if (!hostname || !assessment) {
          return sendResponse({ ok: false, error: "no_scan_data" });
        }

        const out = await callAiDetailed({ page: { hostname }, assessment });
        if (!out.text) return sendResponse({ ok: false, error: "no_ai_response", details: out.error });

        state[String(tabId)] = { ...(entry || {}), geminiAdvice: out.text, updatedAt: Date.now() };
        await setSessionState(state);
        return sendResponse({ ok: true, advice: out.text });
      } catch (err) {
        console.warn("REQUEST_GEMINI_ADVICE failed:", err);
        return sendResponse({ ok: false, error: "internal_error" });
      }
    })();
    return true;
  }

  const isPhishingSignals = msg?.type === "phishing_signals";
  const isLegacySecuritySignals = msg?.type === "SECURITY_SIGNALS";
  if (!isPhishingSignals && !isLegacySecuritySignals) return;

  const tabId = sender.tab?.id;
  if (typeof tabId !== "number") return;

  (async () => {
    try {
    // Normalize signals to the schema used by rules/phishingRules.js
    let signals = {};
    if (isPhishingSignals) {
      signals = msg.signals || {};
    } else {
      // Legacy content script shape
      const p = msg.payload || {};
      signals = {
        page: { hostname: p.hostname, protocol: p.protocol },
        fields: {
          hasPasswordField: !!p?.inputs?.password,
          hasSensitiveInputs: !!(p?.inputs?.email || p?.inputs?.phone || p?.inputs?.creditCard),
          formActionExternal: false
        },
        keywords: {
          urgentLanguage: Number(p?.indicators?.riskyKeywordsDetected || 0) > 0,
          accountThreats: false,
          downloadExecutable: Number(p?.indicators?.suspiciousDownloads || 0) > 0,
          totalKeywordHits: Number(p?.indicators?.riskyKeywordsDetected || 0),
          uniqueKeywordsHit: Number(p?.indicators?.riskyKeywordsDetected || 0)
        },
        downloads: {
          suspiciousDownloadLinks: Number(p?.indicators?.suspiciousDownloads || 0)
        }
      };
    }

    let hostname = signals.page?.hostname || "unknown";
    if (hostname === "unknown" && sender.tab?.url) {
      try {
        hostname = new URL(sender.tab.url).hostname || "unknown";
      } catch {
        // ignore
      }
    }

    const assessment = assessPhishingRisk(signals);

    await setBadge(tabId, assessment.level);
    await maybeNotify(tabId, hostname, assessment);

    const state = await getSessionState();
    state[String(tabId)] = {
      hostname,
      assessment,
      signalsSummary: {
        page: {
          hostname,
          protocol: signals?.page?.protocol
        },
        fields: {
          hasPasswordField: !!signals?.fields?.hasPasswordField,
          hasSensitiveInputs: !!signals?.fields?.hasSensitiveInputs,
          formActionExternal: !!signals?.fields?.formActionExternal
        },
        keywords: {
          totalKeywordHits: Number(signals?.keywords?.totalKeywordHits || 0),
          uniqueKeywordsHit: Number(signals?.keywords?.uniqueKeywordsHit || 0)
        },
        downloads: {
          suspiciousDownloadLinks: Number(signals?.downloads?.suspiciousDownloadLinks || 0)
        }
      },
      updatedAt: Date.now()
    };
    await setSessionState(state);

    const advice = (assessment?.level === "high")
      ? (await callAiDetailed({ page: { hostname }, assessment })).text
      : null;

    if (advice) {
      state[String(tabId)].geminiAdvice = advice;
      await setSessionState(state);
    }
    } catch (err) {
      console.warn("Processing phishing signals failed:", err);
    }
  })();
});
