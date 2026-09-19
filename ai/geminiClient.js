// AI Proxy client for security risk explanation
// Extension → Your Server → Gemini

const DEFAULT_AI_PROXY_URL = "http://localhost:3000/scan";
const DEFAULT_EXTENSION_TOKEN = "blue-team-ploy";
const MAX_PAYLOAD_CHARS = 3500;

function looksLikeHtml(s) {
  const t = String(s ?? "");
  return /<\s*\/?\s*[a-z][\s\S]*>/i.test(t);
}

function clampInt(n, fallback = 0) {
  const x = Number(n);
  return Number.isFinite(x) ? Math.max(0, Math.floor(x)) : fallback;
}

function safeString(s, maxLen = 200) {
  const t = (s == null) ? "" : String(s);
  const trimmed = t.trim().slice(0, maxLen);
  return looksLikeHtml(trimmed) ? "" : trimmed;
}

function sanitizeSummary(summary) {
  const s = summary || {};
  const out = {
    page: {
      hostname: safeString(s?.page?.hostname, 200),
      protocol: safeString(s?.page?.protocol, 10)
    },
    fields: {
      passwordInputs: clampInt(s?.fields?.passwordInputs),
      emailInputs: clampInt(s?.fields?.emailInputs),
      creditCardLikeInputs: clampInt(s?.fields?.creditCardLikeInputs)
    },
    keywords: {
      totalKeywordHits: clampInt(s?.keywords?.totalKeywordHits),
      uniqueKeywordsHit: clampInt(s?.keywords?.uniqueKeywordsHit)
    },
    assessment: {
      level: safeString(s?.assessment?.level, 12) || "unknown",
      score: Number.isFinite(Number(s?.assessment?.score))
        ? Number(s.assessment.score)
        : undefined,
      reasons: Array.isArray(s?.assessment?.reasons)
        ? s.assessment.reasons
            .map(r => safeString(r, 160))
            .filter(Boolean)
            .slice(0, 6)
        : []
    }
  };

  let json = JSON.stringify(out);

  if (json.length > MAX_PAYLOAD_CHARS) {
    out.assessment.reasons = out.assessment.reasons.slice(0, 3);
    json = JSON.stringify(out);
  }

  if (looksLikeHtml(json)) return null;

  return out;
}

/**
 * CALL YOUR BACKEND (NOT GEMINI)
 */
export async function getSecurityRiskExplanation(summary, signal) {

  // Back-compat overload:
  // - old: (summary, signal)
  // - new: (summary, { signal, proxyUrl, extensionToken })
  let proxyUrl = DEFAULT_AI_PROXY_URL;
  let extensionToken = DEFAULT_EXTENSION_TOKEN;
  let abortSignal = signal;

  if (signal && typeof signal === "object" && ("proxyUrl" in signal || "extensionToken" in signal || "signal" in signal)) {
    proxyUrl = signal.proxyUrl || DEFAULT_AI_PROXY_URL;
    extensionToken = signal.extensionToken || DEFAULT_EXTENSION_TOKEN;
    abortSignal = signal.signal;
  }

  const sanitized = sanitizeSummary(summary);
  if (!sanitized) return null;

  let res;

  try {
    res = await fetch(proxyUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",

        // 🔥 simple extension auth (VERY recommended)
        "x-extension-token": extensionToken
      },
      body: JSON.stringify({
        summary: sanitized
      }),
      signal: abortSignal
    });

  } catch (err) {
    throw new Error(`proxy_unreachable: ${err?.message || String(err)}`);
  }

  if (!res.ok) {
    const t = await res.text().catch(() => "");
    throw new Error(`proxy_http_${res.status}: ${t.slice(0, 600)}`);
  }

  let json;
  try {
    json = await res.json();
  } catch {
    throw new Error("proxy_bad_json");
  }

  const text = json?.explanation?.trim();

  if (!text || looksLikeHtml(text)) {
    throw new Error("proxy_empty_or_unsafe_response");
  }

  return text.slice(0, 600);
}
