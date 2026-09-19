// rules/phishingRules.js

export function assessPhishingRisk(signals = {}) {
  let score = 0;
  const reasons = [];

  // ===== Page-level checks =====
  if (signals.page?.protocol === "http:") {
    score += 2;
    reasons.push("Page is not using HTTPS");
  }

  // ===== Form / input checks =====
  const fields = signals.fields || {};

  if (fields.hasPasswordField) {
    score += 2;
    reasons.push("Password input field detected");
  }

  if (fields.hasSensitiveInputs) {
    score += 2;
    reasons.push("Sensitive input fields detected (email, credit card, etc.)");
  }

  if (fields.formActionExternal) {
    score += 3;
    reasons.push("Login form submits to external domain");
  }

  // ===== Keyword / content checks =====
  const keywords = signals.keywords || {};

  if (keywords.urgentLanguage) {
    score += 1;
    reasons.push("Urgent or fear-based language detected");
  }

  if (keywords.accountThreats) {
    score += 2;
    reasons.push("Threats about account suspension or compromise");
  }

  if (keywords.downloadExecutable) {
    score += 3;
    reasons.push("Executable download language detected (possible malware)");
  }

  // ===== Final risk level =====
  let level = "low";
  if (score >= 6) level = "high";
  else if (score >= 3) level = "medium";

  return {
    level,
    score,
    reasons
  };
}
