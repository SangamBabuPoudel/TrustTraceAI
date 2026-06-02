const WARNING_PAYLOAD_PREFIX = "trusttraceWarning:";

const params = new URLSearchParams(window.location.search);
const warningId = params.get("warning_id");

initWarningPage();

async function initWarningPage() {
  const payload = await loadWarningPayload();

  if (!payload) {
    document.getElementById("original-url").textContent = "Warning details unavailable.";
    return;
  }

  document.getElementById("original-url").textContent = payload.original_url;
  document.getElementById("risk-level").textContent = capitalize(payload.risk_level || "high");
  document.getElementById("trust-score").textContent = payload.trust_score ?? "N/A";
  document.getElementById("phishing-probability").textContent = `${Math.round((Number(payload.phishing_probability) || 0) * 100)}%`;
  document.getElementById("confidence").textContent = capitalize(payload.confidence || "medium");

  const reasonsElement = document.getElementById("reasons");
  reasonsElement.innerHTML = "";
  (payload.reasons || ["TrustTrace AI found high-risk URL signals."]).forEach((reason) => {
    const item = document.createElement("li");
    item.textContent = reason;
    reasonsElement.appendChild(item);
  });
  if (payload.threat_intel?.is_known_bad) {
    const item = document.createElement("li");
    item.textContent = payload.threat_intel.reason || "URL matched local threat intelligence.";
    reasonsElement.appendChild(item);
  }
  (payload.deep_analysis?.signals || []).forEach((signal) => {
    const item = document.createElement("li");
    item.textContent = signal.message || "Deep URL heuristic signal detected.";
    reasonsElement.appendChild(item);
  });
  renderAttackExplanation(payload.attack_explanation);

  document.getElementById("go-back").addEventListener("click", () => goBackToSafety());
  document.getElementById("proceed").addEventListener("click", () => proceedAnyway(payload.original_url));
}

function renderAttackExplanation(explanation) {
  const section = document.getElementById("attack-section");
  if (!explanation) {
    section.hidden = true;
    return;
  }

  section.hidden = false;
  document.getElementById("attack-type").textContent = explanation.attack_type || "Unknown";
  document.getElementById("attack-summary").textContent = explanation.summary || "TrustTrace AI found a risky attack pattern.";
  document.getElementById("safer-action").textContent = explanation.safer_action || "Go directly to the official website using a trusted bookmark.";

  const avoidList = document.getElementById("attack-avoid");
  avoidList.innerHTML = "";
  (explanation.what_to_avoid || []).slice(0, 3).forEach((itemText) => {
    const item = document.createElement("li");
    item.textContent = itemText;
    avoidList.appendChild(item);
  });
}

async function loadWarningPayload() {
  if (!warningId) {
    return null;
  }

  const key = `${WARNING_PAYLOAD_PREFIX}${warningId}`;
  const stored = await chrome.storage.session.get(key);
  return stored[key] || null;
}

async function proceedAnyway(originalUrl) {
  if (!originalUrl) {
    return;
  }

  await chrome.runtime.sendMessage({
    type: "TRUSTTRACE_PROCEED_ANYWAY",
    original_url: originalUrl
  });
  window.location.href = originalUrl;
}

function goBackToSafety() {
  if (history.length > 1) {
    history.back();
    return;
  }

  window.location.href = "about:blank";
}

function capitalize(value) {
  return String(value).charAt(0).toUpperCase() + String(value).slice(1);
}
