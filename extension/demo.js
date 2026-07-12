const DEMO_PAGES = [
  "test-phishing.html",
  "test-scam-message.html",
  "test-previsit-links.html",
  "test-universal-links.html",
  "test-clipboard-guardian.html",
  "test-visual-clone.html",
  "test-adaptive-trust.html",
  "test-attack-explanations.html"
];

renderScenarioCards();
renderDemoPageLinks();

function renderScenarioCards() {
  const grid = document.getElementById("scenario-grid");
  const scenarios = globalThis.TRUSTTRACE_DEMO_SCENARIOS || [];

  grid.innerHTML = scenarios.map((scenario) => {
    const probability = Math.round(Number(scenario.phishing_probability || 0) * 100);
    return `
      <article class="scenario-card ${escapeHtml(scenario.risk_level)}">
        <div class="scenario-top">
          <div>
            <p class="eyebrow">${escapeHtml(scenario.scenario_label)}</p>
            <h2>${escapeHtml(scenario.title)}</h2>
          </div>
          <span class="risk-badge ${escapeHtml(scenario.risk_level)}">${escapeHtml(getRiskLabel(scenario.risk_level))}</span>
        </div>
        <p class="summary">${escapeHtml(scenario.summary)}</p>
        <div class="metrics">
          <div class="metric"><span>Trust score</span><strong>${escapeHtml(String(scenario.trust_score))}/100</strong></div>
          <div class="metric"><span>Probability</span><strong>${probability}%</strong></div>
          <div class="metric"><span>Attack</span><strong>${escapeHtml(scenario.attack_type)}</strong></div>
        </div>
        <ul class="signals">${(scenario.signals || []).slice(0, 3).map((signal) => `<li>${escapeHtml(signal)}</li>`).join("")}</ul>
      </article>
    `;
  }).join("");
}

function renderDemoPageLinks() {
  const links = document.getElementById("page-links");
  links.innerHTML = DEMO_PAGES.map((page) => {
    const url = `http://127.0.0.1:5500/extension/${page}`;
    return `<a href="${escapeHtml(url)}">${escapeHtml(url)}</a>`;
  }).join("");
}

function getRiskLabel(riskLevel) {
  if (riskLevel === "high") return "High Risk";
  if (riskLevel === "medium") return "Medium Risk";
  return "Low Risk";
}

function escapeHtml(value) {
  return String(value || "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll("\"", "&quot;")
    .replaceAll("'", "&#039;");
}
