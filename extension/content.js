const MAX_VISIBLE_TEXT_LENGTH = 5000;
const SEARCH_BADGE_ATTRIBUTE = "data-trusttrace-search-badge";
const SEARCH_RESULT_ATTRIBUTE = "data-trusttrace-search-scanned";
const MAX_SEARCH_RESULTS_TO_SCAN = 12;
const searchResultCache = new Map();
let searchScanTimer = null;

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message?.type === "SHOW_CAUTION_BANNER") {
    showCautionBanner(message.result);
    sendResponse({ ok: true });
    return false;
  }

  if (message?.type !== "TRUSTTRACE_COLLECT_PAGE") {
    return false;
  }

  sendResponse({
    pageTitle: document.title || "",
    selectedText: getSelectedText().slice(0, MAX_VISIBLE_TEXT_LENGTH),
    visibleText: getVisibleBodyText().slice(0, MAX_VISIBLE_TEXT_LENGTH),
    forms: collectFormMetadata(),
    links: collectVisibleLinks(),
    messageCandidates: collectMessageCandidates()
  });

  return true;
});

initSearchResultBadges();

function getVisibleBodyText() {
  const bodyText = document.body?.innerText || "";
  return bodyText.replace(/\s+/g, " ").trim();
}

function getSelectedText() {
  return window.getSelection()?.toString().replace(/\s+/g, " ").trim() || "";
}

function collectFormMetadata() {
  return Array.from(document.forms).map((form) => {
    const inputs = Array.from(form.querySelectorAll("input"));
    const submitButton = form.querySelector(
      "button[type='submit'], input[type='submit'], button:not([type])"
    );

    return {
      action: form.getAttribute("action") || "",
      method: (form.getAttribute("method") || "get").toLowerCase(),
      has_password_field: inputs.some((input) => input.type === "password"),
      has_email_or_username_field: inputs.some(isEmailOrUsernameInput),
      input_count: inputs.length,
      hidden_input_count: inputs.filter((input) => input.type === "hidden").length,
      submit_text: getSubmitText(submitButton)
    };
  });
}

function isEmailOrUsernameInput(input) {
  const inputType = input.type.toLowerCase();
  const inputName = `${input.name || ""} ${input.id || ""} ${input.placeholder || ""}`.toLowerCase();

  return (
    inputType === "email" ||
    inputName.includes("email") ||
    inputName.includes("user") ||
    inputName.includes("login")
  );
}

function getSubmitText(submitButton) {
  if (!submitButton) {
    return "";
  }

  if (submitButton.tagName.toLowerCase() === "input") {
    return submitButton.value || "";
  }

  return submitButton.innerText || submitButton.textContent || "";
}

function collectVisibleLinks() {
  return Array.from(document.querySelectorAll("a[href]"))
    .filter((link) => link.innerText.trim() || link.href)
    .slice(0, 30)
    .map((link) => ({
      text: link.innerText.replace(/\s+/g, " ").trim(),
      href: link.href
    }));
}

function collectMessageCandidates() {
  const selectedText = getSelectedText();
  const elements = getCandidateElements();

  return elements
    .map((element, index) => buildMessageCandidate(element, index, selectedText))
    .filter((candidate) => candidate.message_text.length >= 20)
    .sort((a, b) => b.confidence_score - a.confidence_score || a.position.top - b.position.top)
    .slice(0, 12);
}

function getCandidateElements() {
  const selectors = [
    ".trusttrace-message-card",
    "[data-trusttrace-message]",
    "[data-sender]",
    "[data-subject]",
    "article",
    "[role='article']",
    ".message",
    ".email",
    ".mail",
    ".conversation",
    ".chat-message"
  ];
  const elements = Array.from(document.querySelectorAll(selectors.join(",")));
  const uniqueElements = [];

  elements.forEach((element) => {
    if (!isVisible(element) || uniqueElements.some((existing) => existing.contains(element))) {
      return;
    }
    uniqueElements.push(element);
  });

  return uniqueElements;
}

function buildMessageCandidate(element, index, selectedText) {
  const rect = element.getBoundingClientRect();
  const messageText = (element.innerText || "").replace(/\s+/g, " ").trim();
  const links = Array.from(element.querySelectorAll("a[href]")).map((link) => ({
    text: link.innerText.replace(/\s+/g, " ").trim(),
    href: link.href
  }));
  const sender = extractSender(element, messageText);
  const subject = extractSubject(element, messageText);
  const confidenceScore = scoreCandidate(element, messageText, links, sender, subject);

  return {
    candidate_id: `message-${index + 1}`,
    sender,
    subject,
    preview: messageText.slice(0, 300),
    message_text: messageText.slice(0, MAX_VISIBLE_TEXT_LENGTH),
    links,
    source_url: window.location.href,
    confidence_score: selectedText && messageText.includes(selectedText) ? confidenceScore + 50 : confidenceScore,
    contains_selection: Boolean(selectedText && messageText.includes(selectedText)),
    position: {
      top: Math.max(0, Math.round(rect.top + window.scrollY)),
      left: Math.max(0, Math.round(rect.left + window.scrollX)),
      width: Math.round(rect.width),
      height: Math.round(rect.height)
    }
  };
}

function extractSender(element, text) {
  const explicitSender = element.getAttribute("data-sender");
  if (explicitSender) {
    return explicitSender.trim();
  }

  const senderMatch = text.match(/\b(?:sender|from):\s*([^\n]+?)(?:\s{2,}| subject:| message:|$)/i);
  return senderMatch ? senderMatch[1].trim() : "";
}

function extractSubject(element, text) {
  const explicitSubject = element.getAttribute("data-subject");
  if (explicitSubject) {
    return explicitSubject.trim();
  }

  const heading = element.querySelector("h1, h2, h3, [data-subject]");
  if (heading?.innerText) {
    return heading.innerText.trim();
  }

  const subjectMatch = text.match(/\bsubject:\s*([^\n]+?)(?:\s{2,}| sender:| from:| message:|$)/i);
  return subjectMatch ? subjectMatch[1].trim() : document.title || "";
}

function scoreCandidate(element, text, links, sender, subject) {
  let score = 0;
  const lowerText = text.toLowerCase();

  if (element.matches(".trusttrace-message-card, [data-trusttrace-message]")) score += 50;
  if (element.matches("[data-sender], [data-subject], article, [role='article']")) score += 25;
  if (sender) score += 15;
  if (subject) score += 10;
  if (links.length > 0) score += 10;
  if (/(urgent|suspended|locked|verify|password|security code|payment failed)/.test(lowerText)) score += 20;

  return score;
}

function isVisible(element) {
  const rect = element.getBoundingClientRect();
  const style = window.getComputedStyle(element);
  return rect.width > 0 && rect.height > 0 && style.visibility !== "hidden" && style.display !== "none";
}

function showCautionBanner(result) {
  const existingBanner = document.getElementById("trusttrace-caution-banner");
  if (existingBanner) {
    existingBanner.remove();
  }

  const banner = document.createElement("div");
  banner.id = "trusttrace-caution-banner";
  banner.style.cssText = [
    "position: fixed",
    "top: 0",
    "left: 0",
    "right: 0",
    "z-index: 2147483647",
    "padding: 12px 16px",
    "background: #fef3c7",
    "color: #422006",
    "border-bottom: 2px solid #f59e0b",
    "box-shadow: 0 8px 24px rgba(0,0,0,0.18)",
    "font-family: Arial, sans-serif",
    "font-size: 14px",
    "line-height: 1.4"
  ].join(";");

  const reasons = (result?.reasons || []).slice(0, 2);
  const probability = Math.round((Number(result?.phishing_probability) || 0) * 100);

  banner.innerHTML = `
    <div style="display:flex; gap:12px; align-items:flex-start; justify-content:space-between;">
      <div>
        <strong>TrustTrace AI caution: this page has some suspicious signals.</strong>
        <div>Trust score: ${result?.trust_score ?? "N/A"} · Phishing probability: ${probability}%</div>
        ${reasons.length ? `<ul style="margin:6px 0 0; padding-left:18px;">${reasons.map((reason) => `<li>${escapeHtml(reason)}</li>`).join("")}</ul>` : ""}
      </div>
      <div style="display:flex; gap:8px; flex:0 0 auto;">
        <button id="trusttrace-open-popup" style="padding:7px 10px; border:1px solid #92400e; border-radius:8px; background:#fffbeb; color:#422006; cursor:pointer;">Open TrustTrace AI</button>
        <button id="trusttrace-dismiss-caution" style="padding:7px 10px; border:1px solid #92400e; border-radius:8px; background:#92400e; color:#fff; cursor:pointer;">Dismiss</button>
      </div>
    </div>
  `;

  document.documentElement.appendChild(banner);
  document.getElementById("trusttrace-dismiss-caution")?.addEventListener("click", () => {
    banner.remove();
  });
  document.getElementById("trusttrace-open-popup")?.addEventListener("click", () => {
    chrome.runtime.sendMessage({ type: "TRUSTTRACE_OPEN_POPUP" });
  });
}

function initSearchResultBadges() {
  if (!isGoogleSearchResultsPage()) {
    return;
  }

  if (!document.body) {
    window.addEventListener("DOMContentLoaded", initSearchResultBadges, { once: true });
    return;
  }

  scanVisibleSearchResults();

  const observer = new MutationObserver(() => {
    window.clearTimeout(searchScanTimer);
    searchScanTimer = window.setTimeout(scanVisibleSearchResults, 500);
  });

  observer.observe(document.body, {
    childList: true,
    subtree: true
  });
}

function isGoogleSearchResultsPage() {
  return (
    location.hostname === "www.google.com" ||
    location.hostname === "google.com" ||
    location.hostname.endsWith(".google.com")
  ) && location.pathname === "/search";
}

function scanVisibleSearchResults() {
  const results = collectGoogleSearchResultLinks();

  results.forEach(({ link, targetUrl }) => {
    if (link.getAttribute(SEARCH_RESULT_ATTRIBUTE) === targetUrl) {
      return;
    }

    link.setAttribute(SEARCH_RESULT_ATTRIBUTE, targetUrl);
    const badge = attachSearchResultBadge(link, targetUrl);
    updateSearchBadge(badge, {
      label: "Scanning",
      level: "pending",
      title: "TrustTrace AI is checking this result URL."
    });

    analyzeSearchResult(targetUrl)
      .then((result) => {
        updateSearchBadgeFromResult(badge, targetUrl, result);
      })
      .catch(() => {
        updateSearchBadge(badge, {
          label: "Offline",
          level: "offline",
          title: "TrustTrace AI backend is unavailable."
        });
      });
  });
}

function collectGoogleSearchResultLinks() {
  const seenUrls = new Set();
  return Array.from(document.querySelectorAll("#search a[href]"))
    .map((link) => ({ link, targetUrl: extractSearchResultUrl(link) }))
    .filter(({ link, targetUrl }) => {
      if (!targetUrl || seenUrls.has(targetUrl) || !isSearchResultLink(link, targetUrl)) {
        return false;
      }
      seenUrls.add(targetUrl);
      return true;
    })
    .slice(0, MAX_SEARCH_RESULTS_TO_SCAN);
}

function extractSearchResultUrl(link) {
  try {
    const hrefUrl = new URL(link.href);
    if (hrefUrl.hostname.endsWith("google.com") && hrefUrl.pathname === "/url") {
      const redirectedUrl = hrefUrl.searchParams.get("q") || hrefUrl.searchParams.get("url");
      return redirectedUrl ? new URL(redirectedUrl).href : "";
    }
    return hrefUrl.href;
  } catch (error) {
    return "";
  }
}

function isSearchResultLink(link, targetUrl) {
  try {
    const target = new URL(targetUrl);
    const hasResultTitle = Boolean(link.querySelector("h3") || link.closest("[data-sokoban-container]")?.querySelector("h3"));
    const isWebUrl = ["http:", "https:"].includes(target.protocol);

    return hasResultTitle && isWebUrl && isVisible(link);
  } catch (error) {
    return false;
  }
}

function attachSearchResultBadge(link, targetUrl) {
  const existingBadge = link.parentElement?.querySelector(
    `[${SEARCH_BADGE_ATTRIBUTE}="${cssEscape(targetUrl)}"]`
  );
  if (existingBadge) {
    return existingBadge;
  }

  const badge = document.createElement("button");
  badge.type = "button";
  badge.setAttribute(SEARCH_BADGE_ATTRIBUTE, targetUrl);
  badge.style.cssText = [
    "display:inline-flex",
    "align-items:center",
    "gap:5px",
    "margin-left:8px",
    "padding:3px 8px",
    "border-radius:999px",
    "border:1px solid rgba(148,163,184,0.55)",
    "font:600 11px/1.2 Arial,sans-serif",
    "vertical-align:middle",
    "cursor:default",
    "transition:background 160ms ease,border-color 160ms ease,color 160ms ease,transform 160ms ease",
    "box-shadow:0 2px 8px rgba(15,23,42,0.12)"
  ].join(";");

  const title = link.querySelector("h3") || link;
  title.insertAdjacentElement("afterend", badge);
  return badge;
}

async function analyzeSearchResult(targetUrl) {
  if (searchResultCache.has(targetUrl)) {
    return searchResultCache.get(targetUrl);
  }

  const response = await chrome.runtime.sendMessage({
    type: "TRUSTTRACE_ANALYZE_SEARCH_RESULT",
    url: targetUrl
  });

  if (!response?.ok) {
    throw new Error(response?.error || "Search result analysis failed.");
  }

  searchResultCache.set(targetUrl, response.result);
  return response.result;
}

function updateSearchBadgeFromResult(badge, targetUrl, result) {
  const level = getSearchBadgeLevel(result);
  const labels = {
    trusted: "Trusted",
    caution: "Caution",
    high: "High Risk"
  };

  updateSearchBadge(badge, {
    label: labels[level],
    level,
    title: buildSearchBadgeTitle(result)
  });

  if (level === "high") {
    badge.style.cursor = "pointer";
    badge.addEventListener("click", (event) => {
      event.preventDefault();
      event.stopPropagation();
      chrome.runtime.sendMessage({
        type: "TRUSTTRACE_OPEN_WARNING_FOR_URL",
        url: targetUrl,
        result
      });
    });
  }
}

function getSearchBadgeLevel(result) {
  const trustScore = Number(result?.trust_score);
  const probability = Number(result?.phishing_probability);

  if (
    trustScore <= 30 ||
    probability >= 0.75 ||
    (result?.risk_level === "high" && result?.confidence === "high")
  ) {
    return "high";
  }

  if ((trustScore > 30 && trustScore <= 60) || result?.risk_level === "medium") {
    return "caution";
  }

  return "trusted";
}

function updateSearchBadge(badge, state) {
  const styles = {
    pending: {
      text: "#334155",
      background: "#f8fafc",
      border: "rgba(148,163,184,0.65)"
    },
    trusted: {
      text: "#065f46",
      background: "#d1fae5",
      border: "#34d399"
    },
    caution: {
      text: "#78350f",
      background: "#fef3c7",
      border: "#f59e0b"
    },
    high: {
      text: "#7f1d1d",
      background: "#fee2e2",
      border: "#ef4444"
    },
    offline: {
      text: "#475569",
      background: "#e2e8f0",
      border: "#94a3b8"
    }
  };
  const style = styles[state.level] || styles.pending;

  badge.textContent = state.label;
  badge.title = state.title;
  badge.style.color = style.text;
  badge.style.background = style.background;
  badge.style.borderColor = style.border;
}

function buildSearchBadgeTitle(result) {
  const probability = Math.round((Number(result?.phishing_probability) || 0) * 100);
  const topReason = result?.reasons?.[0] ? ` Reason: ${result.reasons[0]}` : "";
  return `TrustTrace AI: ${result?.risk_level || "low"} risk, trust score ${result?.trust_score ?? "N/A"}, phishing probability ${probability}%.${topReason}`;
}

function cssEscape(value) {
  if (window.CSS?.escape) {
    return window.CSS.escape(value);
  }
  return String(value).replaceAll("\"", "\\\"");
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll("\"", "&quot;")
    .replaceAll("'", "&#039;");
}
