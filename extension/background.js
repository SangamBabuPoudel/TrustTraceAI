importScripts("securityStats.js", "localAnalyzer.js");

const HIGH_RISK_CACHE_KEY = "trusttraceHighRiskCache";
const SESSION_ALLOWLIST_KEY = "trusttraceSessionAllowlist";
const WARNING_PAYLOAD_PREFIX = "trusttraceWarning:";
const OFFICIAL_GITHUB_DOMAINS = [
  "github.com",
  "githubstatus.com"
];

const pendingCautionsByTab = new Map();
const inFlightByTab = new Map();

chrome.runtime.onInstalled.addListener(() => {
  console.log("TrustTrace AI extension installed.");
});

chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  if (details.frameId !== 0 || !shouldInspectUrl(details.url)) {
    return;
  }

  const tabId = details.tabId;
  const targetUrl = details.url;

  if (await isSessionAllowed(targetUrl)) {
    return;
  }

  const cachedResult = await shouldIgnoreHighRiskCache(targetUrl) ? null : await getCachedHighRiskResult(targetUrl);
  if (cachedResult) {
    await TrustTraceSecurityStats.recordWarningBlock(cachedResult);
    await redirectToWarning(tabId, targetUrl, cachedResult);
    return;
  }

  if (inFlightByTab.get(tabId) === targetUrl) {
    return;
  }

  inFlightByTab.set(tabId, targetUrl);

  try {
    const result = await analyzeUrl(targetUrl);

    if (isHighRisk(result)) {
      await cacheHighRiskResult(targetUrl, result);
      await TrustTraceSecurityStats.recordWarningBlock(result);
      await redirectToWarning(tabId, targetUrl, result);
      return;
    }

    if (isMediumRisk(result)) {
      pendingCautionsByTab.set(tabId, {
        original_url: targetUrl,
        result
      });
      await TrustTraceSecurityStats.recordCautionBanner(result);
      await showCautionBanner(tabId, result);
    }
  } catch (error) {
    console.warn("TrustTrace AI pre-visit analysis unavailable.", error);
  } finally {
    inFlightByTab.delete(tabId);
  }
});

chrome.webNavigation.onCompleted.addListener(async (details) => {
  if (details.frameId !== 0 || !pendingCautionsByTab.has(details.tabId)) {
    return;
  }

  const caution = pendingCautionsByTab.get(details.tabId);
  if (!caution) {
    return;
  }

  pendingCautionsByTab.delete(details.tabId);
  await showCautionBanner(details.tabId, caution.result);
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message?.type === "TRUSTTRACE_PROCEED_ANYWAY") {
    allowForSession(message.original_url).then(() => {
      sendResponse({ ok: true });
    });
    return true;
  }

  if (message?.type === "TRUSTTRACE_OPEN_POPUP") {
    chrome.action.openPopup?.();
    sendResponse({ ok: true });
    return false;
  }

  if (message?.type === "TRUSTTRACE_ANALYZE_SEARCH_RESULT") {
    analyzeSearchResultUrl(message.url)
      .then((result) => {
        sendResponse({ ok: true, result });
      })
      .catch((error) => {
        console.warn("TrustTrace AI search-result analysis unavailable.", error);
        sendResponse({ ok: false, error: "Local analysis unavailable." });
      });
    return true;
  }

  if (message?.type === "TRUSTTRACE_OPEN_WARNING_FOR_URL") {
    const tabId = sender.tab?.id || message.tab_id;
    if (!tabId || !message.url || !message.result) {
      sendResponse({ ok: false });
      return false;
    }

    redirectToWarning(tabId, message.url, message.result).then(() => {
      sendResponse({ ok: true });
    });
    return true;
  }

  if (message?.type === "TRUSTTRACE_RECORD_CLIPBOARD_MISMATCH") {
    TrustTraceSecurityStats.recordClipboardMismatchWarning().then(() => {
      sendResponse({ ok: true });
    });
    return true;
  }

  return false;
});

async function showCautionBanner(tabId, result) {
  try {
    await chrome.tabs.sendMessage(tabId, {
      type: "SHOW_CAUTION_BANNER",
      result
    });
  } catch (error) {
    try {
      await chrome.scripting.executeScript({
        target: { tabId },
        files: ["clipboardGuardian.js", "localAnalyzer.js", "content.js"]
      });
      await chrome.tabs.sendMessage(tabId, {
        type: "SHOW_CAUTION_BANNER",
        result
      });
    } catch (injectionError) {
      console.warn("TrustTrace AI caution banner could not be injected.", injectionError);
    }
  }
}

async function analyzeUrl(url) {
  return TrustTraceLocalAnalyzer.analyzeUrl(url);
}

async function analyzeSearchResultUrl(url) {
  const freshResult = await analyzeUrl(url);

  if (isTrustedOfficialResult(freshResult)) {
    return isOfficialGitHubUrl(url) ? normalizeOfficialGitHubResult(freshResult) : freshResult;
  }

  const cachedResult = await getCachedHighRiskResult(url);
  if (cachedResult) {
    return cachedResult;
  }

  const result = freshResult;
  if (isHighRisk(result)) {
    await cacheHighRiskResult(url, result);
  }
  return result;
}

async function shouldIgnoreHighRiskCache(url) {
  const result = await analyzeUrl(url);
  return isTrustedOfficialResult(result);
}

function isTrustedOfficialResult(result) {
  return Boolean(
    result?.risk_level === "low" &&
    Number(result?.trust_score) >= 85 &&
    (
      result?.reputation?.is_official_auth_provider ||
      result?.reputation?.is_official_brand_domain ||
      result?.reputation?.is_high_reputation_domain
    )
  );
}

function isOfficialGitHubUrl(url) {
  try {
    const hostname = new URL(url).hostname.toLowerCase();
    return OFFICIAL_GITHUB_DOMAINS.some((domain) => hostname === domain || hostname.endsWith(`.${domain}`));
  } catch (error) {
    return false;
  }
}

function normalizeOfficialGitHubResult(result) {
  const trustScore = Math.max(Number(result?.trust_score || 0), 95);
  return {
    ...result,
    risk_level: "low",
    trust_score: trustScore,
    phishing_probability: Math.min(Number(result?.phishing_probability ?? 0.05), 0.05),
    confidence: "high",
    reasons: [],
    trust_signals: [
      "Official GitHub domain detected.",
      ...(result?.trust_signals || [])
    ]
  };
}

function shouldInspectUrl(url) {
  if (!url || !url.startsWith("http")) {
    return false;
  }

  try {
    const parsedUrl = new URL(url);
    const hostname = parsedUrl.hostname.toLowerCase();

    if (!["http:", "https:"].includes(parsedUrl.protocol)) {
      return false;
    }

    return Boolean(hostname);
  } catch (error) {
    return false;
  }
}

function isHighRisk(result) {
  return (
    Number(result.trust_score) <= 30 ||
    Number(result.phishing_probability) >= 0.75 ||
    (result.risk_level === "high" && result.confidence === "high")
  );
}

function isMediumRisk(result) {
  const trustScore = Number(result.trust_score);
  return (trustScore > 30 && trustScore <= 60) || result.risk_level === "medium";
}

async function redirectToWarning(tabId, originalUrl, result) {
  const warningId = crypto.randomUUID();
  const payload = {
    original_url: originalUrl,
    risk_level: result.risk_level,
    trust_score: result.trust_score,
    phishing_probability: result.phishing_probability,
    reasons: result.reasons || [],
    confidence: result.confidence || "medium",
    threat_intel: result.threat_intel || null,
    deep_analysis: result.deep_analysis || null,
    attack_explanation: result.attack_explanation || null,
    visual_clone: result.visual_clone || null
  };

  await chrome.storage.session.set({
    [`${WARNING_PAYLOAD_PREFIX}${warningId}`]: payload
  });

  await chrome.tabs.update(tabId, {
    url: chrome.runtime.getURL(`warning.html?warning_id=${encodeURIComponent(warningId)}`)
  });
}

async function isSessionAllowed(url) {
  const stored = await chrome.storage.session.get(SESSION_ALLOWLIST_KEY);
  const allowlist = stored[SESSION_ALLOWLIST_KEY] || {};
  return Boolean(allowlist[url]);
}

async function allowForSession(url) {
  const stored = await chrome.storage.session.get(SESSION_ALLOWLIST_KEY);
  const allowlist = stored[SESSION_ALLOWLIST_KEY] || {};
  allowlist[url] = Date.now();
  await chrome.storage.session.set({ [SESSION_ALLOWLIST_KEY]: allowlist });
}

async function getCachedHighRiskResult(url) {
  const cache = await getHighRiskCache();
  const hostname = getHostname(url);
  return cache[url] || cache[hostname] || null;
}

async function cacheHighRiskResult(url, result) {
  const cache = await getHighRiskCache();
  const hostname = getHostname(url);
  const cachedResult = {
    url,
    hostname,
    risk_level: result.risk_level,
    trust_score: result.trust_score,
    phishing_probability: result.phishing_probability,
    reasons: result.reasons || [],
    confidence: result.confidence || "medium",
    threat_intel: result.threat_intel || null,
    deep_analysis: result.deep_analysis || null,
    attack_explanation: result.attack_explanation || null,
    visual_clone: result.visual_clone || null,
    detected_at: new Date().toISOString()
  };

  cache[url] = cachedResult;
  cache[hostname] = cachedResult;

  await chrome.storage.local.set({ [HIGH_RISK_CACHE_KEY]: cache });
}

async function getHighRiskCache() {
  const stored = await chrome.storage.local.get(HIGH_RISK_CACHE_KEY);
  return stored[HIGH_RISK_CACHE_KEY] || {};
}

function getHostname(url) {
  try {
    return new URL(url).hostname.toLowerCase();
  } catch (error) {
    return "";
  }
}
