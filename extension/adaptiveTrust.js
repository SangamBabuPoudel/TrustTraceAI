const TRUSTTRACE_ADAPTIVE_KEY = "trusttraceAdaptiveTrustProfiles";
const TRUSTTRACE_ADAPTIVE_ENABLED_KEY = "trusttraceAdaptiveTrustEnabled";
const MAX_POSITIVE_ADJUSTMENT = 10;
const MAX_NEGATIVE_ADJUSTMENT = -15;

// Personal Adaptive Trust is intentionally local-only. It stores sanitized
// domain-level metadata in chrome.storage.local and never writes community or
// global reputation. A single user report must not change TrustTrace scoring
// for anyone else.

function getDomainFromUrl(url) {
  try {
    const parsedUrl = new URL(url);
    return parsedUrl.hostname.toLowerCase().replace(/^www\./, "");
  } catch (error) {
    return "";
  }
}

async function isAdaptiveLearningEnabled() {
  const stored = await chrome.storage.local.get(TRUSTTRACE_ADAPTIVE_ENABLED_KEY);
  return Boolean(stored[TRUSTTRACE_ADAPTIVE_ENABLED_KEY]);
}

async function setAdaptiveLearningEnabled(enabled) {
  await chrome.storage.local.set({ [TRUSTTRACE_ADAPTIVE_ENABLED_KEY]: Boolean(enabled) });
}

async function getAllLearningProfiles() {
  const stored = await chrome.storage.local.get(TRUSTTRACE_ADAPTIVE_KEY);
  return stored[TRUSTTRACE_ADAPTIVE_KEY] || {};
}

async function saveAllLearningProfiles(profiles) {
  await chrome.storage.local.set({ [TRUSTTRACE_ADAPTIVE_KEY]: profiles });
}

async function getLearningProfile(domain) {
  if (!domain) {
    return createDefaultProfile("");
  }

  const profiles = await getAllLearningProfiles();
  return normalizeProfile(profiles[domain], domain);
}

async function updateLearningProfile(scanResult, url) {
  if (!(await isAdaptiveLearningEnabled())) {
    return null;
  }

  const domain = getDomainFromUrl(url);
  if (!domain || !scanResult) {
    return null;
  }

  const profiles = await getAllLearningProfiles();
  const profile = normalizeProfile(profiles[domain], domain);
  const riskLevel = scanResult.risk_level || "low";

  profile.total_scans += 1;
  if (riskLevel === "high") {
    profile.high_risk_scan_count += 1;
  } else if (riskLevel === "medium") {
    profile.caution_scan_count += 1;
  } else {
    profile.safe_scan_count += 1;
  }
  profile.last_risk_level = riskLevel;
  profile.last_trust_score = Number(scanResult.trust_score || 0);
  profile.last_seen = new Date().toISOString();
  profile.learned_trust_adjustment = calculateAdjustment(profile);

  profiles[domain] = profile;
  await saveAllLearningProfiles(profiles);
  return profile;
}

async function markDomainTrusted(url) {
  return updateFeedbackProfile(url, (profile) => {
    profile.user_marked_trusted_count += 1;
  });
}

async function markDomainSuspicious(url) {
  return updateFeedbackProfile(url, (profile) => {
    profile.user_marked_suspicious_count += 1;
  });
}

async function markFalsePositive(url) {
  return updateFeedbackProfile(url, (profile) => {
    profile.false_positive_count += 1;
  });
}

async function updateFeedbackProfile(url, updater) {
  await setAdaptiveLearningEnabled(true);
  const domain = getDomainFromUrl(url);
  if (!domain) {
    return createDefaultProfile("");
  }

  const profiles = await getAllLearningProfiles();
  const profile = normalizeProfile(profiles[domain], domain);
  updater(profile);
  profile.last_seen = new Date().toISOString();
  profile.learned_trust_adjustment = calculateAdjustment(profile);
  profiles[domain] = profile;
  await saveAllLearningProfiles(profiles);
  return profile;
}

async function getAdaptiveAdjustment(domain) {
  const profile = await getLearningProfile(domain);
  return calculateAdjustment(profile);
}

async function resetAdaptiveLearning() {
  await chrome.storage.local.remove(TRUSTTRACE_ADAPTIVE_KEY);
}

async function getAdaptiveLearningSummary() {
  const profiles = await getAllLearningProfiles();
  const values = Object.values(profiles).map((profile) => normalizeProfile(profile, profile.domain));

  return {
    domain_count: values.length,
    false_positive_count: values.reduce((sum, profile) => sum + profile.false_positive_count, 0),
    user_trusted_marks: values.reduce((sum, profile) => sum + profile.user_marked_trusted_count, 0),
    user_suspicious_marks: values.reduce((sum, profile) => sum + profile.user_marked_suspicious_count, 0)
  };
}

async function applyAdaptiveTrustToResult(scanResult, url) {
  if (!(await isAdaptiveLearningEnabled())) {
    return scanResult;
  }

  const domain = getDomainFromUrl(url);
  if (!domain || !scanResult) {
    return scanResult;
  }

  const profile = await getLearningProfile(domain);
  const rawAdjustment = calculateAdjustment(profile);
  const strongEvidence = hasStrongPhishingEvidence(scanResult);
  const adjustment = rawAdjustment > 0 && strongEvidence ? 0 : rawAdjustment;

  if (adjustment === 0) {
    await updateLearningProfile(scanResult, url);
    return scanResult;
  }

  const adjustedResult = cloneScanResult(scanResult);
  const originalTrustScore = Number(scanResult.trust_score || 0);
  const nextTrustScore = clamp(originalTrustScore + adjustment, 0, 100);
  adjustedResult.trust_score = nextTrustScore;
  adjustedResult.phishing_probability = Number((1 - nextTrustScore / 100).toFixed(2));

  if (scanResult.risk_level !== "high" || adjustment < 0) {
    adjustedResult.risk_level = riskLevelFromTrustScore(nextTrustScore);
  }
  if (scanResult.risk_level === "high" && strongEvidence) {
    adjustedResult.risk_level = "high";
  }

  adjustedResult.trust_signals = [
    ...(adjustedResult.trust_signals || []),
    ...buildAdaptiveTrustSignals(profile, adjustment, strongEvidence)
  ];
  adjustedResult.adaptive_trust = {
    domain,
    enabled: true,
    adjustment,
    strong_evidence_protected: strongEvidence && rawAdjustment > 0,
    profile: sanitizeProfileForUi(profile)
  };

  await updateLearningProfile(adjustedResult, url);
  return adjustedResult;
}

function buildAdaptiveTrustSignals(profile, adjustment, strongEvidence) {
  const signals = [];
  if (profile.safe_scan_count >= 2 && adjustment > 0) {
    signals.push("You have safely visited this domain before.");
  }
  if (profile.user_marked_trusted_count > 0 && adjustment > 0) {
    signals.push("User marked this domain as trusted.");
  }
  if (profile.false_positive_count > 0 && adjustment > 0) {
    signals.push("Previous false-positive feedback exists for this domain.");
  }
  if (profile.user_marked_suspicious_count > 0 && adjustment < 0) {
    signals.push("User marked this domain as suspicious.");
  }
  if (adjustment !== 0) {
    signals.push("Adaptive trust learning applied a small local adjustment.");
  }
  if (strongEvidence) {
    signals.push("Adaptive learning did not override strong phishing indicators.");
  }
  return signals;
}

function calculateAdjustment(profile) {
  let adjustment = 0;
  adjustment += Math.min(Math.floor(profile.safe_scan_count / 2), 5);
  adjustment += Math.min(profile.user_marked_trusted_count * 4, 8);
  adjustment += Math.min(profile.false_positive_count * 3, 6);
  adjustment -= Math.min(profile.user_marked_suspicious_count * 5, 15);
  adjustment -= Math.min(profile.high_risk_scan_count * 2, 8);
  return clamp(adjustment, MAX_NEGATIVE_ADJUSTMENT, MAX_POSITIVE_ADJUSTMENT);
}

function hasStrongPhishingEvidence(result) {
  const evidence = [
    ...(result.reasons || []),
    ...(result.signals?.url_signals || []),
    ...(result.signals?.form_signals || []),
    ...(result.signals?.visual_clone_signals || []),
    ...(result.signals?.content_signals || []),
    ...(result.signals?.clipboard_signals || []),
    ...(result.signals?.sender_signals || []),
    ...(result.signals?.message_signals || []),
    ...(result.signals?.link_signals || []),
    result.attack_explanation?.attack_type || "",
    result.attack_explanation?.summary || "",
    result.threat_intel?.reason || ""
  ].join(" ").toLowerCase();

  return Boolean(
    result.threat_intel?.is_known_bad ||
    result.visual_clone?.visual_clone_confidence === "high" ||
    result.visual_clone?.is_visual_clone_suspected ||
    result.risk_level === "high" ||
    /known-bad|blocklist|password field|credential phishing|visual brand cloning|fake login|brand impersonation|typosquat|lookalike|homoglyph|sender uses a personal\/free email|suspicious sender|recovery phrase|seed phrase|private key|clipboard manipulation|security code|otp/.test(evidence)
  );
}

function normalizeProfile(profile, domain) {
  return {
    ...createDefaultProfile(domain),
    ...(profile || {}),
    domain: domain || profile?.domain || ""
  };
}

function createDefaultProfile(domain) {
  return {
    domain,
    total_scans: 0,
    safe_scan_count: 0,
    caution_scan_count: 0,
    high_risk_scan_count: 0,
    last_risk_level: "",
    last_trust_score: 0,
    user_marked_trusted_count: 0,
    user_marked_suspicious_count: 0,
    false_positive_count: 0,
    last_seen: "",
    learned_trust_adjustment: 0
  };
}

function sanitizeProfileForUi(profile) {
  return { ...profile };
}

function cloneScanResult(result) {
  return JSON.parse(JSON.stringify(result));
}

function riskLevelFromTrustScore(trustScore) {
  if (trustScore <= 40) return "high";
  if (trustScore <= 70) return "medium";
  return "low";
}

function clamp(value, min, max) {
  return Math.max(min, Math.min(max, value));
}

globalThis.TrustTraceAdaptiveTrust = {
  getDomainFromUrl,
  isAdaptiveLearningEnabled,
  setAdaptiveLearningEnabled,
  getLearningProfile,
  updateLearningProfile,
  markDomainTrusted,
  markDomainSuspicious,
  markFalsePositive,
  getAdaptiveAdjustment,
  resetAdaptiveLearning,
  getAdaptiveLearningSummary,
  applyAdaptiveTrustToResult
};
