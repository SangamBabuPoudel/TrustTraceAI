const TRUSTTRACE_STATS_KEY = "trusttraceSecurityStats";

const TRUSTTRACE_DEFAULT_ATTACK_TYPES = {
  "Credential phishing": 0,
  "Brand impersonation phishing": 0,
  "Typosquatting / lookalike domain": 0,
  "Suspicious link redirection": 0,
  "Urgency / social engineering pressure": 0
};

const TRUSTTRACE_DEFAULT_STATS = {
  total_url_scans: 0,
  total_page_scans: 0,
  total_message_scans: 0,
  total_link_scans: 0,
  high_risk_blocks: 0,
  medium_cautions: 0,
  trusted_results: 0,
  high_risk_links_detected: 0,
  suspicious_messages_detected: 0,
  fake_login_forms_detected: 0,
  repeated_message_warnings: 0,
  attack_type_counts: TRUSTTRACE_DEFAULT_ATTACK_TYPES,
  last_updated: ""
};

function cloneTrustTraceStats(stats = {}) {
  return {
    ...TRUSTTRACE_DEFAULT_STATS,
    ...stats,
    attack_type_counts: {
      ...TRUSTTRACE_DEFAULT_ATTACK_TYPES,
      ...(stats.attack_type_counts || {})
    }
  };
}

async function getSecurityStats() {
  const stored = await chrome.storage.local.get(TRUSTTRACE_STATS_KEY);
  return cloneTrustTraceStats(stored[TRUSTTRACE_STATS_KEY]);
}

async function saveSecurityStats(stats) {
  const nextStats = cloneTrustTraceStats(stats);
  nextStats.last_updated = new Date().toISOString();
  await chrome.storage.local.set({ [TRUSTTRACE_STATS_KEY]: nextStats });
  return nextStats;
}

async function updateSecurityStats(updater) {
  const stats = await getSecurityStats();
  updater(stats);
  return saveSecurityStats(stats);
}

async function resetSecurityStats() {
  return saveSecurityStats(TRUSTTRACE_DEFAULT_STATS);
}

async function recordScanResult(result, scanType) {
  return updateSecurityStats((stats) => {
    if (scanType === "website" || scanType === "page") {
      stats.total_url_scans += 1;
      stats.total_page_scans += 1;
    } else if (scanType === "url") {
      stats.total_url_scans += 1;
    }

    incrementRiskCounters(stats, result);
    incrementAttackType(stats, result);

    if (hasFakeLoginSignal(result)) {
      stats.fake_login_forms_detected += 1;
    }
  });
}

async function recordWarningBlock(result) {
  return updateSecurityStats((stats) => {
    stats.high_risk_blocks += 1;
    incrementAttackType(stats, result);
  });
}

async function recordCautionBanner(result) {
  return updateSecurityStats((stats) => {
    stats.medium_cautions += 1;
    incrementAttackType(stats, result);
  });
}

async function recordLinkScanSummary(summary) {
  return updateSecurityStats((stats) => {
    stats.total_link_scans += Number(summary.total || 0);
    stats.high_risk_links_detected += Number(summary.high || 0);
  });
}

async function recordMessageScanResult(result) {
  return updateSecurityStats((stats) => {
    stats.total_message_scans += 1;
    if (result?.risk_level === "medium" || result?.risk_level === "high") {
      stats.suspicious_messages_detected += 1;
    }
    if (Number(result?.repeat_count || 0) > 1 || result?.repeat_warning) {
      stats.repeated_message_warnings += 1;
    }
    incrementRiskCounters(stats, result);
    incrementAttackType(stats, result);
  });
}

function incrementRiskCounters(stats, result) {
  if (!result) {
    return;
  }
  if (result.risk_level === "low" && Number(result.trust_score || 0) >= 80) {
    stats.trusted_results += 1;
  }
  if (result.risk_level === "medium") {
    stats.medium_cautions += 1;
  }
}

function incrementAttackType(stats, result) {
  const attackType = result?.attack_explanation?.attack_type;
  if (!attackType || attackType === "Unknown / low-risk") {
    return;
  }
  stats.attack_type_counts[attackType] = (stats.attack_type_counts[attackType] || 0) + 1;
}

function hasFakeLoginSignal(result) {
  const formSignals = result?.signals?.form_signals || [];
  return formSignals.some((signal) => (
    /password|credential|login form|account-verification|unencrypted http/i.test(signal)
  ));
}

globalThis.TrustTraceSecurityStats = {
  getSecurityStats,
  resetSecurityStats,
  recordScanResult,
  recordWarningBlock,
  recordCautionBanner,
  recordLinkScanSummary,
  recordMessageScanResult
};
