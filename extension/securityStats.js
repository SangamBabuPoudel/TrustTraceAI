const TRUSTTRACE_STATS_KEY = "trusttraceSecurityStats";

const TRUSTTRACE_DEFAULT_ATTACK_TYPES = {
  "Credential phishing": 0,
  "Visual brand cloning / fake login page": 0,
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
  clipboard_scans: 0,
  clipboard_warnings: 0,
  clipboard_high_risk_findings: 0,
  clipboard_url_scans: 0,
  clipboard_mismatch_warnings: 0,
  visual_clone_warnings: 0,
  high_confidence_visual_clones: 0,
  branded_login_clone_detections: 0,
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
    incrementVisualCloneCounters(stats, result);
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

async function recordClipboardScanResult(result, options = {}) {
  return updateSecurityStats((stats) => {
    stats.clipboard_scans += 1;
    if (options.urlScanned) {
      stats.clipboard_url_scans += 1;
    }
    if (result?.risk_level === "medium" || result?.risk_level === "high") {
      stats.clipboard_warnings += 1;
    }
    if (result?.risk_level === "high") {
      stats.clipboard_high_risk_findings += 1;
    }
  });
}

async function recordClipboardMismatchWarning() {
  return updateSecurityStats((stats) => {
    stats.clipboard_mismatch_warnings += 1;
    stats.clipboard_warnings += 1;
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

function incrementVisualCloneCounters(stats, result) {
  const visualClone = result?.visual_clone;
  if (!visualClone || Number(visualClone.visual_clone_score || 0) < 40) {
    return;
  }

  stats.visual_clone_warnings += 1;
  if (visualClone.visual_clone_confidence === "high" || visualClone.is_visual_clone_suspected) {
    stats.high_confidence_visual_clones += 1;
  }

  const visualSignals = result?.signals?.visual_clone_signals || [];
  const hasBrandedLoginClone = visualSignals.some((signal) => (
    /branded login form|password field|login layout/i.test(signal)
  ));
  if (hasBrandedLoginClone) {
    stats.branded_login_clone_detections += 1;
  }
}

globalThis.TrustTraceSecurityStats = {
  getSecurityStats,
  resetSecurityStats,
  recordScanResult,
  recordWarningBlock,
  recordCautionBanner,
  recordLinkScanSummary,
  recordMessageScanResult,
  recordClipboardScanResult,
  recordClipboardMismatchWarning
};
