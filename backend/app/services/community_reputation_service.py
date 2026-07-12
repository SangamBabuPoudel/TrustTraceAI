"""
Future community reputation design for TrustTrace AI.

This module is intentionally a placeholder. It does not submit reports, fetch
cloud reputation, or change scoring today. The goal is to document a safe
boundary between local Personal Adaptive Trust and any future global/community
signal.

Important rule:
A single complaint should never change global detection for all users.
"""

from datetime import datetime
from typing import Dict, Optional
from urllib.parse import urlparse


WEAK_COMMUNITY_THRESHOLD = 3
MEDIUM_COMMUNITY_THRESHOLD = 10
STRONG_COMMUNITY_THRESHOLD = 25


def sanitize_domain(value: str) -> str:
    """Return only a normalized hostname; never keep paths or query strings."""
    if not value:
        return ""

    parsed = urlparse(value if "://" in value else "https://" + value)
    hostname = parsed.hostname or ""
    return hostname.lower().removeprefix("www.")


def build_empty_reputation_summary(domain: str) -> Dict[str, object]:
    return {
        "domain": sanitize_domain(domain),
        "safe_report_count": 0,
        "suspicious_report_count": 0,
        "false_positive_report_count": 0,
        "unique_reporter_count": 0,
        "confidence_score": 0,
        "last_reported": None,
        "status": "not_configured",
        "global_signal": "none",
        "abuse_protection_notes": [
            "One report is not enough to affect global reputation.",
            "Future reports should be rate-limited and deduplicated.",
            "Future reports should store only sanitized domain-level data.",
            "Community reputation should be weighted below verified threat intelligence and official-domain reputation.",
            "Community votes should not override known malicious feeds or strong phishing signals."
        ]
    }


def estimate_community_confidence(unique_reporter_count: int) -> Dict[str, object]:
    """
    Future threshold model for community confidence.

    Suggested design:
    - 1-2 reports: local/user-level signal only.
    - 3-9 independent reports: weak community signal.
    - 10-24 independent reports: medium community confidence.
    - 25+ independent reports: stronger community reputation signal.
    - Verified official or threat-intel sources should outweigh community votes.
    """
    if unique_reporter_count >= STRONG_COMMUNITY_THRESHOLD:
        return {"global_signal": "strong", "confidence_score": 80}
    if unique_reporter_count >= MEDIUM_COMMUNITY_THRESHOLD:
        return {"global_signal": "medium", "confidence_score": 55}
    if unique_reporter_count >= WEAK_COMMUNITY_THRESHOLD:
        return {"global_signal": "weak", "confidence_score": 25}
    return {"global_signal": "local_only", "confidence_score": 0}


def evaluate_future_community_reputation(
    domain: str,
    safe_report_count: int = 0,
    suspicious_report_count: int = 0,
    false_positive_report_count: int = 0,
    unique_reporter_count: int = 0,
    last_reported: Optional[datetime] = None
) -> Dict[str, object]:
    """
    Build a design-safe community reputation summary.

    This function is not wired into production scoring. It exists to make the
    future architecture explicit while preventing one user's local feedback from
    becoming a global reputation change.
    """
    clean_domain = sanitize_domain(domain)
    confidence = estimate_community_confidence(unique_reporter_count)

    return {
        "domain": clean_domain,
        "safe_report_count": safe_report_count,
        "suspicious_report_count": suspicious_report_count,
        "false_positive_report_count": false_positive_report_count,
        "unique_reporter_count": unique_reporter_count,
        "confidence_score": confidence["confidence_score"],
        "last_reported": last_reported.isoformat() if last_reported else None,
        "status": "placeholder_only",
        "global_signal": confidence["global_signal"],
        "abuse_protection_notes": [
            "Attackers may try to mass-mark phishing domains as safe.",
            "Competitors may falsely report legitimate domains as suspicious.",
            "Users may accidentally mark a domain incorrectly.",
            "Future community reporting must use thresholds, rate limits, deduplication, and verified-source weighting.",
            "Community reputation must not store private URL paths, query strings, page text, passwords, emails, clipboard text, cookies, or tokens."
        ]
    }
