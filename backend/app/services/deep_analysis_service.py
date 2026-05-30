import re
from dataclasses import dataclass

from app.data.trusted_domains import TRUSTED_BRANDS
from app.services.reputation_service import ReputationResult
from app.services.url_feature_extractor import SUSPICIOUS_TLDS


@dataclass(frozen=True)
class DeepAnalysisResult:
    risk_score: int
    reasons: list[str]
    signals: list[str]
    placeholders: list[dict]


def analyze_url_deep(url: str, reputation: ReputationResult) -> DeepAnalysisResult:
    hostname = reputation.hostname
    reasons: list[str] = []
    signals: list[str] = []
    risk_score = 0

    if reputation.reputation_warnings:
        risk_score += 35
        signals.append("brand_spoofing")
        reasons.extend(reputation.reputation_warnings)

    lookalike_reason = _detect_lookalike(hostname)
    if lookalike_reason and not reputation.is_official_brand_domain:
        risk_score += 25
        signals.append("lookalike_domain")
        reasons.append(lookalike_reason)

    if _has_hyphenated_brand_security_pattern(hostname) and not reputation.is_official_brand_domain:
        risk_score += 25
        signals.append("hyphenated_brand_security_domain")
        reasons.append("The domain combines a trusted brand with security/login wording in a non-official hostname.")

    if _subdomain_depth(hostname) >= 4 and not reputation.is_official_brand_domain:
        risk_score += 15
        signals.append("deep_subdomain_chain")
        reasons.append("The hostname has an unusually deep subdomain structure.")

    suspicious_tld = next((tld for tld in SUSPICIOUS_TLDS if hostname.endswith(tld)), "")
    if suspicious_tld:
        risk_score += 15
        signals.append("suspicious_tld")
        reasons.append(f"The hostname uses suspicious TLD {suspicious_tld}.")

    return DeepAnalysisResult(
        risk_score=min(risk_score, 100),
        reasons=reasons,
        signals=signals,
        placeholders=[
            run_url_ml_model_placeholder(url),
            check_certificate_reputation_placeholder(hostname),
            check_rdap_domain_age_placeholder(hostname),
            check_tranco_rank_placeholder(hostname),
            check_urlscan_placeholder(hostname),
        ],
    )


def run_url_ml_model_placeholder(url: str) -> dict:
    return _placeholder("url_ml_model")


def check_certificate_reputation_placeholder(hostname: str) -> dict:
    return _placeholder("certificate_reputation")


def check_rdap_domain_age_placeholder(hostname: str) -> dict:
    return _placeholder("rdap_domain_age")


def check_tranco_rank_placeholder(hostname: str) -> dict:
    return _placeholder("tranco_rank")


def check_urlscan_placeholder(hostname: str) -> dict:
    return _placeholder("urlscan")


def _placeholder(name: str) -> dict:
    return {
        "source": name,
        "status": "placeholder",
        "details": "Reserved for future integration.",
    }


def _detect_lookalike(hostname: str) -> str:
    compact_hostname = hostname.replace("-", "")
    for brand in TRUSTED_BRANDS:
        compact_brand = brand.replace(" ", "")
        if compact_brand.replace("o", "0") in compact_hostname:
            return f"The hostname appears to use a lookalike spelling of {brand.title()}."
        if re.search(r"(.)\1{2,}", compact_hostname) and compact_brand[:3] in compact_hostname:
            return f"The hostname has repeated letters that may imitate {brand.title()}."
    return ""


def _has_hyphenated_brand_security_pattern(hostname: str) -> bool:
    return any(
        brand in hostname and re.search(r"(login|verify|security|secure|account)", hostname)
        for brand in TRUSTED_BRANDS
    )


def _subdomain_depth(hostname: str) -> int:
    parts = [part for part in hostname.split(".") if part]
    return max(len(parts) - 2, 0)
