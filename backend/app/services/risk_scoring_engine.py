from dataclasses import dataclass

from app.services.url_feature_extractor import UrlFeatures


SIGNAL_WEIGHTS = {
    "uses_http": 15,
    "is_long_url": 10,
    "suspicious_keywords": 8,
    "has_ip_address": 25,
    "has_excessive_hyphens": 10,
    "has_many_subdomains": 15,
    "has_at_symbol": 20,
    "is_url_shortener": 30,
    "suspicious_tld": 15,
    "brand_impersonation_keywords": 25,
    "has_encoded_characters": 10,
    "has_multiple_slashes": 10,
    "has_long_query_string": 10,
}


@dataclass(frozen=True)
class RiskScore:
    risk_level: str
    phishing_probability: float
    trust_score: int


def score_url_risk(features: UrlFeatures) -> RiskScore:
    if features.is_local_development:
        return RiskScore(
            risk_level="low",
            phishing_probability=0.0,
            trust_score=100,
        )

    points = 0

    if features.uses_http:
        points += SIGNAL_WEIGHTS["uses_http"]
    if features.is_long_url:
        points += SIGNAL_WEIGHTS["is_long_url"]
    if features.suspicious_keywords:
        points += min(
            len(features.suspicious_keywords) * SIGNAL_WEIGHTS["suspicious_keywords"],
            30,
        )
    if features.has_ip_address:
        points += SIGNAL_WEIGHTS["has_ip_address"]
    if features.has_excessive_hyphens:
        points += SIGNAL_WEIGHTS["has_excessive_hyphens"]
    if features.has_many_subdomains:
        points += SIGNAL_WEIGHTS["has_many_subdomains"]
    if features.has_at_symbol:
        points += SIGNAL_WEIGHTS["has_at_symbol"]
    if features.is_url_shortener:
        points += SIGNAL_WEIGHTS["is_url_shortener"]
    if features.suspicious_tld:
        points += SIGNAL_WEIGHTS["suspicious_tld"]
    if features.brand_impersonation_keywords:
        points += SIGNAL_WEIGHTS["brand_impersonation_keywords"]
    if features.has_encoded_characters:
        points += SIGNAL_WEIGHTS["has_encoded_characters"]
    if features.has_multiple_slashes:
        points += SIGNAL_WEIGHTS["has_multiple_slashes"]
    if features.has_long_query_string:
        points += SIGNAL_WEIGHTS["has_long_query_string"]

    capped_points = min(points, 100)
    phishing_probability = round(capped_points / 100, 2)
    trust_score = max(100 - capped_points, 0)

    if capped_points >= 60:
        risk_level = "high"
    elif capped_points >= 30:
        risk_level = "medium"
    else:
        risk_level = "low"

    return RiskScore(
        risk_level=risk_level,
        phishing_probability=phishing_probability,
        trust_score=trust_score,
    )
