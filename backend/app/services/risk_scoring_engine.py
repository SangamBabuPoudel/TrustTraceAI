from dataclasses import dataclass

from app.services.url_feature_extractor import UrlFeatures


@dataclass(frozen=True)
class RiskScore:
    risk_level: str
    phishing_probability: float
    trust_score: int


def score_url_risk(features: UrlFeatures) -> RiskScore:
    points = 0

    if features.uses_http:
        points += 20
    if features.is_long_url:
        points += 15
    if features.suspicious_keywords:
        points += min(len(features.suspicious_keywords) * 10, 30)
    if features.has_ip_address:
        points += 25
    if features.has_excessive_hyphens:
        points += 10
    if features.has_many_subdomains:
        points += 15
    if features.has_at_symbol:
        points += 25

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
