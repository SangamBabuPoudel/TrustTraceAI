from dataclasses import dataclass
from typing import Protocol
from urllib.parse import urlparse

from app.services.explanation_engine import build_explanations
from app.services.risk_scoring_engine import score_url_risk
from app.services.sender_identity_analyzer import BRAND_DOMAINS
from app.data.trusted_domains import TRUSTED_BRANDS
from app.services.url_feature_extractor import extract_url_features


class MessageLinkMetadata(Protocol):
    text: str
    href: str


@dataclass(frozen=True)
class MessageLinkAnalysis:
    risk_score: int
    reasons: list[str]
    signals: list[str]


def analyze_message_links(links: list[MessageLinkMetadata], mentioned_brands: list[str]) -> MessageLinkAnalysis:
    reasons: list[str] = []
    signals: list[str] = []
    risk_score = 0

    for index, link in enumerate(links, start=1):
        if not link.href:
            continue

        features = extract_url_features(link.href)
        url_score = score_url_risk(features)
        url_reasons = [
            reason
            for reason in build_explanations(features)
            if not reason.startswith("No obvious phishing indicators")
        ]

        if url_reasons:
            risk_score += min(round(url_score.phishing_probability * 100), 45)
            signals.append("suspicious_message_link")
            reasons.extend(f"Link {index}: {reason}" for reason in url_reasons)

        link_text_brands = _brands_in_text(link.text)
        destination_domain = urlparse(link.href).hostname or ""
        brands_to_check = sorted(set(mentioned_brands + link_text_brands))

        for brand in brands_to_check:
            official_domains = TRUSTED_BRANDS.get(brand) or [BRAND_DOMAINS.get(brand, "")]
            official_domains = [domain for domain in official_domains if domain]
            if official_domains and not any(_domain_matches(destination_domain, domain) for domain in official_domains):
                risk_score += 35
                signals.append("link_text_destination_mismatch")
                reasons.append(
                    f"The displayed link text mentions {brand.title()}, but the actual destination is not {official_domains[0]}."
                )

    return MessageLinkAnalysis(
        risk_score=min(risk_score, 100),
        reasons=reasons,
        signals=signals,
    )


def _brands_in_text(text: str) -> list[str]:
    normalized_text = text.lower()
    return sorted(brand for brand in BRAND_DOMAINS if brand in normalized_text)


def _domain_matches(domain: str, official_domain: str) -> bool:
    return domain == official_domain or domain.endswith(f".{official_domain}")
