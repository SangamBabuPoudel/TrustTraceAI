import re
from dataclasses import dataclass

from app.data.trusted_domains import TRUSTED_BRANDS


FREE_EMAIL_DOMAINS = {
    "gmail.com",
    "yahoo.com",
    "hotmail.com",
    "outlook.com",
    "icloud.com",
    "proton.me",
    "aol.com",
}

BRAND_DOMAINS = {brand: domains[0] for brand, domains in TRUSTED_BRANDS.items()}
BRAND_DOMAINS["bank of america"] = "bankofamerica.com"
BRAND_DOMAINS["wells fargo"] = "wellsfargo.com"


@dataclass(frozen=True)
class SenderIdentityAnalysis:
    risk_score: int
    reasons: list[str]
    signals: list[str]


def analyze_sender_identity(
    sender: str,
    sender_type: str,
    mentioned_brands: list[str],
    has_company_or_security_claim: bool,
    has_urgent_credential_request: bool,
    has_suspicious_links: bool,
) -> SenderIdentityAnalysis:
    normalized_sender = sender.strip().lower()
    reasons: list[str] = []
    signals: list[str] = []
    risk_score = 0

    if sender_type == "phone":
        if has_company_or_security_claim:
            risk_score += 30
            signals.append("phone_claims_company")
            reasons.append("The message claims to be from a company or bank but appears to come from a regular phone number.")
        if has_urgent_credential_request:
            risk_score += 30
            signals.append("phone_urgent_credential_request")
            reasons.append("The phone-based message contains urgent credential-request language.")
        if has_suspicious_links:
            risk_score += 20
            signals.append("phone_message_with_suspicious_links")
            reasons.append("The phone-based message contains suspicious links.")
        return SenderIdentityAnalysis(min(risk_score, 100), reasons, signals)

    sender_domain = _extract_sender_domain(normalized_sender)
    if not sender_domain:
        return SenderIdentityAnalysis(0, reasons, signals)

    if sender_domain in FREE_EMAIL_DOMAINS and has_company_or_security_claim:
        brand_text = mentioned_brands[0].title() if mentioned_brands else "a trusted company or security team"
        risk_score += 35
        signals.append("free_email_provider_impersonation")
        reasons.append(
            f"The sender uses a personal/free email provider while claiming to represent {brand_text}."
        )

    for brand in mentioned_brands:
        official_domains = _official_domains_for_brand(brand)
        if official_domains and not any(_domain_matches(sender_domain, domain) for domain in official_domains):
            risk_score += 30
            signals.append("brand_sender_domain_mismatch")
            reasons.append(
                f"The message mentions {brand.title()}, but the sender domain does not match the official {brand.title()} domain."
            )

    lookalike_reason = _detect_lookalike_domain(sender_domain)
    if lookalike_reason:
        risk_score += 25
        signals.append("lookalike_sender_domain")
        reasons.append(lookalike_reason)

    return SenderIdentityAnalysis(min(risk_score, 100), reasons, signals)


def _extract_sender_domain(sender: str) -> str:
    if "@" not in sender:
        return ""
    return sender.rsplit("@", 1)[1].strip(" >")


def _domain_matches(sender_domain: str, official_domain: str) -> bool:
    return sender_domain == official_domain or sender_domain.endswith(f".{official_domain}")


def _official_domains_for_brand(brand: str) -> list[str]:
    if brand in TRUSTED_BRANDS:
        return TRUSTED_BRANDS[brand]
    domain = BRAND_DOMAINS.get(brand)
    return [domain] if domain else []


def _detect_lookalike_domain(domain: str) -> str:
    compact_domain = domain.replace("-", "")
    for brand, official_domain in BRAND_DOMAINS.items():
        compact_brand = brand.replace(" ", "")
        if _domain_matches(domain, official_domain):
            continue
        if compact_brand in compact_domain:
            return f"The sender domain contains the brand name {brand.title()} inside a non-official domain."
        if compact_brand.replace("o", "0") in compact_domain:
            return f"The sender domain appears to use a lookalike spelling of {brand.title()}."
        if re.search(r"(.)\1{2,}", compact_domain) and compact_brand[:3] in compact_domain:
            return f"The sender domain has an unusual repeated-letter pattern that may imitate {brand.title()}."
    return ""
