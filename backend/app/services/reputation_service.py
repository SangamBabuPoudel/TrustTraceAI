from dataclasses import dataclass
from urllib.parse import urlparse

from app.data.trusted_domains import (
    HIGH_REPUTATION_DOMAINS,
    TRUSTED_BRANDS,
    TRUSTED_COMMERCE_DOMAINS,
)


IDENTITY_CONTEXT_TERMS = {
    "login",
    "signin",
    "sign-in",
    "verify",
    "verification",
    "account",
    "secure",
    "security",
    "password",
    "reset",
    "recovery",
    "otp",
    "code",
    "locked",
    "suspended",
    "update",
}

PRODUCT_MARKETPLACE_TERMS = {
    "shop",
    "store",
    "product",
    "products",
    "iphone",
    "watch",
    "phone",
    "phones",
    "cell",
    "cart",
    "price",
    "deal",
    "deals",
    "trade-in",
    "filter",
    "filters",
    "reviews",
    "listing",
    "delivery",
    "pickup",
    "buy",
    "sale",
    "search",
}


@dataclass(frozen=True)
class ReputationResult:
    hostname: str
    is_official_brand_domain: bool
    matched_brand: str
    official_domain: str
    is_high_reputation_domain: bool
    is_trusted_commerce_domain: bool
    reputation_score: int
    trust_signals: list[str]
    reputation_warnings: list[str]


def analyze_url_reputation(url: str) -> ReputationResult:
    hostname = normalize_hostname(urlparse(url).hostname or "")
    matched_brand = ""
    official_domain = ""
    is_official = False
    trust_signals: list[str] = []
    warnings: list[str] = []
    is_trusted_commerce = _is_trusted_commerce_hostname(hostname)
    has_product_context = _has_product_marketplace_context(url)
    has_identity_context = _has_identity_context(url)

    for brand, official_domains in TRUSTED_BRANDS.items():
        brand_in_url = _brand_appears(url, hostname, brand)
        official_match = next(
            (domain for domain in official_domains if is_domain_or_subdomain(hostname, domain)),
            "",
        )

        if official_match:
            matched_brand = brand
            official_domain = official_match
            is_official = True
            trust_signals.append(f"Official {brand.title()} domain detected.")
            break

        if brand_in_url and not matched_brand:
            matched_brand = brand
            official_domain = official_domains[0]
            if is_trusted_commerce and has_product_context and not has_identity_context:
                trust_signals.append(
                    f"Trusted commerce domain detected; {brand.title()} appears in product listing context."
                )
            elif _has_suspicious_brand_context(url, hostname, brand):
                warnings.append(
                    f"{brand.title()} brand keyword appears outside the official {official_domains[0]} domain in a login/security context."
                )

    is_high_reputation = hostname in HIGH_REPUTATION_DOMAINS
    if is_high_reputation:
        trust_signals.append("Domain is in the local high-reputation list.")

    if is_official and is_high_reputation:
        reputation_score = 95
    elif is_official:
        reputation_score = 85
    elif is_high_reputation:
        reputation_score = 90
    elif warnings:
        reputation_score = 20
    elif hostname:
        reputation_score = 50
    else:
        reputation_score = 0

    return ReputationResult(
        hostname=hostname,
        is_official_brand_domain=is_official,
        matched_brand=matched_brand,
        official_domain=official_domain,
        is_high_reputation_domain=is_high_reputation,
        is_trusted_commerce_domain=is_trusted_commerce,
        reputation_score=reputation_score,
        trust_signals=trust_signals,
        reputation_warnings=warnings,
    )


def normalize_hostname(hostname: str) -> str:
    return hostname.strip().lower().rstrip(".")


def is_domain_or_subdomain(hostname: str, domain: str) -> bool:
    normalized_hostname = normalize_hostname(hostname)
    normalized_domain = normalize_hostname(domain)
    return normalized_hostname == normalized_domain or normalized_hostname.endswith(f".{normalized_domain}")


def is_official_for_brand(hostname: str, brand: str) -> bool:
    return any(
        is_domain_or_subdomain(hostname, domain)
        for domain in TRUSTED_BRANDS.get(brand, [])
    )


def is_trusted_commerce_domain(hostname: str) -> bool:
    return _is_trusted_commerce_hostname(hostname)


def _brand_appears(url: str, hostname: str, brand: str) -> bool:
    compact_brand = brand.replace(" ", "").replace("-", "")
    normalized = f"{hostname} {urlparse(url).path}".lower()
    if urlparse(url).query:
        normalized = f"{normalized} {urlparse(url).query.lower()}"
    compact_normalized = normalized.replace("-", "").replace("_", "")
    return compact_brand in compact_normalized


def _is_trusted_commerce_hostname(hostname: str) -> bool:
    return any(is_domain_or_subdomain(hostname, domain) for domain in TRUSTED_COMMERCE_DOMAINS)


def _has_identity_context(url: str) -> bool:
    parsed = urlparse(url)
    normalized = f"{parsed.hostname or ''} {parsed.path} {parsed.query}".lower()
    normalized = normalized.replace("_", "-")
    return any(term in normalized for term in IDENTITY_CONTEXT_TERMS)


def _has_product_marketplace_context(url: str) -> bool:
    parsed = urlparse(url)
    normalized = f"{parsed.hostname or ''} {parsed.path} {parsed.query}".lower()
    normalized = normalized.replace("_", "-")
    return any(term in normalized for term in PRODUCT_MARKETPLACE_TERMS)


def _has_suspicious_brand_context(url: str, hostname: str, brand: str) -> bool:
    parsed = urlparse(url)
    normalized_hostname = normalize_hostname(hostname)
    normalized = f"{normalized_hostname} {parsed.path} {parsed.query}".lower().replace("_", "-")
    compact_brand = brand.replace(" ", "").replace("-", "")
    compact_hostname = normalized_hostname.replace("-", "").replace("_", "")
    brand_in_hostname = compact_brand in compact_hostname
    has_identity_context = any(term in normalized for term in IDENTITY_CONTEXT_TERMS)
    suspicious_hostname_pattern = brand_in_hostname and (
        "-" in normalized_hostname
        or any(term in normalized_hostname for term in IDENTITY_CONTEXT_TERMS)
    )

    return has_identity_context or suspicious_hostname_pattern
