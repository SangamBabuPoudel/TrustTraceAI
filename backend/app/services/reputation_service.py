from dataclasses import dataclass
from urllib.parse import urlparse

from app.data.trusted_domains import HIGH_REPUTATION_DOMAINS, TRUSTED_BRANDS


@dataclass(frozen=True)
class ReputationResult:
    hostname: str
    is_official_brand_domain: bool
    matched_brand: str
    official_domain: str
    is_high_reputation_domain: bool
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
            warnings.append(
                f"{brand.title()} brand keyword appears outside the official {official_domains[0]} domain."
            )

    is_high_reputation = hostname in HIGH_REPUTATION_DOMAINS
    if is_high_reputation:
        trust_signals.append("Domain is in the local high-reputation list.")

    if is_official and is_high_reputation:
        reputation_score = 95
    elif is_official:
        reputation_score = 85
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


def _brand_appears(url: str, hostname: str, brand: str) -> bool:
    compact_brand = brand.replace(" ", "").replace("-", "")
    normalized = f"{hostname} {urlparse(url).path}".lower()
    compact_normalized = normalized.replace("-", "").replace("_", "")
    return compact_brand in compact_normalized
