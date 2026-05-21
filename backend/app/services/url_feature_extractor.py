import re
from dataclasses import dataclass
from urllib.parse import urlparse


SUSPICIOUS_KEYWORDS = {
    "login",
    "verify",
    "account",
    "secure",
    "update",
    "bank",
    "password",
    "refund",
}

IP_ADDRESS_PATTERN = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")


@dataclass(frozen=True)
class UrlFeatures:
    url: str
    scheme: str
    hostname: str
    length: int
    uses_http: bool
    is_long_url: bool
    suspicious_keywords: list[str]
    has_ip_address: bool
    hyphen_count: int
    has_excessive_hyphens: bool
    subdomain_count: int
    has_many_subdomains: bool
    has_at_symbol: bool


def extract_url_features(url: str) -> UrlFeatures:
    parsed_url = urlparse(url)
    hostname = parsed_url.hostname or ""
    normalized_url = url.lower()

    suspicious_keywords = sorted(
        keyword for keyword in SUSPICIOUS_KEYWORDS if keyword in normalized_url
    )

    hostname_parts = [part for part in hostname.split(".") if part]
    subdomain_count = max(len(hostname_parts) - 2, 0)
    hyphen_count = hostname.count("-")

    return UrlFeatures(
        url=url,
        scheme=parsed_url.scheme,
        hostname=hostname,
        length=len(url),
        uses_http=parsed_url.scheme == "http",
        is_long_url=len(url) > 75,
        suspicious_keywords=suspicious_keywords,
        has_ip_address=bool(IP_ADDRESS_PATTERN.match(hostname)),
        hyphen_count=hyphen_count,
        has_excessive_hyphens=hyphen_count >= 3,
        subdomain_count=subdomain_count,
        has_many_subdomains=subdomain_count >= 3,
        has_at_symbol="@" in url,
    )
