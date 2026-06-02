import re
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlparse

from app.services.reputation_service import analyze_url_reputation, is_official_for_brand


SUSPICIOUS_KEYWORDS = {
    "login",
    "verify",
    "account",
    "secure",
    "update",
    "bank",
    "password",
    "refund",
    "payment",
    "billing",
    "signin",
    "signup",
    "sign-in",
    "sign-up",
}

URL_SHORTENER_DOMAINS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "rebrand.ly",
}

SUSPICIOUS_TLDS = {
    ".xyz",
    ".top",
    ".click",
    ".work",
    ".zip",
    ".country",
    ".stream",
    ".gq",
    ".tk",
    ".ml",
    ".ga",
    ".cf",
    ".loan",
    ".party",
    ".download",
    ".gdn",
}

BRAND_IMPERSONATION_KEYWORDS = {
    "paypal",
    "amazon",
    "apple",
    "openai",
    "chatgpt",
    "anthropic",
    "claude",
    "gemini",
    "youtube",
    "microsoft",
    "google",
    "netflix",
    "facebook",
    "instagram",
    "bankofamerica",
    "chase",
    "wells-fargo",
    "wellsfargo",
    "github",
    "wikipedia",
}

IP_ADDRESS_PATTERN = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
ENCODED_CHARACTER_PATTERN = re.compile(r"%[0-9a-fA-F]{2}")
LOCAL_DEVELOPMENT_HOSTS = {"localhost", "127.0.0.1", "0.0.0.0", "::1"}


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
    is_local_development: bool
    is_url_shortener: bool
    suspicious_tld: Optional[str]
    brand_impersonation_keywords: list[str]
    has_encoded_characters: bool
    has_multiple_slashes: bool
    query_length: int
    has_long_query_string: bool


def extract_url_features(url: str) -> UrlFeatures:
    parsed_url = urlparse(url)
    hostname = parsed_url.hostname or ""
    normalized_hostname = hostname.lower()
    normalized_url = url.lower()
    normalized_shortener_host = normalized_hostname.removeprefix("www.")
    reputation = analyze_url_reputation(url)

    suspicious_keywords = sorted(
        keyword for keyword in SUSPICIOUS_KEYWORDS if keyword in normalized_url
    )
    brand_impersonation_keywords = sorted(
        keyword
        for keyword in BRAND_IMPERSONATION_KEYWORDS
        if keyword in normalized_url and not is_official_for_brand(normalized_hostname, keyword)
    )

    hostname_parts = [part for part in hostname.split(".") if part]
    subdomain_count = max(len(hostname_parts) - 2, 0)
    hyphen_count = hostname.count("-")
    suspicious_tld = _find_suspicious_tld(normalized_hostname)
    url_without_scheme = url.split("://", 1)[-1]

    return UrlFeatures(
        url=url,
        scheme=parsed_url.scheme,
        hostname=hostname,
        length=len(url),
        uses_http=parsed_url.scheme == "http",
        is_long_url=len(url) > 75 and not reputation.is_high_reputation_domain,
        suspicious_keywords=suspicious_keywords,
        has_ip_address=bool(IP_ADDRESS_PATTERN.match(hostname)),
        hyphen_count=hyphen_count,
        has_excessive_hyphens=hyphen_count >= 3,
        subdomain_count=subdomain_count,
        has_many_subdomains=subdomain_count >= 3,
        has_at_symbol="@" in url,
        is_local_development=normalized_hostname in LOCAL_DEVELOPMENT_HOSTS,
        is_url_shortener=normalized_shortener_host in URL_SHORTENER_DOMAINS,
        suspicious_tld=suspicious_tld,
        brand_impersonation_keywords=brand_impersonation_keywords,
        has_encoded_characters=bool(ENCODED_CHARACTER_PATTERN.search(url)),
        has_multiple_slashes="//" in url_without_scheme,
        query_length=len(parsed_url.query),
        has_long_query_string=len(parsed_url.query) > 80,
    )


def _find_suspicious_tld(hostname: str) -> Optional[str]:
    for tld in SUSPICIOUS_TLDS:
        if hostname.endswith(tld):
            return tld

    return None
