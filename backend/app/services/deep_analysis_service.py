import re
from dataclasses import dataclass
from math import log2
from urllib.parse import urlparse

from app.data.trusted_domains import TRUSTED_BRANDS
from app.services.reputation_service import ReputationResult
from app.services.url_feature_extractor import SUSPICIOUS_TLDS


DEEP_SUSPICIOUS_TLDS = SUSPICIOUS_TLDS | {
    ".ga",
    ".cf",
    ".loan",
    ".party",
    ".download",
    ".gdn",
}

KNOWN_BRAND_ROOTS = {
    "google",
    "apple",
    "microsoft",
    "amazon",
    "paypal",
    "facebook",
    "instagram",
    "twitter",
    "netflix",
    "steam",
    "chase",
    "wellsfargo",
    "bankofamerica",
    "coinbase",
    "binance",
    "openai",
    "chatgpt",
    "claude",
    "gemini",
    "github",
}

HOMOGLYPH_MAP = {
    "а": "a",
    "е": "e",
    "о": "o",
    "р": "p",
    "с": "c",
    "х": "x",
    "ѕ": "s",
    "і": "i",
    "ј": "j",
    "ԁ": "d",
}

LOOKALIKE_PREFIXES = (
    "secure-",
    "login-",
    "verify-",
    "account-",
    "update-",
    "confirm-",
    "banking-",
    "signin-",
)

IP_ADDRESS_PATTERN = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")


@dataclass(frozen=True)
class DeepSignal:
    type: str
    severity: str
    message: str
    score_delta: int


@dataclass(frozen=True)
class DeepAnalysisResult:
    risk_score: int
    reasons: list[str]
    signals: list[str]
    deep_signals: list[DeepSignal]
    deep_score_delta: int
    placeholders: list[dict]


def analyze_url_deep(url: str, reputation: ReputationResult) -> DeepAnalysisResult:
    hostname = reputation.hostname
    parsed_url = urlparse(url)
    path_and_query = f"{parsed_url.path} {parsed_url.query}".lower()
    deep_signals: list[DeepSignal] = []

    if reputation.reputation_warnings:
        for warning in reputation.reputation_warnings:
            deep_signals.append(
                DeepSignal(
                    type="brand_spoofing",
                    severity="high",
                    message=warning,
                    score_delta=35,
                )
            )

    lookalike_reason = _detect_lookalike(hostname)
    if lookalike_reason and not reputation.is_official_brand_domain:
        deep_signals.append(
            DeepSignal(
                type="lookalike_domain",
                severity="high",
                message=lookalike_reason,
                score_delta=30,
            )
        )

    if _contains_homoglyph(hostname) and not reputation.is_official_brand_domain:
        deep_signals.append(
            DeepSignal(
                type="homoglyph",
                severity="high",
                message="The hostname contains lookalike Unicode characters.",
                score_delta=40,
            )
        )

    if _has_punycode_label(hostname) and not reputation.is_official_brand_domain:
        deep_signals.append(
            DeepSignal(
                type="punycode",
                severity="high",
                message="The hostname uses punycode, which can hide brand lookalike characters.",
                score_delta=40,
            )
        )

    typosquat_brand = _detect_typosquatting(hostname)
    if typosquat_brand and not reputation.is_official_brand_domain:
        deep_signals.append(
            DeepSignal(
                type="typosquatting",
                severity="high",
                message=f"The hostname is very similar to the trusted brand {typosquat_brand.title()}.",
                score_delta=35,
            )
        )

    if _has_hyphenated_brand_security_pattern(hostname) and not reputation.is_official_brand_domain:
        deep_signals.append(
            DeepSignal(
                type="hyphenated_brand_security_domain",
                severity="high",
                message="The domain combines a trusted brand with security/login wording in a non-official hostname.",
                score_delta=30,
            )
        )

    if _has_lookalike_prefix(hostname) and not reputation.is_official_brand_domain:
        deep_signals.append(
            DeepSignal(
                type="login_security_prefix",
                severity="medium",
                message="The hostname uses login/security wording as a domain prefix.",
                score_delta=20,
            )
        )

    if _subdomain_depth(hostname) >= 4 and not reputation.is_official_brand_domain:
        deep_signals.append(
            DeepSignal(
                type="deep_subdomain_chain",
                severity="medium",
                message="The hostname has an unusually deep subdomain structure.",
                score_delta=15,
            )
        )

    suspicious_tld = next((tld for tld in DEEP_SUSPICIOUS_TLDS if hostname.endswith(tld)), "")
    if suspicious_tld:
        deep_signals.append(
            DeepSignal(
                type="suspicious_tld",
                severity="medium",
                message=f"The hostname uses suspicious TLD {suspicious_tld}.",
                score_delta=15,
            )
        )

    if IP_ADDRESS_PATTERN.match(hostname):
        severity = "high" if _has_credential_context(path_and_query) else "medium"
        deep_signals.append(
            DeepSignal(
                type="ip_hostname",
                severity=severity,
                message="The URL uses an IP address instead of a named domain.",
                score_delta=35 if severity == "high" else 20,
            )
        )

    if _domain_entropy(hostname) >= 4.2 and len(hostname.replace(".", "")) >= 18:
        deep_signals.append(
            DeepSignal(
                type="high_entropy_domain",
                severity="medium",
                message="The hostname has an unusually random-looking character pattern.",
                score_delta=15,
            )
        )

    risk_score = min(sum(signal.score_delta for signal in deep_signals), 100)
    reasons = _dedupe([signal.message for signal in deep_signals])
    signals = _dedupe([signal.type for signal in deep_signals])

    return DeepAnalysisResult(
        risk_score=risk_score,
        reasons=reasons,
        signals=signals,
        deep_signals=deep_signals,
        deep_score_delta=-risk_score,
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


def _contains_homoglyph(hostname: str) -> bool:
    return any(character in HOMOGLYPH_MAP for character in hostname)


def _has_punycode_label(hostname: str) -> bool:
    return any(label.startswith("xn--") for label in hostname.split("."))


def _detect_typosquatting(hostname: str) -> str:
    labels = [label for label in hostname.split(".") if label]
    candidates = set(labels)
    for label in labels:
        candidates.update(part for part in label.split("-") if part)
        candidates.add(_normalize_ascii_lookalikes(label.replace("-", "")))

    for candidate in candidates:
        normalized_candidate = _normalize_ascii_lookalikes(candidate)
        if len(normalized_candidate) < 4:
            continue

        for brand in KNOWN_BRAND_ROOTS:
            if normalized_candidate == brand and candidate != brand:
                return brand
            if normalized_candidate == brand:
                continue
            if abs(len(normalized_candidate) - len(brand)) > 2:
                continue
            if _levenshtein_distance(normalized_candidate, brand) <= 2:
                return brand

    return ""


def _has_hyphenated_brand_security_pattern(hostname: str) -> bool:
    return any(
        brand in hostname and re.search(r"(login|verify|security|secure|account)", hostname)
        for brand in TRUSTED_BRANDS
    )


def _has_lookalike_prefix(hostname: str) -> bool:
    return any(label.startswith(LOOKALIKE_PREFIXES) for label in hostname.split("."))


def _subdomain_depth(hostname: str) -> int:
    parts = [part for part in hostname.split(".") if part]
    return max(len(parts) - 2, 0)


def _domain_entropy(hostname: str) -> float:
    compact = hostname.replace(".", "").replace("-", "")
    if not compact:
        return 0.0

    return -sum(
        (compact.count(character) / len(compact))
        * log2(compact.count(character) / len(compact))
        for character in set(compact)
    )


def _has_credential_context(text: str) -> bool:
    return any(
        keyword in text
        for keyword in ("login", "verify", "account", "password", "secure", "signin", "payment", "bank")
    )


def _normalize_ascii_lookalikes(value: str) -> str:
    return value.lower().translate(str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s"}))


def _levenshtein_distance(left: str, right: str) -> int:
    if left == right:
        return 0
    if not left:
        return len(right)
    if not right:
        return len(left)

    previous_row = list(range(len(right) + 1))
    for left_index, left_character in enumerate(left, start=1):
        current_row = [left_index]
        for right_index, right_character in enumerate(right, start=1):
            insert_cost = current_row[right_index - 1] + 1
            delete_cost = previous_row[right_index] + 1
            replace_cost = previous_row[right_index - 1] + (
                0 if left_character == right_character else 1
            )
            current_row.append(min(insert_cost, delete_cost, replace_cost))
        previous_row = current_row

    return previous_row[-1]


def _dedupe(values: list[str]) -> list[str]:
    return list(dict.fromkeys(values))
