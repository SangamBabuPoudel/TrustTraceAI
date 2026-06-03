from dataclasses import dataclass
from typing import Protocol
from urllib.parse import urlparse

from app.data.brand_profiles import BRAND_PROFILES
from app.data.trusted_domains import TRUSTED_COMMERCE_DOMAINS
from app.services.reputation_service import is_domain_or_subdomain, normalize_hostname


PRODUCT_MARKETPLACE_TERMS = {
    "shop",
    "store",
    "product",
    "products",
    "iphone",
    "watch",
    "phone",
    "phones",
    "cell phones",
    "cart",
    "price",
    "trade-in",
    "filters",
    "reviews",
    "product listing",
    "free cell phones",
    "add to cart",
    "delivery",
    "pickup",
    "buy",
    "deal",
    "deals",
}

IDENTITY_CLAIM_TERMS = {
    "apple id",
    "google account",
    "microsoft account",
    "paypal login",
    "verify your",
    "verify account",
    "verify apple id",
    "sign in to",
    "security verification",
    "account locked",
    "account suspended",
    "unusual activity",
    "password reset",
    "security code",
    "otp",
    "one-time code",
    "confirm identity",
    "account recovery",
}


class LayoutHints(Protocol):
    has_centered_login_card: bool
    has_fullscreen_login_layout: bool
    has_minimal_login_page: bool


class VisualMetadata(Protocol):
    document_title: str
    primary_headings: list[str]
    favicons: list
    images: list
    logo_candidates: list
    button_texts: list[str]
    input_labels: list[str]
    brand_like_text: list[str]
    color_hints: list[str]
    layout_hints: LayoutHints


class FormMetadata(Protocol):
    has_password_field: bool
    has_email_or_username_field: bool


@dataclass(frozen=True)
class VisualCloneSignal:
    type: str
    severity: str
    brand: str
    message: str


@dataclass(frozen=True)
class VisualCloneResult:
    is_visual_clone_suspected: bool
    visual_clone_score: int
    visual_clone_confidence: str
    primary_clone_brand: str
    claimed_brands: list[str]
    signals: list[VisualCloneSignal]
    trust_signals: list[str]


def analyze_visual_clone(
    page_url: str,
    visual_metadata: VisualMetadata,
    forms: list[FormMetadata],
) -> VisualCloneResult:
    hostname = normalize_hostname(urlparse(page_url).hostname or "")
    evidence_text = _build_evidence_text(visual_metadata)
    trusted_commerce = _is_trusted_commerce_hostname(hostname)
    product_context = _has_product_marketplace_context(page_url, evidence_text)
    credential_form = any(
        form.has_password_field or form.has_email_or_username_field
        for form in forms
    )
    password_form = any(form.has_password_field for form in forms)
    layout_hints = visual_metadata.layout_hints
    layout_clone = (
        layout_hints.has_centered_login_card
        or layout_hints.has_fullscreen_login_layout
        or layout_hints.has_minimal_login_page
    )
    claimed_brands = _detect_claimed_brands(evidence_text)
    signals: list[VisualCloneSignal] = []
    trust_signals: list[str] = []
    score = 0

    if trusted_commerce and product_context and not password_form and not _has_any_identity_claim(evidence_text):
        if claimed_brands:
            brand_names = ", ".join(BRAND_PROFILES[brand]["brand_name"] for brand in claimed_brands[:3])
            trust_signals.append(
                f"Trusted commerce domain detected; {brand_names} appears in product listing context."
            )
        return VisualCloneResult(
            is_visual_clone_suspected=False,
            visual_clone_score=0,
            visual_clone_confidence="low",
            primary_clone_brand="",
            claimed_brands=claimed_brands,
            signals=[],
            trust_signals=trust_signals,
        )

    for brand in claimed_brands:
        profile = BRAND_PROFILES[brand]
        brand_name = profile["brand_name"]
        official = _is_official_brand_hostname(hostname, profile["official_domains"])

        if official:
            trust_signals.append(f"Official brand domain matched visual brand claim for {brand_name}.")
            continue

        logo_or_favicon_claim = _has_logo_or_favicon_claim(visual_metadata, brand)
        security_clone_language = _has_security_clone_language(evidence_text, profile)
        identity_claim_context = _has_identity_claim_context(evidence_text, profile)
        clone_context = password_form or security_clone_language or identity_claim_context

        if not clone_context:
            continue

        score += 20
        signals.append(_signal("visual_brand_claim", "medium", brand_name, f"Page visually claims to represent {brand_name}."))

        if clone_context:
            score += 35
            signals.append(_signal("brand_domain_mismatch", "high", brand_name, f"Page claims to represent {brand_name}, but the domain is not an official {brand_name} domain."))

        if credential_form and clone_context:
            score += 40
            signals.append(_signal("branded_login_form", "high", brand_name, "A branded login form appears on a non-official domain."))

        if logo_or_favicon_claim and clone_context:
            score += 25
            signals.append(_signal("logo_favicon_mismatch", "high", brand_name, f"Logo or favicon metadata suggests {brand_name}, but the domain does not match."))

        if security_clone_language:
            score += 25
            signals.append(_signal("security_clone_language", "high", brand_name, "Brand-related security or verification language appears on a non-official domain."))

        if layout_clone and credential_form:
            score += 20
            signals.append(_signal("login_layout_clone", "medium", brand_name, "Login layout resembles a branded sign-in page on a non-official domain."))

        if password_form:
            score += 35
            signals.append(_signal("password_field_on_branded_non_official_page", "high", brand_name, "A password field appears on a branded non-official page."))

    if trust_signals and not signals:
        score = min(score, 5)

    score = min(score, 100)
    confidence = "high" if score >= 70 else "medium" if score >= 40 else "low"

    return VisualCloneResult(
        is_visual_clone_suspected=score >= 70,
        visual_clone_score=score,
        visual_clone_confidence=confidence,
        primary_clone_brand=claimed_brands[0] if claimed_brands and signals else "",
        claimed_brands=claimed_brands,
        signals=_dedupe_signals(signals),
        trust_signals=trust_signals,
    )


def _build_evidence_text(metadata: VisualMetadata) -> str:
    parts = [
        metadata.document_title,
        " ".join(metadata.primary_headings),
        " ".join(metadata.button_texts),
        " ".join(metadata.input_labels),
        " ".join(metadata.brand_like_text),
        " ".join(metadata.color_hints),
    ]
    for item in list(metadata.favicons) + list(metadata.images) + list(metadata.logo_candidates):
        parts.extend([
            getattr(item, "href", ""),
            getattr(item, "src", ""),
            getattr(item, "alt", ""),
            getattr(item, "title", ""),
            getattr(item, "class_name", ""),
            getattr(item, "id", ""),
            getattr(item, "nearby_text", ""),
        ])
    return " ".join(parts).lower()


def _detect_claimed_brands(evidence_text: str) -> list[str]:
    claimed = []
    for brand, profile in BRAND_PROFILES.items():
        terms = profile["aliases"] + profile["visual_keywords"]
        if any(term.lower() in evidence_text for term in terms):
            claimed.append(brand)
    return claimed


def _is_official_brand_hostname(hostname: str, official_domains: list[str]) -> bool:
    return any(is_domain_or_subdomain(hostname, domain) for domain in official_domains)


def _has_logo_or_favicon_claim(metadata: VisualMetadata, brand: str) -> bool:
    profile = BRAND_PROFILES[brand]
    terms = [term.lower() for term in profile["aliases"] + profile["visual_keywords"]]
    for item in list(metadata.favicons) + list(metadata.logo_candidates) + list(metadata.images):
        item_text = " ".join([
            getattr(item, "href", ""),
            getattr(item, "src", ""),
            getattr(item, "alt", ""),
            getattr(item, "title", ""),
            getattr(item, "class_name", ""),
            getattr(item, "id", ""),
            getattr(item, "nearby_text", ""),
        ]).lower()
        if any(term in item_text for term in terms):
            return True
    return False


def _has_security_clone_language(evidence_text: str, profile: dict) -> bool:
    terms = profile["security_phrases"] + [
        "account locked",
        "unusual activity",
        "suspended",
        "security alert",
        "confirm identity",
        "account recovery",
        "security verification",
        "security code",
        "one-time code",
    ]
    return any(term.lower() in evidence_text for term in terms)


def _has_identity_claim_context(evidence_text: str, profile: dict) -> bool:
    brand_specific_login_phrases = [
        phrase
        for phrase in profile["login_phrases"]
        if _is_brand_specific_identity_phrase(phrase)
    ]
    terms = brand_specific_login_phrases + profile["security_phrases"] + list(IDENTITY_CLAIM_TERMS)
    return any(term.lower() in evidence_text for term in terms)


def _is_brand_specific_identity_phrase(phrase: str) -> bool:
    normalized = phrase.lower()
    if normalized in {"sign in", "log in", "continue"}:
        return False
    return True


def _has_any_identity_claim(evidence_text: str) -> bool:
    return any(term in evidence_text for term in IDENTITY_CLAIM_TERMS)


def _has_product_marketplace_context(page_url: str, evidence_text: str) -> bool:
    parsed_url = urlparse(page_url)
    combined = f"{parsed_url.path} {parsed_url.query} {evidence_text}".lower()
    return any(term in combined for term in PRODUCT_MARKETPLACE_TERMS)


def _is_trusted_commerce_hostname(hostname: str) -> bool:
    return any(is_domain_or_subdomain(hostname, domain) for domain in TRUSTED_COMMERCE_DOMAINS)


def _signal(signal_type: str, severity: str, brand: str, message: str) -> VisualCloneSignal:
    return VisualCloneSignal(type=signal_type, severity=severity, brand=brand, message=message)


def _dedupe_signals(signals: list[VisualCloneSignal]) -> list[VisualCloneSignal]:
    seen = set()
    deduped = []
    for signal in signals:
        key = (signal.type, signal.brand, signal.message)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(signal)
    return deduped
