from dataclasses import dataclass


@dataclass(frozen=True)
class ContentRule:
    name: str
    keywords: tuple[str, ...]
    weight: int
    explanation: str


@dataclass(frozen=True)
class ContentAnalysis:
    risk_score: int
    reasons: list[str]
    signals: list[str]
    has_account_verification_language: bool


CONTENT_RULES = (
    ContentRule(
        name="urgent_language",
        keywords=("urgent", "immediately", "act now", "limited time", "final warning"),
        weight=15,
        explanation="The page uses urgent language that may pressure users to act quickly.",
    ),
    ContentRule(
        name="account_threat_language",
        keywords=("suspended", "locked", "disabled", "restricted", "unusual activity"),
        weight=20,
        explanation="The page mentions account restrictions or unusual activity.",
    ),
    ContentRule(
        name="credential_language",
        keywords=("password", "login", "verify", "confirm identity", "security code"),
        weight=20,
        explanation="The page asks about credentials or identity verification.",
    ),
    ContentRule(
        name="payment_refund_language",
        keywords=("payment failed", "refund", "invoice", "billing", "bank account"),
        weight=15,
        explanation="The page references payment, refund, billing, or bank account topics.",
    ),
    ContentRule(
        name="prize_scam_language",
        keywords=("winner", "congratulations", "claim reward", "free gift"),
        weight=15,
        explanation="The page uses prize or reward wording commonly found in scams.",
    ),
    ContentRule(
        name="fear_language",
        keywords=(
            "your account will be closed",
            "unauthorized access",
            "security alert",
        ),
        weight=20,
        explanation="The page uses fear-based security language to create urgency.",
    ),
)


def analyze_page_content(page_title: str, visible_text: str) -> ContentAnalysis:
    text_to_scan = _normalize_text(f"{page_title} {visible_text}")
    reasons: list[str] = []
    signals: list[str] = []
    risk_score = 0

    for rule in CONTENT_RULES:
        matches = _find_keyword_matches(text_to_scan, rule.keywords)

        if not matches:
            continue

        risk_score += rule.weight
        matched_terms = ", ".join(matches)
        signals.append(rule.name)
        reasons.append(f"{rule.explanation} Matched term(s): {matched_terms}.")

    combo_score, combo_reasons, combo_signals = _analyze_content_combinations(signals)
    risk_score += combo_score
    reasons.extend(combo_reasons)
    signals.extend(combo_signals)

    return ContentAnalysis(
        risk_score=min(risk_score, 100),
        reasons=reasons,
        signals=signals,
        has_account_verification_language=_has_account_verification_language(signals),
    )


def _normalize_text(text: str) -> str:
    return " ".join(text.lower().split())


def _find_keyword_matches(text: str, keywords: tuple[str, ...]) -> list[str]:
    return sorted(keyword for keyword in keywords if keyword in text)


def _analyze_content_combinations(signals: list[str]) -> tuple[int, list[str], list[str]]:
    signal_set = set(signals)
    combo_score = 0
    combo_reasons: list[str] = []
    combo_signals: list[str] = []

    account_warning_combo = {
        "urgent_language",
        "account_threat_language",
        "credential_language",
    }
    security_fear_combo = {
        "urgent_language",
        "credential_language",
        "fear_language",
    }

    if account_warning_combo.issubset(signal_set):
        combo_score += 25
        combo_signals.append("urgent_account_verification_combo")
        combo_reasons.append(
            "The page combines urgent language, account-threat language, and credential verification language."
        )

    if security_fear_combo.issubset(signal_set):
        combo_score += 20
        combo_signals.append("security_fear_credential_combo")
        combo_reasons.append(
            "The page combines security-alert language with credential requests and urgency."
        )

    return combo_score, combo_reasons, combo_signals


def _has_account_verification_language(signals: list[str]) -> bool:
    signal_set = set(signals)
    return bool(
        {"account_threat_language", "credential_language"}.issubset(signal_set)
        or "urgent_account_verification_combo" in signal_set
        or "security_fear_credential_combo" in signal_set
    )
