from dataclasses import dataclass

from app.data.trusted_domains import TRUSTED_BRANDS


@dataclass(frozen=True)
class MessageRule:
    name: str
    keywords: tuple[str, ...]
    weight: int
    explanation: str


@dataclass(frozen=True)
class MessageAnalysis:
    risk_score: int
    reasons: list[str]
    signals: list[str]
    mentioned_brands: list[str]
    has_urgent_credential_request: bool
    has_company_or_security_claim: bool


MESSAGE_RULES = (
    MessageRule(
        name="urgency",
        keywords=("urgent", "immediately", "act now", "final warning", "limited time", "respond now"),
        weight=18,
        explanation="The message uses urgent language.",
    ),
    MessageRule(
        name="account_threat",
        keywords=("suspended", "locked", "disabled", "restricted", "unusual activity", "account closure", "account will be closed"),
        weight=22,
        explanation="The message uses account-suspension or account-threat language.",
    ),
    MessageRule(
        name="credential_request",
        keywords=("password", "login", "verify", "confirm identity", "security code", "authentication code", "one-time code", "otp"),
        weight=25,
        explanation="The message asks for password, login, or security-code verification.",
    ),
    MessageRule(
        name="payment_refund_invoice",
        keywords=("refund", "payment failed", "invoice", "billing", "bank account", "card declined", "transaction failed"),
        weight=18,
        explanation="The message references payment, refund, invoice, or banking issues.",
    ),
    MessageRule(
        name="prize_scam",
        keywords=("congratulations", "winner", "claim reward", "free gift", "lottery", "prize"),
        weight=18,
        explanation="The message uses prize or reward language often found in scams.",
    ),
    MessageRule(
        name="fear_security",
        keywords=("unauthorized access", "security alert", "suspicious activity", "account compromised"),
        weight=20,
        explanation="The message uses fear-based security language.",
    ),
)

KNOWN_BRANDS = set(TRUSTED_BRANDS) | {"bank of america", "wells fargo"}

COMPANY_CLAIM_WORDS = {
    "account",
    "bank",
    "security",
    "support",
    "payment",
    "delivery",
    "team",
    "service",
    "verify",
}


def analyze_message_text(subject: str, message_text: str) -> MessageAnalysis:
    text_to_scan = _normalize_text(f"{subject} {message_text}")
    reasons: list[str] = []
    signals: list[str] = []
    risk_score = 0

    for rule in MESSAGE_RULES:
        matches = _find_matches(text_to_scan, rule.keywords)
        if not matches:
            continue

        risk_score += rule.weight
        signals.append(rule.name)
        reasons.append(f"{rule.explanation} Matched term(s): {', '.join(matches)}.")

    if {"urgency", "account_threat", "credential_request"}.issubset(set(signals)):
        risk_score += 25
        signals.append("urgent_account_credential_combo")
        reasons.append("The message combines urgency, account-threat language, and credential requests.")

    if {"fear_security", "credential_request"}.issubset(set(signals)):
        risk_score += 18
        signals.append("security_credential_combo")
        reasons.append("The message combines security-alert language with credential requests.")

    mentioned_brands = sorted(brand for brand in KNOWN_BRANDS if brand in text_to_scan)
    has_company_or_security_claim = bool(
        mentioned_brands or any(word in text_to_scan for word in COMPANY_CLAIM_WORDS)
    )

    return MessageAnalysis(
        risk_score=min(risk_score, 100),
        reasons=reasons,
        signals=signals,
        mentioned_brands=mentioned_brands,
        has_urgent_credential_request={"urgency", "credential_request"}.issubset(set(signals)),
        has_company_or_security_claim=has_company_or_security_claim,
    )


def _normalize_text(text: str) -> str:
    return " ".join(text.lower().split())


def _find_matches(text: str, keywords: tuple[str, ...]) -> list[str]:
    return sorted(keyword for keyword in keywords if keyword in text)
