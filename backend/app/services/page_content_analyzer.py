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

    return ContentAnalysis(
        risk_score=min(risk_score, 100),
        reasons=reasons,
        signals=signals,
    )


def _normalize_text(text: str) -> str:
    return " ".join(text.lower().split())


def _find_keyword_matches(text: str, keywords: tuple[str, ...]) -> list[str]:
    return sorted(keyword for keyword in keywords if keyword in text)
