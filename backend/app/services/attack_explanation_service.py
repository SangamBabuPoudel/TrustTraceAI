from typing import Optional


ATTACK_TEMPLATES = {
    "Known-bad URL / malware": {
        "attack_category": "Known threat intelligence",
        "summary": "This URL appears in a known-bad threat list or local blocklist.",
        "how_it_works": [
            "The destination matched a known-bad URL or domain list.",
            "Known-bad links are often used for phishing, malware delivery, or credential theft.",
            "Attackers may rotate similar domains to avoid detection.",
        ],
        "what_to_avoid": [
            "Do not visit the link unless you are testing in a safe environment.",
            "Do not enter passwords, payment details, or security codes.",
            "Do not download files from this destination.",
        ],
        "safer_action": "Close the page and use a trusted source or official website instead.",
    },
    "Credential phishing": {
        "attack_category": "Credential theft",
        "summary": "This may be trying to collect login credentials or security codes.",
        "how_it_works": [
            "The page or message uses login, password, verification, or security-code language.",
            "The user may be asked to enter passwords, one-time codes, or personal details.",
            "Captured credentials can be reused to access real accounts.",
        ],
        "what_to_avoid": [
            "Do not enter passwords or security codes.",
            "Do not use account recovery or verification links from this page.",
            "Do not approve login prompts that you did not initiate.",
        ],
        "safer_action": "Go directly to the official website by typing the address yourself or using a trusted bookmark.",
    },
    "Brand impersonation phishing": {
        "attack_category": "Brand impersonation",
        "summary": "This appears to impersonate a trusted brand.",
        "how_it_works": [
            "The attacker uses a brand name outside the official domain.",
            "The page or message borrows familiar brand language to create trust.",
            "The user may be pushed toward a fake login, payment, or verification flow.",
        ],
        "what_to_avoid": [
            "Do not trust the page just because it mentions a known brand.",
            "Do not enter account, payment, or identity information.",
            "Do not click recovery or payment links from the suspicious page.",
        ],
        "safer_action": "Open the official brand site in a new tab using a trusted bookmark or manually typed address.",
    },
    "Typosquatting / lookalike domain": {
        "attack_category": "Lookalike domain",
        "summary": "The domain appears designed to look similar to a trusted brand.",
        "how_it_works": [
            "Attackers register misspelled, punycode, or lookalike domains.",
            "Small spelling changes can make fake domains look legitimate at a glance.",
            "The fake domain may host login pages, payment prompts, or malware.",
        ],
        "what_to_avoid": [
            "Do not assume the domain is safe because it looks familiar.",
            "Do not enter passwords, security codes, or payment details.",
            "Do not download files from the lookalike domain.",
        ],
        "safer_action": "Check the domain carefully and navigate to the official site yourself.",
    },
    "Insecure credential collection": {
        "attack_category": "Insecure transport",
        "summary": "This page may expose sensitive data because it is not encrypted.",
        "how_it_works": [
            "The page uses HTTP instead of encrypted HTTPS.",
            "Login, account, payment, or password data could be exposed in transit.",
            "Attackers may intercept or tamper with unencrypted traffic.",
        ],
        "what_to_avoid": [
            "Do not enter passwords on an HTTP page.",
            "Do not submit payment or account recovery information.",
            "Do not ignore browser Not Secure warnings.",
        ],
        "safer_action": "Look for the official HTTPS version of the site before entering sensitive information.",
    },
    "Suspicious link redirection": {
        "attack_category": "Hidden destination",
        "summary": "This link may hide its real destination.",
        "how_it_works": [
            "Shortened or mismatched links can conceal where the user will land.",
            "The visible link text may mention one brand while the destination goes elsewhere.",
            "Attackers use redirects to move users into phishing or malware pages.",
        ],
        "what_to_avoid": [
            "Do not click shortened or mismatched links from untrusted messages.",
            "Do not rely only on the displayed link text.",
            "Do not enter credentials after an unexpected redirect.",
        ],
        "safer_action": "Open the official site directly instead of following the suspicious link.",
    },
    "Clipboard manipulation risk": {
        "attack_category": "Clipboard abuse",
        "summary": "This page or clipboard content may be trying to manipulate copied values or trick users into pasting sensitive information.",
        "how_it_works": [
            "Attackers may ask users to paste OTPs, recovery phrases, private keys, or wallet addresses.",
            "A malicious page may copy a different value than the one visibly shown.",
            "Clipboard manipulation can redirect payments, steal accounts, or expose sensitive secrets.",
        ],
        "what_to_avoid": [
            "Do not paste recovery phrases, private keys, passwords, OTPs, or payment addresses into untrusted pages.",
            "Verify destination URLs and wallet addresses manually.",
            "Do not trust copy buttons on suspicious pages without checking the pasted value.",
        ],
        "safer_action": "Use official apps or trusted websites, and manually verify sensitive copied values before pasting.",
    },
    "Urgency / social engineering pressure": {
        "attack_category": "Social engineering",
        "summary": "This uses pressure language to make users act quickly.",
        "how_it_works": [
            "The message may claim there is an urgent account, payment, or security problem.",
            "Pressure language reduces the time users spend verifying the destination.",
            "The attacker tries to make the user click or submit information immediately.",
        ],
        "what_to_avoid": [
            "Do not rush into clicking links or submitting information.",
            "Do not trust threats of immediate account closure without verification.",
            "Do not call phone numbers or use links from suspicious messages.",
        ],
        "safer_action": "Pause, verify through the official website, and contact support through a trusted channel.",
    },
    "Repeated scam/campaign pattern": {
        "attack_category": "Campaign behavior",
        "summary": "A similar message has appeared before, which can indicate repeated scam activity.",
        "how_it_works": [
            "Repeated similar messages can be part of a phishing campaign.",
            "Attackers may resend urgent messages until a user clicks.",
            "The repetition can make the message feel more important than it is.",
        ],
        "what_to_avoid": [
            "Do not respond to repeated suspicious messages.",
            "Do not click links just because the warning was sent again.",
            "Do not share verification codes or account information.",
        ],
        "safer_action": "Delete or report repeated suspicious messages and verify account status directly.",
    },
    "Unknown / low-risk": {
        "attack_category": "No strong pattern",
        "summary": "No strong attack pattern was identified from the current checks.",
        "how_it_works": [
            "TrustTrace did not find strong phishing, impersonation, or credential-harvesting patterns.",
        ],
        "what_to_avoid": [
            "Stay alert for unexpected requests for passwords, payment details, or security codes.",
        ],
        "safer_action": "Continue normally, but verify sensitive requests through official channels.",
    },
}

PRIORITY = [
    "Known-bad URL / malware",
    "Credential phishing",
    "Brand impersonation phishing",
    "Typosquatting / lookalike domain",
    "Insecure credential collection",
    "Suspicious link redirection",
    "Clipboard manipulation risk",
    "Urgency / social engineering pressure",
    "Repeated scam/campaign pattern",
    "Unknown / low-risk",
]


def build_attack_explanation(
    reasons: list[str],
    risk_level: str,
    signals: Optional[dict] = None,
    threat_intel: Optional[dict] = None,
    deep_analysis: Optional[dict] = None,
    repeat_count: int = 1,
    repeat_warning: Optional[str] = None,
) -> dict:
    signals = signals or {}
    evidence = _collect_evidence(reasons, signals, threat_intel, deep_analysis, repeat_warning)
    detected = _detect_attack_types(evidence=evidence, threat_intel=threat_intel, repeat_count=repeat_count)
    primary = _choose_primary(detected)
    template = ATTACK_TEMPLATES[primary]

    return {
        "attack_type": primary,
        "attack_category": template["attack_category"],
        "severity": _severity_for(primary, risk_level),
        "summary": template["summary"],
        "how_it_works": template["how_it_works"],
        "what_to_avoid": template["what_to_avoid"],
        "safer_action": template["safer_action"],
        "secondary_attack_types": [attack for attack in detected if attack != primary],
    }


def _collect_evidence(
    reasons: list[str],
    signals: dict,
    threat_intel: Optional[dict],
    deep_analysis: Optional[dict],
    repeat_warning: Optional[str],
) -> str:
    parts = list(reasons)
    for value in signals.values():
        if isinstance(value, list):
            parts.extend(str(item) for item in value)
    if threat_intel:
        parts.extend(str(value) for value in threat_intel.values())
    if deep_analysis:
        for signal in deep_analysis.get("signals", []):
            if isinstance(signal, dict):
                parts.extend(str(value) for value in signal.values())
            else:
                parts.append(str(signal))
    if repeat_warning:
        parts.append(repeat_warning)
    return " ".join(parts).lower()


def _detect_attack_types(evidence: str, threat_intel: Optional[dict], repeat_count: int) -> list[str]:
    detected = []
    if threat_intel and threat_intel.get("is_known_bad"):
        detected.append("Known-bad URL / malware")
    if _has_any(evidence, ["password", "credential", "security code", "one-time code", "otp", "login", "verify", "confirm identity", "password field"]):
        detected.append("Credential phishing")
    if _has_any(evidence, ["brand keyword appears outside", "impersonat", "official domain", "sender domain does not match", "personal/free email provider", "displayed link text mentions"]):
        detected.append("Brand impersonation phishing")
    if _has_any(evidence, ["typosquat", "lookalike", "homoglyph", "punycode", "repeated letters", "similar to the trusted brand"]):
        detected.append("Typosquatting / lookalike domain")
    if _has_any(evidence, ["http instead of encrypted https", "unencrypted http", "not encrypted"]) and _has_any(evidence, ["password", "login", "account", "payment", "billing", "bank", "credential"]):
        detected.append("Insecure credential collection")
    if _has_any(evidence, ["shortened", "shortener", "real destination", "displayed link text", "redirect", "mismatch", "multiple slashes"]):
        detected.append("Suspicious link redirection")
    if _has_any(evidence, ["clipboard", "copied value", "copy button", "recovery phrase", "seed phrase", "private key", "wallet address", "paste otp", "paste security code"]):
        detected.append("Clipboard manipulation risk")
    if _has_any(evidence, ["urgent", "immediately", "final warning", "suspended", "locked", "account closure", "unusual activity", "act now"]):
        detected.append("Urgency / social engineering pressure")
    if repeat_count > 1 or _has_any(evidence, ["similar message", "repeated", "campaign"]):
        detected.append("Repeated scam/campaign pattern")

    return detected or ["Unknown / low-risk"]


def _choose_primary(detected: list[str]) -> str:
    for attack_type in PRIORITY:
        if attack_type in detected:
            return attack_type
    return "Unknown / low-risk"


def _severity_for(attack_type: str, risk_level: str) -> str:
    if attack_type == "Unknown / low-risk":
        return "low"
    if risk_level == "high" or attack_type in {"Known-bad URL / malware", "Credential phishing"}:
        return "high"
    if risk_level == "medium":
        return "medium"
    return "low"


def _has_any(text: str, needles: list[str]) -> bool:
    return any(needle in text for needle in needles)
