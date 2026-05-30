from dataclasses import dataclass
from typing import Protocol
from urllib.parse import urljoin, urlparse


SUSPICIOUS_SUBMIT_WORDS = {
    "verify",
    "confirm",
    "update",
    "unlock",
    "secure",
    "continue",
}


class FormMetadata(Protocol):
    action: str
    method: str
    has_password_field: bool
    has_email_or_username_field: bool
    input_count: int
    hidden_input_count: int
    submit_text: str


@dataclass(frozen=True)
class FormAnalysis:
    risk_score: int
    reasons: list[str]
    signals: list[str]
    has_password_form: bool


def analyze_forms(
    page_url: str,
    forms: list[FormMetadata],
    has_suspicious_url: bool,
    has_suspicious_content: bool,
    is_trusted_context: bool = False,
) -> FormAnalysis:
    reasons: list[str] = []
    signals: list[str] = []
    risk_score = 0
    has_password_form = any(form.has_password_field for form in forms)

    for index, form in enumerate(forms, start=1):
        form_label = f"Form {index}"

        if form.has_password_field and not is_trusted_context:
            risk_score += 30
            signals.append("password_field_present")
            reasons.append(f"{form_label}: A password field was detected.")

        if form.has_email_or_username_field and not is_trusted_context:
            risk_score += 10
            signals.append("email_or_username_field_present")
            reasons.append(f"{form_label}: An email or username field was detected.")

        if form.has_email_or_username_field and form.has_password_field and not is_trusted_context:
            risk_score += 30
            signals.append("email_password_login_combo")
            reasons.append(
                f"{form_label}: The form asks for both an email or username and a password."
            )

        if _has_missing_action(form) and not is_trusted_context:
            risk_score += 15
            signals.append("missing_form_action")
            reasons.append(
                f"{form_label}: The form action is missing, which can make destination behavior unclear."
            )
        elif _submits_to_different_domain(page_url, form.action):
            risk_score += 25
            signals.append("different_domain_form_action")
            reasons.append(
                f"{form_label}: The login form submits data to a different domain than the current page."
            )

        if not _has_missing_action(form) and _uses_http_action(page_url, form.action):
            risk_score += 20
            signals.append("http_form_action")
            reasons.append(
                f"{form_label}: The form submits over HTTP instead of encrypted HTTPS."
            )

        suspicious_submit_words = _find_suspicious_submit_words(form.submit_text)
        if suspicious_submit_words and (not is_trusted_context or has_suspicious_content or has_suspicious_url):
            risk_score += 20
            signals.append("suspicious_submit_text")
            matched_words = ", ".join(suspicious_submit_words)
            reasons.append(
                f"{form_label}: The submit button uses suspicious action word(s): {matched_words}."
            )

        if form.hidden_input_count > 0 and not is_trusted_context:
            risk_score += 5
            signals.append("hidden_inputs_present")
            reasons.append(
                f"{form_label}: The form contains {form.hidden_input_count} hidden input(s)."
            )

        if form.has_password_field and has_suspicious_content:
            risk_score += 45
            signals.append("password_form_with_suspicious_content")
            reasons.append(
                f"{form_label}: A password field was detected on a page with suspicious account-verification or security-alert language."
            )

        if form.has_password_field and has_suspicious_url:
            risk_score += 30
            signals.append("password_form_on_suspicious_url")
            reasons.append(
                f"{form_label}: A password field appears on a URL with suspicious phishing indicators."
            )

    return FormAnalysis(
        risk_score=min(risk_score, 100),
        reasons=reasons,
        signals=signals,
        has_password_form=has_password_form,
    )


def _has_missing_action(form: FormMetadata) -> bool:
    return not form.action.strip()


def _submits_to_different_domain(page_url: str, action: str) -> bool:
    resolved_action = urljoin(page_url, action)
    page_hostname = urlparse(page_url).hostname or ""
    action_hostname = urlparse(resolved_action).hostname or ""
    return bool(action_hostname and page_hostname and action_hostname != page_hostname)


def _uses_http_action(page_url: str, action: str) -> bool:
    resolved_action = urljoin(page_url, action)
    return urlparse(resolved_action).scheme == "http"


def _find_suspicious_submit_words(submit_text: str) -> list[str]:
    normalized_text = submit_text.lower()
    return sorted(word for word in SUSPICIOUS_SUBMIT_WORDS if word in normalized_text)
