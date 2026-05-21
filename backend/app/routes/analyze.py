from fastapi import APIRouter

from app.models.schemas import (
    AnalyzePageRequest,
    AnalyzePageResponse,
    AnalyzePageSignals,
    AnalyzeUrlRequest,
    AnalyzeUrlResponse,
)
from app.services.explanation_engine import build_explanations
from app.services.form_analyzer import analyze_forms
from app.services.page_content_analyzer import analyze_page_content
from app.services.risk_scoring_engine import score_url_risk
from app.services.url_feature_extractor import extract_url_features


router = APIRouter()


@router.post("/analyze-url", response_model=AnalyzeUrlResponse)
def analyze_url(payload: AnalyzeUrlRequest) -> AnalyzeUrlResponse:
    features = extract_url_features(str(payload.url))
    score = score_url_risk(features)
    reasons = build_explanations(features)

    return AnalyzeUrlResponse(
        url=str(payload.url),
        risk_level=score.risk_level,
        phishing_probability=score.phishing_probability,
        trust_score=score.trust_score,
        reasons=reasons,
    )


@router.post("/analyze-page", response_model=AnalyzePageResponse)
def analyze_page(payload: AnalyzePageRequest) -> AnalyzePageResponse:
    url = str(payload.url)
    url_features = extract_url_features(url)
    content_analysis = analyze_page_content(
        page_title=payload.page_title,
        visible_text=payload.visible_text,
    )

    if url_features.is_local_development:
        local_development_reason = (
            "Local development URL detected; URL risk scoring skipped, "
            "but page content and forms were analyzed."
        )
        form_analysis = analyze_forms(
            page_url=url,
            forms=payload.forms,
            has_suspicious_url=False,
            has_suspicious_content=content_analysis.has_account_verification_language,
        )
        combined_points = _combine_local_content_and_form_scores(
            content_score=content_analysis.risk_score,
            form_score=form_analysis.risk_score,
            has_password_form=form_analysis.has_password_form,
            has_suspicious_content=content_analysis.has_account_verification_language,
        )
        reasons = (
            [local_development_reason]
            + content_analysis.reasons
            + form_analysis.reasons
        )

        if not content_analysis.reasons and not form_analysis.reasons:
            reasons.append("No obvious phishing indicators were found by the MVP checks.")

        return AnalyzePageResponse(
            url=url,
            risk_level=_risk_level_from_points(combined_points),
            phishing_probability=round(combined_points / 100, 2),
            trust_score=max(100 - combined_points, 0),
            reasons=reasons,
            signals=AnalyzePageSignals(
                url_signals=[],
                content_signals=content_analysis.reasons,
                form_signals=form_analysis.reasons,
            ),
        )

    url_score = score_url_risk(url_features)
    url_reasons = _remove_safe_reasons(build_explanations(url_features))
    form_analysis = analyze_forms(
        page_url=url,
        forms=payload.forms,
        has_suspicious_url=bool(url_reasons),
        has_suspicious_content=content_analysis.has_account_verification_language,
    )

    combined_points = _combine_url_content_and_form_scores(
        url_score=url_score.phishing_probability * 100,
        content_score=content_analysis.risk_score,
        form_score=form_analysis.risk_score,
        has_password_form=form_analysis.has_password_form,
        has_suspicious_url=bool(url_reasons),
        has_suspicious_content=content_analysis.has_account_verification_language,
    )
    phishing_probability = round(combined_points / 100, 2)
    trust_score = max(100 - combined_points, 0)
    risk_level = _risk_level_from_points(combined_points)

    reasons = url_reasons + content_analysis.reasons + form_analysis.reasons
    if not reasons:
        reasons = ["No obvious phishing indicators were found by the MVP checks."]

    return AnalyzePageResponse(
        url=url,
        risk_level=risk_level,
        phishing_probability=phishing_probability,
        trust_score=trust_score,
        reasons=reasons,
        signals=AnalyzePageSignals(
            url_signals=url_reasons,
            content_signals=content_analysis.reasons,
            form_signals=form_analysis.reasons,
        ),
    )


def _risk_level_from_points(points: int) -> str:
    if points >= 60:
        return "high"
    if points >= 30:
        return "medium"
    return "low"


def _remove_safe_reasons(reasons: list[str]) -> list[str]:
    return [
        reason
        for reason in reasons
        if not reason.startswith("No obvious phishing indicators")
    ]


def _combine_url_content_and_form_scores(
    url_score: float,
    content_score: int,
    form_score: int,
    has_password_form: bool,
    has_suspicious_url: bool,
    has_suspicious_content: bool,
) -> int:
    combined_points = round(
        (url_score * 0.45)
        + (content_score * 0.30)
        + (form_score * 0.25)
    )
    return _add_password_form_bonus(
        combined_points=combined_points,
        has_password_form=has_password_form,
        has_suspicious_url=has_suspicious_url,
        has_suspicious_content=has_suspicious_content,
    )


def _combine_local_content_and_form_scores(
    content_score: int,
    form_score: int,
    has_password_form: bool,
    has_suspicious_content: bool,
) -> int:
    combined_points = max(
        content_score,
        form_score,
        round((content_score * 0.50) + (form_score * 0.50)),
    )
    return _add_password_form_bonus(
        combined_points=combined_points,
        has_password_form=has_password_form,
        has_suspicious_url=False,
        has_suspicious_content=has_suspicious_content,
    )


def _add_password_form_bonus(
    combined_points: int,
    has_password_form: bool,
    has_suspicious_url: bool,
    has_suspicious_content: bool,
) -> int:
    if has_password_form and (has_suspicious_url or has_suspicious_content):
        combined_points += 20

    return min(combined_points, 100)
