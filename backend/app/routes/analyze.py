from fastapi import APIRouter

from app.models.schemas import (
    AnalyzePageRequest,
    AnalyzePageResponse,
    AnalyzePageSignals,
    AnalyzeUrlRequest,
    AnalyzeUrlResponse,
)
from app.services.explanation_engine import build_explanations
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
            "but page content was analyzed."
        )
        content_points = content_analysis.risk_score
        reasons = [local_development_reason] + content_analysis.reasons

        if not content_analysis.reasons:
            reasons.append("No obvious phishing indicators were found by the MVP checks.")

        return AnalyzePageResponse(
            url=url,
            risk_level=_risk_level_from_points(content_points),
            phishing_probability=round(content_points / 100, 2),
            trust_score=max(100 - content_points, 0),
            reasons=reasons,
            signals=AnalyzePageSignals(
                url_signals=[local_development_reason],
                content_signals=content_analysis.reasons,
            ),
        )

    url_score = score_url_risk(url_features)
    url_reasons = _remove_safe_reasons(build_explanations(url_features))

    combined_points = round(
        (url_score.phishing_probability * 100 * 0.6)
        + (content_analysis.risk_score * 0.4)
    )
    phishing_probability = round(combined_points / 100, 2)
    trust_score = max(100 - combined_points, 0)
    risk_level = _risk_level_from_points(combined_points)

    reasons = url_reasons + content_analysis.reasons
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
