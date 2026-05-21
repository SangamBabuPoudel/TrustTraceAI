from fastapi import APIRouter

from app.models.schemas import AnalyzeUrlRequest, AnalyzeUrlResponse
from app.services.explanation_engine import build_explanations
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
