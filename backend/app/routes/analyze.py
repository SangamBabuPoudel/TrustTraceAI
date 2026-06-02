from fastapi import APIRouter

from app.models.schemas import (
    AnalyzeMessageRequest,
    AnalyzeMessageResponse,
    AnalyzeMessageSignals,
    AnalyzePageRequest,
    AnalyzePageResponse,
    AnalyzePageSignals,
    AnalyzeUrlRequest,
    AnalyzeUrlResponse,
    DeepAnalysisSummary,
    DeepSignalSummary,
    ReputationSummary,
    ThreatIntelSummary,
)
from app.services.attack_explanation_service import build_attack_explanation
from app.services.deep_analysis_service import analyze_url_deep
from app.services.explanation_engine import build_explanations
from app.services.form_analyzer import analyze_forms
from app.services.message_analyzer import analyze_message_text
from app.services.message_fingerprint_service import record_message_scan
from app.services.message_link_analyzer import analyze_message_links
from app.services.page_content_analyzer import analyze_page_content
from app.services.risk_scoring_engine import score_url_risk
from app.services.sender_identity_analyzer import analyze_sender_identity
from app.services.reputation_service import ReputationResult, analyze_url_reputation
from app.services.threat_intel_service import get_threat_intel_summary
from app.services.url_feature_extractor import extract_url_features


router = APIRouter()


@router.post("/analyze-url", response_model=AnalyzeUrlResponse)
def analyze_url(payload: AnalyzeUrlRequest) -> AnalyzeUrlResponse:
    url_pipeline = _analyze_url_with_pipeline(str(payload.url))

    return AnalyzeUrlResponse(
        url=str(payload.url),
        risk_level=url_pipeline["risk_level"],
        phishing_probability=url_pipeline["phishing_probability"],
        trust_score=url_pipeline["trust_score"],
        reasons=url_pipeline["reasons"],
        confidence=url_pipeline["confidence"],
        trust_signals=url_pipeline["trust_signals"],
        reputation=url_pipeline["reputation"],
        threat_intel=url_pipeline["threat_intel"],
        deep_analysis=url_pipeline["deep_analysis"],
        attack_explanation=url_pipeline["attack_explanation"],
    )


@router.post("/analyze-page", response_model=AnalyzePageResponse)
def analyze_page(payload: AnalyzePageRequest) -> AnalyzePageResponse:
    url = str(payload.url)
    url_features = extract_url_features(url)
    url_pipeline = _analyze_url_with_pipeline(url)
    trusted_context = (
        url_pipeline["reputation"].is_official_brand_domain
        or url_pipeline["reputation"].is_high_reputation_domain
    )
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
            is_trusted_context=False,
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

        signals = AnalyzePageSignals(
            url_signals=[],
            content_signals=content_analysis.reasons,
            form_signals=form_analysis.reasons,
        )
        attack_explanation = build_attack_explanation(
            reasons=reasons,
            risk_level=_risk_level_from_points(combined_points),
            signals=signals.dict(),
            threat_intel=url_pipeline["threat_intel"].dict(),
            deep_analysis=url_pipeline["deep_analysis"].dict(),
        )

        return AnalyzePageResponse(
            url=url,
            risk_level=_risk_level_from_points(combined_points),
            phishing_probability=round(combined_points / 100, 2),
            trust_score=max(100 - combined_points, 0),
            reasons=reasons,
            signals=signals,
            confidence="high" if combined_points >= 60 else "medium",
            trust_signals=[],
            reputation=_reputation_summary(url_pipeline["raw_reputation"]),
            threat_intel=url_pipeline["threat_intel"],
            deep_analysis=url_pipeline["deep_analysis"],
            attack_explanation=attack_explanation,
        )

    form_analysis = analyze_forms(
        page_url=url,
        forms=payload.forms,
        has_suspicious_url=bool(url_pipeline["reasons"]),
        has_suspicious_content=content_analysis.has_account_verification_language,
        is_trusted_context=trusted_context,
    )
    effective_content_score = content_analysis.risk_score
    effective_content_reasons = content_analysis.reasons
    if trusted_context and not content_analysis.has_account_verification_language:
        effective_content_score = 0
        effective_content_reasons = []

    combined_points = _combine_url_content_and_form_scores(
        url_score=url_pipeline["points"],
        content_score=effective_content_score,
        form_score=form_analysis.risk_score,
        has_password_form=form_analysis.has_password_form,
        has_suspicious_url=bool(url_pipeline["reasons"]),
        has_suspicious_content=content_analysis.has_account_verification_language,
    )
    combined_points = max(combined_points, url_pipeline["points"])
    if url_features.uses_http and content_analysis.has_account_verification_language:
        combined_points = max(combined_points, 45)
    if url_features.uses_http and form_analysis.has_password_form:
        combined_points = max(combined_points, 85)
        if not any("unencrypted HTTP page" in reason for reason in form_analysis.reasons):
            form_analysis.reasons.append(
                "Password or credential entry was detected on an unencrypted HTTP page."
            )
    if trusted_context and form_analysis.risk_score == 0 and effective_content_score == 0:
        combined_points = min(combined_points, 5)

    reasons = url_pipeline["reasons"] + effective_content_reasons + form_analysis.reasons
    if not reasons:
        reasons = ["No obvious phishing indicators were found by the MVP checks."]

    signals = AnalyzePageSignals(
        url_signals=url_pipeline["reasons"],
        content_signals=effective_content_reasons,
        form_signals=form_analysis.reasons,
    )
    risk_level = _risk_level_from_points(combined_points)
    attack_explanation = build_attack_explanation(
        reasons=reasons,
        risk_level=risk_level,
        signals=signals.dict(),
        threat_intel=url_pipeline["threat_intel"].dict(),
        deep_analysis=url_pipeline["deep_analysis"].dict(),
    )

    return AnalyzePageResponse(
        url=url,
        risk_level=risk_level,
        phishing_probability=round(combined_points / 100, 2),
        trust_score=max(100 - combined_points, 0),
        reasons=reasons,
        signals=signals,
        confidence=url_pipeline["confidence"],
        trust_signals=url_pipeline["trust_signals"],
        reputation=url_pipeline["reputation"],
        threat_intel=url_pipeline["threat_intel"],
        deep_analysis=url_pipeline["deep_analysis"],
        attack_explanation=attack_explanation,
    )


@router.post("/analyze-message", response_model=AnalyzeMessageResponse)
def analyze_message(payload: AnalyzeMessageRequest) -> AnalyzeMessageResponse:
    message_analysis = analyze_message_text(
        subject=payload.subject,
        message_text=payload.message_text,
    )
    link_analysis = analyze_message_links(
        links=payload.links,
        mentioned_brands=message_analysis.mentioned_brands,
    )
    sender_analysis = analyze_sender_identity(
        sender=payload.sender,
        sender_type=payload.sender_type,
        mentioned_brands=message_analysis.mentioned_brands,
        has_company_or_security_claim=message_analysis.has_company_or_security_claim,
        has_urgent_credential_request=message_analysis.has_urgent_credential_request,
        has_suspicious_links=bool(link_analysis.reasons),
    )

    preliminary_points = _combine_message_scores(
        message_score=message_analysis.risk_score,
        sender_score=sender_analysis.risk_score,
        link_score=link_analysis.risk_score,
        repeat_score=0,
    )
    repeat_result = record_message_scan(
        sender=payload.sender,
        subject=payload.subject,
        source_url=payload.source_url,
        message_text=payload.message_text,
        links=payload.links,
        risk_level=_risk_level_from_points(preliminary_points),
        phishing_probability=round(preliminary_points / 100, 2),
    )
    repeat_score = 20 if repeat_result.repeat_count > 1 else 0
    combined_points = _combine_message_scores(
        message_score=message_analysis.risk_score,
        sender_score=sender_analysis.risk_score,
        link_score=link_analysis.risk_score,
        repeat_score=repeat_score,
    )

    if sender_analysis.risk_score >= 30 and message_analysis.has_urgent_credential_request:
        combined_points += 15
    if link_analysis.risk_score >= 35 and sender_analysis.risk_score >= 30:
        combined_points += 15
    if repeat_score and message_analysis.risk_score >= 30:
        combined_points += 10

    combined_points = min(combined_points, 100)
    reasons = (
        sender_analysis.reasons
        + message_analysis.reasons
        + link_analysis.reasons
        + repeat_result.repeat_signals
    )
    if not reasons:
        reasons = ["No obvious phishing indicators were found by the MVP message checks."]

    signals = AnalyzeMessageSignals(
        sender_signals=sender_analysis.reasons,
        message_signals=message_analysis.reasons,
        link_signals=link_analysis.reasons,
        repeat_signals=repeat_result.repeat_signals,
    )
    risk_level = _risk_level_from_points(combined_points)
    attack_explanation = build_attack_explanation(
        reasons=reasons,
        risk_level=risk_level,
        signals=signals.dict(),
        repeat_count=repeat_result.repeat_count,
        repeat_warning=repeat_result.repeat_warning,
    )

    return AnalyzeMessageResponse(
        risk_level=risk_level,
        phishing_probability=round(combined_points / 100, 2),
        trust_score=max(100 - combined_points, 0),
        reasons=reasons,
        signals=signals,
        repeat_count=repeat_result.repeat_count,
        repeat_warning=repeat_result.repeat_warning,
        attack_explanation=attack_explanation,
    )


def _analyze_url_with_pipeline(url: str) -> dict:
    features = extract_url_features(url)
    reputation = analyze_url_reputation(url)
    threat_intel = get_threat_intel_summary(url)
    deep_analysis = analyze_url_deep(url, reputation)
    known_bad = threat_intel["is_known_bad"]

    if features.is_local_development:
        attack_explanation = build_attack_explanation(
            reasons=["Local development URL detected; phishing risk scoring skipped."],
            risk_level="low",
            threat_intel=_threat_intel_summary(threat_intel).dict(),
            deep_analysis=DeepAnalysisSummary().dict(),
        )
        return {
            "points": 0,
            "risk_level": "low",
            "phishing_probability": 0.0,
            "trust_score": 100,
            "reasons": ["Local development URL detected; phishing risk scoring skipped."],
            "confidence": "high",
            "trust_signals": [],
            "reputation": _reputation_summary(reputation),
            "raw_reputation": reputation,
            "threat_intel": _threat_intel_summary(threat_intel),
            "deep_analysis": DeepAnalysisSummary(),
            "attack_explanation": attack_explanation,
        }

    base_score = score_url_risk(features)
    points = round(base_score.phishing_probability * 100)
    reasons = _remove_safe_reasons(build_explanations(features))
    trust_signals = list(reputation.trust_signals)

    if known_bad:
        points = 100
        reasons.insert(0, threat_intel["reason"])
    else:
        reasons.extend(deep_analysis.reasons)
        points = max(points, deep_analysis.risk_score)

        has_fake_brand = bool(reputation.reputation_warnings)
        has_credential_context = bool(
            set(features.suspicious_keywords)
            & {
                "login",
                "signin",
                "signup",
                "sign-in",
                "sign-up",
                "verify",
                "account",
                "secure",
                "update",
                "password",
                "payment",
                "billing",
                "bank",
            }
        )
        if features.uses_http:
            points = max(points, 25)
        if features.uses_http and has_credential_context:
            points = max(points, 45)
        if has_fake_brand and has_credential_context:
            points = max(points, 85)
        elif has_fake_brand:
            points = max(points, 60)
        if features.suspicious_tld and has_credential_context:
            points = max(points, 70)

        trusted_domain = reputation.is_official_brand_domain or reputation.is_high_reputation_domain
        strong_url_evidence = any(
            [
                features.has_at_symbol,
                features.has_ip_address,
                features.suspicious_tld,
                bool(reputation.reputation_warnings),
            ]
        )
        if trusted_domain and not strong_url_evidence:
            weak_reasons = [
                reason
                for reason in reasons
                if "HTTP instead of" in reason or "IP address" in reason or "@" in reason
            ]
            reasons = weak_reasons
            points = min(points, 5 if features.scheme == "https" else 20)

    points = min(points, 100)
    trusted_domain = reputation.is_official_brand_domain or reputation.is_high_reputation_domain
    if points <= 5 and trust_signals and trusted_domain:
        reasons = []
    elif not reasons and points > 0:
        reasons = ["Multiple weak URL signals were found."]

    threat_intel_summary = _threat_intel_summary(threat_intel)
    deep_analysis_summary = _deep_analysis_summary(deep_analysis)
    risk_level = _risk_level_from_points(points)
    attack_explanation = build_attack_explanation(
        reasons=reasons,
        risk_level=risk_level,
        threat_intel=threat_intel_summary.dict(),
        deep_analysis=deep_analysis_summary.dict(),
    )

    return {
        "points": points,
        "risk_level": risk_level,
        "phishing_probability": round(points / 100, 2),
        "trust_score": max(100 - points, 0),
        "reasons": reasons,
        "confidence": _confidence_for_url(points, reputation, known_bad),
        "trust_signals": trust_signals,
        "reputation": _reputation_summary(reputation),
        "raw_reputation": reputation,
        "threat_intel": threat_intel_summary,
        "deep_analysis": deep_analysis_summary,
        "attack_explanation": attack_explanation,
    }


def _reputation_summary(reputation: ReputationResult) -> ReputationSummary:
    return ReputationSummary(
        is_official_brand_domain=reputation.is_official_brand_domain,
        is_high_reputation_domain=reputation.is_high_reputation_domain,
        matched_brand=reputation.matched_brand,
        reputation_score=reputation.reputation_score,
    )


def _threat_intel_summary(threat_intel: dict) -> ThreatIntelSummary:
    return ThreatIntelSummary(
        is_known_bad=threat_intel.get("is_known_bad", False),
        source=threat_intel.get("source", ""),
        reason=threat_intel.get("reason", ""),
    )


def _deep_analysis_summary(deep_analysis) -> DeepAnalysisSummary:
    return DeepAnalysisSummary(
        signals=[
            DeepSignalSummary(
                type=signal.type,
                severity=signal.severity,
                message=signal.message,
            )
            for signal in deep_analysis.deep_signals
        ],
        score_delta=deep_analysis.deep_score_delta,
    )


def _confidence_for_url(points: int, reputation: ReputationResult, known_bad: bool) -> str:
    if known_bad or points >= 70 or reputation.is_official_brand_domain or reputation.is_high_reputation_domain:
        return "high"
    if points >= 30:
        return "medium"
    return "low"


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


def _combine_message_scores(
    message_score: int,
    sender_score: int,
    link_score: int,
    repeat_score: int,
) -> int:
    return min(
        round(
            (message_score * 0.35)
            + (sender_score * 0.25)
            + (link_score * 0.30)
            + (repeat_score * 0.10)
        ),
        100,
    )
