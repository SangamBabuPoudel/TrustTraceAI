from typing import Literal, Optional

from pydantic import AnyHttpUrl, BaseModel, Field


class AnalyzeUrlRequest(BaseModel):
    url: AnyHttpUrl


class ReputationSummary(BaseModel):
    is_official_brand_domain: bool = False
    is_high_reputation_domain: bool = False
    matched_brand: str = ""
    reputation_score: int = Field(default=0, ge=0, le=100)


class ThreatIntelSummary(BaseModel):
    is_known_bad: bool = False
    source: str = ""
    reason: str = ""


class DeepSignalSummary(BaseModel):
    type: str
    severity: str
    message: str


class DeepAnalysisSummary(BaseModel):
    signals: list[DeepSignalSummary] = Field(default_factory=list)
    score_delta: int = 0


class AttackExplanationSummary(BaseModel):
    attack_type: str = "Unknown / low-risk"
    attack_category: str = "No strong pattern"
    severity: Literal["low", "medium", "high"] = "low"
    summary: str = "No strong attack pattern was identified from the current checks."
    how_it_works: list[str] = Field(default_factory=list)
    what_to_avoid: list[str] = Field(default_factory=list)
    safer_action: str = ""
    secondary_attack_types: list[str] = Field(default_factory=list)


class VisualFaviconMetadata(BaseModel):
    href: str = ""
    type: str = ""
    rel: str = ""


class VisualImageMetadata(BaseModel):
    src: str = ""
    alt: str = ""
    title: str = ""
    class_name: str = ""
    id: str = ""
    width: int = 0
    height: int = 0
    nearby_text: str = ""


class VisualLayoutHints(BaseModel):
    has_centered_login_card: bool = False
    has_fullscreen_login_layout: bool = False
    has_minimal_login_page: bool = False


class VisualMetadata(BaseModel):
    document_title: str = ""
    primary_headings: list[str] = Field(default_factory=list)
    favicons: list[VisualFaviconMetadata] = Field(default_factory=list)
    images: list[VisualImageMetadata] = Field(default_factory=list)
    logo_candidates: list[VisualImageMetadata] = Field(default_factory=list)
    button_texts: list[str] = Field(default_factory=list)
    input_labels: list[str] = Field(default_factory=list)
    brand_like_text: list[str] = Field(default_factory=list)
    color_hints: list[str] = Field(default_factory=list)
    layout_hints: VisualLayoutHints = Field(default_factory=VisualLayoutHints)


class VisualCloneSignalSummary(BaseModel):
    type: str
    severity: Literal["low", "medium", "high"]
    brand: str
    message: str


class VisualCloneSummary(BaseModel):
    is_visual_clone_suspected: bool = False
    visual_clone_score: int = Field(default=0, ge=0, le=100)
    visual_clone_confidence: Literal["low", "medium", "high"] = "low"
    primary_clone_brand: Optional[str] = None
    claimed_brands: list[str] = Field(default_factory=list)
    signals: list[VisualCloneSignalSummary] = Field(default_factory=list)


class AnalyzeUrlResponse(BaseModel):
    url: str
    risk_level: Literal["low", "medium", "high"]
    phishing_probability: float = Field(ge=0.0, le=1.0)
    trust_score: int = Field(ge=0, le=100)
    reasons: list[str]
    confidence: Literal["low", "medium", "high"] = "medium"
    trust_signals: list[str] = Field(default_factory=list)
    reputation: ReputationSummary = Field(default_factory=ReputationSummary)
    threat_intel: ThreatIntelSummary = Field(default_factory=ThreatIntelSummary)
    deep_analysis: DeepAnalysisSummary = Field(default_factory=DeepAnalysisSummary)
    attack_explanation: AttackExplanationSummary = Field(default_factory=AttackExplanationSummary)


class PageFormMetadata(BaseModel):
    action: str = ""
    method: str = "get"
    has_password_field: bool = False
    has_email_or_username_field: bool = False
    input_count: int = 0
    hidden_input_count: int = 0
    submit_text: str = ""


class AnalyzePageRequest(BaseModel):
    url: AnyHttpUrl
    page_title: str = ""
    visible_text: str = ""
    forms: list[PageFormMetadata] = Field(default_factory=list)
    visual_metadata: VisualMetadata = Field(default_factory=VisualMetadata)


class AnalyzePageSignals(BaseModel):
    url_signals: list[str] = Field(default_factory=list)
    content_signals: list[str] = Field(default_factory=list)
    form_signals: list[str] = Field(default_factory=list)
    clipboard_signals: list[str] = Field(default_factory=list)
    visual_clone_signals: list[str] = Field(default_factory=list)


class AnalyzePageResponse(BaseModel):
    url: str
    risk_level: Literal["low", "medium", "high"]
    phishing_probability: float = Field(ge=0.0, le=1.0)
    trust_score: int = Field(ge=0, le=100)
    reasons: list[str]
    signals: AnalyzePageSignals
    confidence: Literal["low", "medium", "high"] = "medium"
    trust_signals: list[str] = Field(default_factory=list)
    reputation: ReputationSummary = Field(default_factory=ReputationSummary)
    threat_intel: ThreatIntelSummary = Field(default_factory=ThreatIntelSummary)
    deep_analysis: DeepAnalysisSummary = Field(default_factory=DeepAnalysisSummary)
    attack_explanation: AttackExplanationSummary = Field(default_factory=AttackExplanationSummary)
    visual_clone: VisualCloneSummary = Field(default_factory=VisualCloneSummary)


class MessageLink(BaseModel):
    text: str = ""
    href: str = ""


class AnalyzeMessageRequest(BaseModel):
    source_url: str = ""
    subject: str = ""
    sender: str = ""
    sender_type: Literal["email", "phone", "unknown"] = "unknown"
    message_text: str = ""
    links: list[MessageLink] = Field(default_factory=list)


class AnalyzeMessageSignals(BaseModel):
    sender_signals: list[str]
    message_signals: list[str]
    link_signals: list[str]
    repeat_signals: list[str]


class AnalyzeMessageResponse(BaseModel):
    risk_level: Literal["low", "medium", "high"]
    phishing_probability: float = Field(ge=0.0, le=1.0)
    trust_score: int = Field(ge=0, le=100)
    reasons: list[str]
    signals: AnalyzeMessageSignals
    repeat_count: int
    repeat_warning: Optional[str] = None
    attack_explanation: AttackExplanationSummary = Field(default_factory=AttackExplanationSummary)
