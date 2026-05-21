from typing import Literal

from pydantic import AnyHttpUrl, BaseModel, Field


class AnalyzeUrlRequest(BaseModel):
    url: AnyHttpUrl


class AnalyzeUrlResponse(BaseModel):
    url: str
    risk_level: Literal["low", "medium", "high"]
    phishing_probability: float = Field(ge=0.0, le=1.0)
    trust_score: int = Field(ge=0, le=100)
    reasons: list[str]


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


class AnalyzePageSignals(BaseModel):
    url_signals: list[str]
    content_signals: list[str]
    form_signals: list[str]


class AnalyzePageResponse(BaseModel):
    url: str
    risk_level: Literal["low", "medium", "high"]
    phishing_probability: float = Field(ge=0.0, le=1.0)
    trust_score: int = Field(ge=0, le=100)
    reasons: list[str]
    signals: AnalyzePageSignals
