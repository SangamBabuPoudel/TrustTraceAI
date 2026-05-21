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
