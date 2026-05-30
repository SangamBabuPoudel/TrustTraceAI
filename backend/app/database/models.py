from dataclasses import dataclass


@dataclass(frozen=True)
class MessageScanRecord:
    message_hash: str
    sender: str
    subject: str
    source_url: str
    normalized_preview: str
    risk_level: str
    phishing_probability: float
    scan_count: int
