import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional, Protocol

from app.database.db import get_connection, initialize_database


class MessageLinkMetadata(Protocol):
    href: str


@dataclass(frozen=True)
class MessageFingerprintResult:
    message_hash: str
    repeat_count: int
    repeat_warning: Optional[str]
    repeat_signals: list[str]


def record_message_scan(
    sender: str,
    subject: str,
    source_url: str,
    message_text: str,
    links: list[MessageLinkMetadata],
    risk_level: str,
    phishing_probability: float,
) -> MessageFingerprintResult:
    initialize_database()
    normalized_message = normalize_message_text(message_text)
    link_hrefs = " ".join(sorted(link.href for link in links if link.href))
    message_hash = hashlib.sha256(
        f"{normalized_message}|{sender.strip().lower()}|{subject.strip().lower()}|{link_hrefs}".encode("utf-8")
    ).hexdigest()
    now = datetime.now(timezone.utc).isoformat()
    preview = normalized_message[:180]

    with get_connection() as connection:
        existing = connection.execute(
            "SELECT scan_count FROM message_scans WHERE message_hash = ?",
            (message_hash,),
        ).fetchone()

        if existing:
            repeat_count = int(existing["scan_count"]) + 1
            connection.execute(
                """
                UPDATE message_scans
                SET last_seen_at = ?, scan_count = ?, risk_level = ?, phishing_probability = ?
                WHERE message_hash = ?
                """,
                (now, repeat_count, risk_level, phishing_probability, message_hash),
            )
        else:
            repeat_count = 1
            connection.execute(
                """
                INSERT INTO message_scans (
                    message_hash, sender, subject, source_url, normalized_preview,
                    risk_level, phishing_probability, first_seen_at, last_seen_at, scan_count
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    message_hash,
                    sender,
                    subject,
                    source_url,
                    preview,
                    risk_level,
                    phishing_probability,
                    now,
                    now,
                    repeat_count,
                ),
            )

    repeat_warning = None
    repeat_signals: list[str] = []
    if repeat_count > 1:
        repeat_warning = (
            f"A similar message has been scanned {repeat_count} times on this device. "
            "Repeated urgent messages can indicate a phishing campaign."
        )
        repeat_signals.append(repeat_warning)

    return MessageFingerprintResult(
        message_hash=message_hash,
        repeat_count=repeat_count,
        repeat_warning=repeat_warning,
        repeat_signals=repeat_signals,
    )


def normalize_message_text(message_text: str) -> str:
    return " ".join(message_text.lower().strip().split())
