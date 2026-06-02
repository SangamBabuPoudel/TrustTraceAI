# Privacy Design

TrustTrace AI is designed around minimal collection, local analysis, and user-controlled scans.

## Principles

- Local-first: the extension calls a backend running on the user's machine.
- Minimal data: each workflow sends only the data needed for that analysis.
- User control: message scanning happens only when the user clicks Scan Email/Message.
- No hidden mailbox scanning: TrustTrace AI does not connect to Gmail, Outlook, or other provider APIs.
- No external threat APIs in the MVP: current threat intelligence integrations are placeholders.
- No external AI model in the MVP: Attack Explanation Mode is rule-based and local.

## What Is Collected

| Workflow | Data used |
|---|---|
| URL scan | Current URL. |
| Pre-visit warning | Destination URL only. |
| Page scan | URL, visible text, page title, form metadata. |
| Link scan | Visible link URLs, link text, hostname, lightweight surrounding context. |
| Search annotation | Visible result URLs only. |
| Message scan | Selected or visible message text, optional sender input, visible links. |
| Repeated message detection | Hash and short metadata, not full message body. |

## What Is Not Collected

- Passwords.
- Cookies.
- Hidden form values.
- Full mailbox data.
- Background email content.
- Browser history.
- Search query text for annotation.
- API keys in frontend code.

## Repeated Message Storage

Repeated scam/campaign detection uses local SQLite storage at `backend/trusttrace.db`.

Stored:

- SHA-256 message hash.
- Sender.
- Subject.
- Source URL.
- Short normalized preview.
- Risk level.
- Phishing probability.
- First/last seen timestamps.
- Scan count.

Not stored:

- Full message bodies.
- Passwords.
- Cookies.
- Private mailbox data.

## Pre-Visit Protection

Pre-visit protection sends only the destination URL to the local backend. Page content is not collected before navigation. If a URL is high risk, the extension shows `warning.html`. If the user clicks Proceed Anyway, the exact URL is allowed for the current browser session only.

## External Integrations

Future integrations such as Google Safe Browsing, PhishTank, URLHaus, RDAP, Tranco, URLScan, and ML classifiers should remain optional, backend-only, clearly documented, and privacy reviewed before use.
