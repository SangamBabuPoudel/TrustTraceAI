# API Design

## Health Check

`GET /health`

Response:

```json
{
  "status": "ok"
}
```

## Analyze URL

`POST /api/analyze-url`

Request:

```json
{
  "url": "https://example.com"
}
```

Response:

```json
{
  "url": "https://example.com",
  "risk_level": "low",
  "phishing_probability": 0.0,
  "trust_score": 100,
  "reasons": []
}
```

### Risk Levels

- `low`: few or no suspicious rule-based indicators.
- `medium`: several warning signs are present.
- `high`: strong phishing indicators are present.

### MVP Detection Signals

- HTTP instead of HTTPS.
- Long URL length.
- Suspicious keywords such as `login`, `verify`, `account`, `secure`, `update`, `bank`, `password`, and `refund`.
- IP address in the URL hostname.
- Excessive hyphens in the hostname.
- Too many subdomains.
- `@` symbol in the URL.
