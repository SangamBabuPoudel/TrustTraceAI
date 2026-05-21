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

### Local Development URLs

During MVP testing, local development hosts are treated as safe development URLs and skip phishing risk scoring. This includes `localhost`, `127.0.0.1`, `0.0.0.0`, and `::1`.

Example response:

```json
{
  "url": "http://127.0.0.1:8000/health",
  "risk_level": "low",
  "phishing_probability": 0.0,
  "trust_score": 100,
  "reasons": ["Local development URL detected; phishing risk scoring skipped."]
}
```
