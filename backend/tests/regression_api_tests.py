#!/usr/bin/env python3
"""Simple TrustTrace AI API regression checks.

Run while the FastAPI backend is available at http://127.0.0.1:8000:

    python3 backend/tests/regression_api_tests.py
"""

from typing import Callable

import requests


API_BASE_URL = "http://127.0.0.1:8000"
ANALYZE_URL_ENDPOINT = f"{API_BASE_URL}/api/analyze-url"


OFFICIAL_SAFE_CASES = [
    "https://www.apple.com",
    "https://support.apple.com/en-us/111001?device-type=mac",
    "https://openai.com",
    "https://chatgpt.com",
    "https://claude.ai",
    "https://gemini.google.com",
    "https://www.usf.edu",
    "https://my.usf.edu",
    "https://login.microsoftonline.com",
    "https://login.live.com",
    "https://www.microsoft.com",
    "https://office.com",
    "https://github.com",
    "https://github.com/login",
    "https://github.com/apps/desktop",
    "https://github.com/desktop/desktop",
    "https://docs.github.com",
    "https://www.verizon.com/shop/online/free-cell-phones/apple/",
]

FAKE_RISKY_CASES = [
    "http://apple-login-security.example.com/verify",
    "https://openai-login-verify.example.com/password",
    "https://claude-security-login.example.com",
    "https://gemini-google-verify-account.xyz/login",
    "https://gooogle-login.example.com",
    "http://github-login-security.example.com/verify",
    "https://githhub-login.example.com",
    "https://github-security-verify.xyz/login",
    "http://microsoft-login-security.example.com/verify",
    "https://usf-login-security.example.com/login",
    "https://usf.edu.login.example.com",
    "https://microsoft-authenticator-verify.xyz/login",
]


def main() -> int:
    print("TrustTrace AI API Regression Tests")
    print("=" * 38)

    if not backend_is_available():
        print("FAIL backend is unavailable at http://127.0.0.1:8000")
        print("Start it with: cd backend && python3 -m uvicorn app.main:app --reload")
        return 1

    results = []
    for url in OFFICIAL_SAFE_CASES:
        results.append(run_case(url, expect_official_safe))

    for url in FAKE_RISKY_CASES:
        results.append(run_case(url, expect_fake_risky))

    passed = sum(1 for result in results if result)
    total = len(results)
    print("=" * 38)
    print(f"Summary: {passed}/{total} passed")

    return 0 if passed == total else 1


def backend_is_available() -> bool:
    try:
        response = requests.get(f"{API_BASE_URL}/health", timeout=5)
        return response.status_code == 200
    except requests.RequestException:
        return False


def run_case(url: str, expectation: Callable[[dict], tuple[bool, list[str]]]) -> bool:
    try:
        response = requests.post(
            ANALYZE_URL_ENDPOINT,
            json={"url": url},
            timeout=10,
        )
        response.raise_for_status()
        result = response.json()
    except requests.RequestException as error:
        print_case_report(
            passed=False,
            url=url,
            result={},
            failures=[f"Request failed: {error}"],
        )
        return False

    passed, failures = expectation(result)
    print_case_report(passed=passed, url=url, result=result, failures=failures)
    return passed


def expect_official_safe(result: dict) -> tuple[bool, list[str]]:
    failures = []
    reasons_text = " ".join(result.get("reasons", [])).lower()

    if result.get("risk_level") != "low":
        failures.append("Expected risk_level low.")
    if int(result.get("trust_score", 0)) < 80:
        failures.append("Expected trust_score >= 80.")
    if float(result.get("phishing_probability", 1.0)) > 0.25:
        failures.append("Expected phishing_probability <= 0.25.")
    if "visual clone" in reasons_text:
        failures.append("Unexpected visual clone reason.")
    if "impersonation" in reasons_text or "outside the official" in reasons_text:
        failures.append("Unexpected brand impersonation warning.")

    return len(failures) == 0, failures


def expect_fake_risky(result: dict) -> tuple[bool, list[str]]:
    failures = []
    risk_level = result.get("risk_level")
    trust_score = int(result.get("trust_score", 100))
    reasons_text = " ".join(result.get("reasons", [])).lower()
    attack_type = result.get("attack_explanation", {}).get("attack_type", "").lower()
    evidence_text = f"{reasons_text} {attack_type}"

    if risk_level not in {"medium", "high"}:
        failures.append("Expected risk_level medium or high.")
    if trust_score >= 80:
        failures.append("Expected trust_score lower than official safe sites.")
    if not has_risky_brand_evidence(evidence_text):
        failures.append("Expected fake brand/lookalike/impersonation evidence.")

    return len(failures) == 0, failures


def has_risky_brand_evidence(text: str) -> bool:
    indicators = [
        "known-bad",
        "blocklist",
        "brand",
        "impersonation",
        "lookalike",
        "typosquat",
        "similar to the trusted brand",
        "security/login",
        "credential phishing",
        "visual brand cloning",
        "suspicious tld",
    ]
    return any(indicator in text for indicator in indicators)


def print_case_report(
    passed: bool,
    url: str,
    result: dict,
    failures: list[str],
) -> None:
    status = "PASS" if passed else "FAIL"
    risk_level = result.get("risk_level", "unavailable")
    trust_score = result.get("trust_score", "unavailable")
    probability = result.get("phishing_probability", "unavailable")
    top_reasons = result.get("reasons", [])[:3] or ["No reasons returned."]

    print(f"{status} {url}")
    print(f"  risk_level: {risk_level}")
    print(f"  trust_score: {trust_score}")
    print(f"  phishing_probability: {probability}")
    print("  top_reasons:")
    for reason in top_reasons:
        print(f"    - {reason}")
    if failures:
        print("  failures:")
        for failure in failures:
            print(f"    - {failure}")
    print()


if __name__ == "__main__":
    raise SystemExit(main())
