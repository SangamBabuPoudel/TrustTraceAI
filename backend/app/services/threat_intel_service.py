from urllib.parse import urlparse

from app.data.local_blocklist import KNOWN_BAD_DOMAINS, KNOWN_BAD_URLS


def check_local_blocklist(url: str) -> dict:
    normalized_url = url.rstrip("/")
    if normalized_url in KNOWN_BAD_URLS or normalized_url.lower() in KNOWN_BAD_URLS:
        return {
            "source": "local_blocklist",
            "status": "matched",
            "is_known_bad": True,
            "reason": "URL matched local MVP known-bad blocklist.",
            "details": "Local MVP test blocklist match.",
        }

    return {
        "source": "local_blocklist",
        "status": "clear",
        "is_known_bad": False,
        "reason": "No local known-bad URL match.",
        "details": "Local MVP test blocklist checked.",
    }


def check_known_bad_domain(hostname: str) -> dict:
    normalized_hostname = hostname.lower().strip(".")
    if normalized_hostname in KNOWN_BAD_DOMAINS:
        return {
            "source": "local_domain_blocklist",
            "status": "matched",
            "is_known_bad": True,
            "reason": "Domain matched local MVP known-bad blocklist.",
            "details": "Local MVP test domain blocklist match.",
        }

    return {
        "source": "local_domain_blocklist",
        "status": "clear",
        "is_known_bad": False,
        "reason": "No local known-bad domain match.",
        "details": "Local MVP domain blocklist checked.",
    }


def get_threat_intel_summary(url: str) -> dict:
    local_result = check_local_blocklist(url)
    if local_result["is_known_bad"]:
        return local_result

    hostname = (urlparse(url).hostname or "").lower()
    domain_result = check_known_bad_domain(hostname)
    if domain_result["is_known_bad"]:
        return domain_result

    return {
        "source": "none",
        "status": "clear",
        "is_known_bad": False,
        "reason": "No local known-bad match.",
        "details": "External threat intelligence integrations are placeholders for future MVPs.",
    }


def check_phishtank(url: str) -> dict:
    return _placeholder("phishtank")


def check_openphish(url: str) -> dict:
    return _placeholder("openphish")


def check_google_safe_browsing(url: str) -> dict:
    return _placeholder("google_safe_browsing")


def check_urlhaus(url: str) -> dict:
    return _placeholder("urlhaus")


def check_virustotal(url: str) -> dict:
    return _placeholder("virustotal")


def check_all_threat_intel(url: str) -> list[dict]:
    return [
        check_local_blocklist(url),
        check_known_bad_domain(urlparse(url).hostname or ""),
        check_phishtank(url),
        check_openphish(url),
        check_google_safe_browsing(url),
        check_urlhaus(url),
        check_virustotal(url),
    ]


def _placeholder(source: str) -> dict:
    return {
        "source": source,
        "status": "not_configured",
        "is_known_bad": False,
        "details": "Placeholder for future integration.",
    }
