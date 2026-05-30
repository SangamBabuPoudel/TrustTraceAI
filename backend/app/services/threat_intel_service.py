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
