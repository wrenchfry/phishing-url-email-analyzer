from urllib.parse import urlparse
import re


SUSPICIOUS_WORDS = [
    "access",
    "billing",
    "login",
    "account",
    "free",
    "password",
    "restore",
    "secure",
    "suspend",
    "update",
    "verify",
]

BENIGN_TRAINING_WORDS = [
    "awareness",
    "training",
    "learning",
]


def is_ip_address(hostname):
    return bool(re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", hostname))


def check_url(url):
    findings = []
    score = 0
    parsed = urlparse(url)
    domain = parsed.netloc.lower()

    if parsed.scheme.lower() != "https":
        findings.append("URL does not use HTTPS")
        score += 2

    if not domain:
        findings.append("Could not read the domain")
        score += 1
    elif is_ip_address(domain):
        findings.append("URL uses an IP address instead of a normal domain")
        score += 3

    lower_url = url.lower()
    for word in SUSPICIOUS_WORDS:
        if word == "password" and any(safe_word in lower_url for safe_word in BENIGN_TRAINING_WORDS):
            continue

        if word in lower_url:
            findings.append(f"URL contains suspicious word: {word}")
            score += 1

    return {
        "url": url,
        "domain": domain,
        "score": score,
        "findings": findings,
    }


def risk_label(score):
    if score >= 5:
        return "High"
    if score >= 2:
        return "Medium"
    return "Low"
