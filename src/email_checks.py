import re
from urllib.parse import urlparse


URGENCY_WORDS = [
    "urgent",
    "today",
    "locked",
    "suspended",
    "unusual activity",
    "losing access",
    "before the end of the day",
]


def get_sender_domain(text):
    match = re.search(r"^From:.*<[^@\s]+@([^>\s]+)>", text, flags=re.MULTILINE)
    if match:
        return match.group(1).lower()
    return ""


def get_url_domain(url):
    return urlparse(url).netloc.lower()


def check_email_text(text, urls=None):
    findings = []
    score = 0
    urls = urls or []
    lower_text = text.lower()

    for word in URGENCY_WORDS:
        if word in lower_text:
            findings.append(f"Email uses urgency language: {word}")
            score += 1

    sender_domain = get_sender_domain(text)
    if sender_domain:
        for url in urls:
            url_domain = get_url_domain(url)
            if url_domain and sender_domain not in url_domain:
                findings.append(f"Sender domain does not match link domain: {sender_domain} -> {url_domain}")
                score += 2
                break

    return {
        "score": score,
        "findings": findings,
    }
