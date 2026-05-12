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


def get_sender_address(text):
    match = re.search(r"^From:.*<([^>\s]+)>", text, flags=re.MULTILINE)
    if match:
        return match.group(1).strip()
    return ""


def get_subject(text):
    match = re.search(r"^Subject:\s*(.+)$", text, flags=re.MULTILINE)
    if match:
        return match.group(1).strip()
    return ""


def get_url_domain(url):
    return urlparse(url).netloc.lower()


def find_markdown_links(text):
    return re.findall(r"\[([^\]]+)\]\((https?://[^\s)]+)\)", text, flags=re.IGNORECASE)


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

    for label, url in find_markdown_links(text):
        url_domain = get_url_domain(url)
        label_words = re.findall(r"[a-z0-9]+", label.lower())
        if url_domain and label_words and not any(word in url_domain for word in label_words):
            findings.append(f"Link text may not match destination: {label} -> {url_domain}")
            score += 2

    return {
        "score": score,
        "findings": findings,
    }
