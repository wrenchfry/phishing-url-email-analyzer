URGENCY_WORDS = [
    "urgent",
    "today",
    "locked",
    "suspended",
    "unusual activity",
    "losing access",
    "before the end of the day",
]


def check_email_text(text):
    findings = []
    score = 0

    for word in URGENCY_WORDS:
        if word in text:
            findings.append(f"Email uses urgency language: {word}")
            score += 1

    return {
        "score": score,
        "findings": findings,
    }
