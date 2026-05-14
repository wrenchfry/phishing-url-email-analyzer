import re
import sys
from pathlib import Path

from email_checks import check_email_text, get_sender_address, get_subject
from url_checks import check_url, risk_label


def extract_urls(text):
    pattern = r"https?://[^\s]+"
    urls = re.findall(pattern, text, flags=re.IGNORECASE)
    cleaned_urls = []

    for url in urls:
        cleaned_url = url.rstrip(").,")
        if cleaned_url not in cleaned_urls:
            cleaned_urls.append(cleaned_url)

    return cleaned_urls


def read_email_text(path):
    return Path(path).read_text(encoding="utf-8")


def recommendation_for(label):
    if label == "High":
        return "Do not click links. Report this message to IT or security."
    if label == "Medium":
        return "Review carefully before clicking any links."
    return "No major warning signs found from these simple checks."


def main():
    if len(sys.argv) < 2:
        print("Usage: python src/main.py samples/suspicious_email.txt")
        return

    email_text = read_email_text(sys.argv[1])
    urls = extract_urls(email_text)
    email_result = check_email_text(email_text, urls)
    url_results = [check_url(url) for url in urls]
    total_score = email_result["score"] + sum(result["score"] for result in url_results)
    overall_label = risk_label(total_score)
    subject = get_subject(email_text)
    sender = get_sender_address(email_text)

    print(f"Overall Risk: {overall_label}")
    print(f"Total Score: {total_score}")
    print(f"Recommendation: {recommendation_for(overall_label)}")
    print()

    if subject:
        print(f"Subject: {subject}")
    if sender:
        print(f"Sender: {sender}")
    print(f"Email Risk: {risk_label(email_result['score'])}")
    if email_result["findings"]:
        for finding in email_result["findings"]:
            print(f"- {finding}")
    else:
        print("- No obvious email wording issues found")
    print()

    if not urls:
        print("No URLs found.")
        return

    print("URLs found:")
    for result in url_results:
        print(f"- {result['url']}")
        print(f"  Risk: {risk_label(result['score'])}")
        if result["findings"]:
            for finding in result["findings"]:
                print(f"  - {finding}")
        else:
            print("  - No obvious URL issues found")


if __name__ == "__main__":
    main()
