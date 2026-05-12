import re
import sys
from pathlib import Path

from email_checks import check_email_text
from url_checks import check_url, risk_label


def extract_urls(text):
    pattern = r"https?://[^\s]+"
    urls = re.findall(pattern, text, flags=re.IGNORECASE)
    return [url.rstrip(").,") for url in urls]


def read_email_text(path):
    return Path(path).read_text(encoding="utf-8")


def main():
    if len(sys.argv) < 2:
        print("Usage: python src/main.py samples/suspicious_email.txt")
        return

    email_text = read_email_text(sys.argv[1])
    urls = extract_urls(email_text)
    email_result = check_email_text(email_text, urls)

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
    for url in urls:
        print(f"- {url}")
        result = check_url(url)
        print(f"  Risk: {risk_label(result['score'])}")
        if result["findings"]:
            for finding in result["findings"]:
                print(f"  - {finding}")
        else:
            print("  - No obvious URL issues found")


if __name__ == "__main__":
    main()
