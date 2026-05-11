import re
import sys
from pathlib import Path


def extract_urls(text):
    pattern = r"https?://[^\s]+"
    return re.findall(pattern, text, flags=re.IGNORECASE)


def read_email_text(path):
    return Path(path).read_text(encoding="utf-8")


def main():
    if len(sys.argv) < 2:
        print("Usage: python src/main.py samples/suspicious_email.txt")
        return

    email_text = read_email_text(sys.argv[1])
    urls = extract_urls(email_text)

    if not urls:
        print("No URLs found.")
        return

    print("URLs found:")
    for url in urls:
        print(f"- {url}")


if __name__ == "__main__":
    main()
