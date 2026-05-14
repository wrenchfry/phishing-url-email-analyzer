import re
import sys
from pathlib import Path

from email_checks import check_email_text, get_sender_address, get_subject
from report import build_markdown_report
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
        print("Usage: python src/main.py samples/suspicious_email.txt [--report reports/report.md]")
        return

    email_text = read_email_text(sys.argv[1])
    urls = extract_urls(email_text)
    email_result = check_email_text(email_text, urls)
    url_results = [check_url(url) for url in urls]
    total_score = email_result["score"] + sum(result["score"] for result in url_results)
    overall_label = risk_label(total_score)
    recommendation = recommendation_for(overall_label)
    subject = get_subject(email_text)
    sender = get_sender_address(email_text)

    print(f"Overall Risk: {overall_label}")
    print(f"Total Score: {total_score}")
    print(f"Recommendation: {recommendation}")
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

    if "--report" in sys.argv:
        report_index = sys.argv.index("--report")
        if len(sys.argv) <= report_index + 1:
            print()
            print("Report path missing after --report")
            return

        report_path = Path(sys.argv[report_index + 1])
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_text = build_markdown_report(
            subject,
            sender,
            email_result,
            url_results,
            total_score,
            recommendation,
        )
        report_path.write_text(report_text, encoding="utf-8")
        print()
        print(f"Report written to {report_path}")


if __name__ == "__main__":
    main()
