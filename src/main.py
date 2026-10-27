import argparse
import json
import re
from pathlib import Path

from email_checks import check_email_message
from email_parser import read_message
from report import build_markdown_report
from signals import summarize_signals
from url_checks import check_url

VERSION = "0.2.0"


def extract_urls(text):
    urls = re.findall(r"https?://[^\s]+", text, flags=re.IGNORECASE)
    return list(dict.fromkeys(url.rstrip(").,") for url in urls))


def analyze_file(path):
    message = read_message(path)
    url_results = [check_url(url) for url in extract_urls(message["text"])]
    email_result = check_email_message(message, url_results)
    signals = [*email_result["signals"], *(item for result in url_results for item in result["signals"])]
    return {
        "input": {"path": str(path), "is_eml": message["is_eml"], "attachment_count": len(message["attachments"])},
        "email": email_result,
        "attachments": message["attachments"],
        "urls": url_results,
        "summary": summarize_signals(signals),
    }


def print_terminal_report(analysis):
    print("Summary\n-------")
    print(f"Overall risk: {analysis['summary']['overall_risk']}")
    print("Safety: this tool did not open URLs or attachments.\n")
    print("Findings\n--------")
    if not analysis["summary"]["groups"]:
        print("- No warning signals found. This does not prove the message is safe.")
    for group in analysis["summary"]["groups"]:
        print(f"- [{group['severity'].upper()}] {group['category']}")
        for item in group["signals"]:
            print(f"  - {item['message']}\n    Evidence: {item['evidence']}\n    Next step: {item['recommendation']}")
    print("\nURLs\n----")
    if not analysis["urls"]:
        print("- No URLs found.")
    for result in analysis["urls"]:
        print(f"- {result['url']}\n  Registrable domain: {result['registrable_domain'] or 'Not found'}")
    if analysis["attachments"]:
        print("\nAttachments\n-----------")
        for attachment in analysis["attachments"]:
            print(f"- {attachment['filename']} ({attachment['content_type']}, {attachment['size_bytes']} bytes)")


def main():
    parser = argparse.ArgumentParser(description="Offline phishing email and URL triage tool")
    parser.add_argument("input", type=Path, help="Plain-text email or .eml file")
    parser.add_argument("--report", type=Path, help="Write a Markdown report")
    parser.add_argument("--format", choices=("text", "json"), default="text", help="Choose terminal output")
    parser.add_argument("--json", type=Path, dest="json_path", help="Write the full analysis as JSON")
    parser.add_argument("--version", action="version", version=f"phishing-analyzer {VERSION}")
    args = parser.parse_args()

    analysis = analyze_file(args.input)
    if args.format == "json":
        print(json.dumps(analysis, indent=2))
    else:
        print_terminal_report(analysis)
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(build_markdown_report(analysis), encoding="utf-8")
        print(f"Markdown report written to {args.report}")
    if args.json_path:
        args.json_path.parent.mkdir(parents=True, exist_ok=True)
        args.json_path.write_text(json.dumps(analysis, indent=2) + "\n", encoding="utf-8")
        print(f"JSON report written to {args.json_path}")


if __name__ == "__main__":
    main()
