# Phishing URL and Email Analyzer

This project is a defensive cybersecurity learning tool for offline phishing triage. It reads plain-text emails or `.eml` files, extracts indicators without opening links or attachments, groups the evidence by risk category, and writes a short report.

## Why I Am Building This

I became interested in phishing analysis after a personal incident where I downloaded software from a site I thought was legitimate: `https://www.hellokittycity.com/`. After running it, I noticed signs that my account/session token access may have been compromised.

That experience made me want to understand how suspicious links, impersonation, downloads, and social engineering can lead to account compromise. This project is my way of turning that mistake into practical cybersecurity learning.

## What It Checks

Current checks include:

- Extract URLs from pasted email text.
- Deduplicate repeated URLs.
- Show the email subject and sender address.
- Parse `.eml` headers, including `From`, `Reply-To`, `Return-Path`, authentication results, and attachment metadata.
- Compare sender and link registrable domains, including country-code suffixes such as `.co.za`.
- Detect links that use IP addresses, punycode, `@` user-info tricks, unusual ports, encoded text, and redirect parameters.
- Detect shortened links such as `bit.ly`.
- Flag URLs with many subdomains.
- Look for urgent or threatening language, sender spoofing indicators, failed authentication headers, and risky attachment extensions.
- Generate explainable terminal, Markdown, and JSON reports with evidence and recommended next actions.

## Architecture

```text
Email file -> Parser -> URL, header, and attachment checks -> Findings -> terminal, Markdown, or JSON report
```

Each stage stays local to your computer. The program reads the input and metadata only; it does not visit suspicious links, follow redirects, or execute attachments.

## Demo

Analyse the included suspicious message and save two report formats:

```bash
python src/main.py samples/suspicious_email.txt --report reports/sample_phishing_analysis.md --json reports/sample_phishing_analysis.json
```

Example terminal result:

```text
Summary
-------
Overall risk: High
Safety: this tool did not open URLs or attachments.

Findings
--------
- [HIGH] URL structure
  - URL uses an IP address instead of a named domain
    Evidence: 192.168.10.44
    Next step: Do not open the link; use the organisation's known website instead.
```

The command also creates an explainable [Markdown report](reports/sample_phishing_analysis.md) and a machine-readable [JSON report](reports/sample_phishing_analysis.json).

## Sample Inputs

- [`safe_internal_reminder.eml`](samples/safe_internal_reminder.eml): a routine internal-training reminder that should remain low risk.
- [`fake_microsoft_reply_to.eml`](samples/fake_microsoft_reply_to.eml): a fake Microsoft-themed message with a mismatched Reply-To address, failed SPF result, and an `@` URL trick.
- [`suspicious_attachment.eml`](samples/suspicious_attachment.eml): an invoice-style message containing a double-extension executable attachment name.

These are fictional, safe learning samples. Their URLs use reserved example domains and their attachment payload is harmless text.

## Design Decisions

- **Offline-first:** the tool deliberately does not fetch URLs, follow redirects, or run attachments. This keeps analysis safer and predictable.
- **Explainable findings:** every signal includes its severity, the evidence that caused it, and a suggested next action. It does not hide a verdict behind one unexplained number.
- **Registrable-domain comparison:** `signin.paypal.co.uk` is compared as `paypal.co.uk`, rather than using fragile word matching.
- **Conservative claims:** a finding is an indicator to investigate, not proof that an email is malicious. Legitimate mail can use third-party delivery or tracking domains.

## What This Project Demonstrates

- Basic security operations triage.
- Introductory phishing and social engineering analysis.
- Indicator extraction from emails and URLs.
- Clear written reporting for non-technical users.
- Awareness of ethical and defensive cybersecurity work.

## Limitations

This tool will not prove that a URL is malicious. It uses simple rule-based checks only, so it can miss real phishing links and it can also flag safe links by mistake.

It does not open suspicious links, follow redirects, download files, execute or scan attachments, collect credentials, or perform offensive testing. The sample emails are for learning and demonstration only.

Future improvements could include an opt-in reputation lookup mode using services such as VirusTotal, Google Safe Browsing, URLScan.io, or PhishTank.

## Status

Learning project. The tool is a Python command-line application designed to make each rule and its limitations visible.

## Installation and Use

```bash
python -m pip install ".[dev]"
python -m unittest discover -s tests
python -m ruff check .
```

For a lightweight runtime-only installation, use:

```bash
python -m pip install -r requirements.txt
```

Useful commands:

```bash
python src/main.py --help
python src/main.py --version
python src/main.py samples/safe_internal_reminder.eml
python src/main.py samples/fake_microsoft_reply_to.eml --format json
python src/main.py suspicious-message.eml --report reports/analysis.md --json reports/analysis.json
```

## Quality Checks

GitHub Actions runs Ruff and the full unit-test suite on every push and pull request. The local commands above use the same checks.

## Learning Notes

- [Phishing awareness brief](docs/phishing_awareness_brief.md)
- [Evidence handling notes](docs/evidence_handling_notes.md)
