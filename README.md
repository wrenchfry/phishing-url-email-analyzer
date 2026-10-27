# Phishing URL and Email Analyzer

This project is a defensive cybersecurity learning tool for offline phishing triage. It reads plain-text emails or `.eml` files, extracts indicators without opening links or attachments, groups the evidence by risk category, and writes a short report.

## Why I Am Building This

I became interested in phishing analysis after a personal incident where I downloaded software from a site I thought was legitimate: `https://www.hellokittycity.com/`. After running it, I noticed signs that my account/session token access may have been compromised.

That experience made me want to understand how suspicious links, impersonation, downloads, and social engineering can lead to account compromise. This project is my way of turning that mistake into practical cybersecurity learning.

## Planned Features

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

## Run

```bash
python -m pip install -r requirements.txt
python src/main.py samples/suspicious_email.txt
```

To write a markdown report:

```bash
python src/main.py samples/suspicious_email.txt --report reports/sample_phishing_analysis.md
```

To analyse a real exported email safely:

```bash
python src/main.py suspicious-message.eml --format json --json reports/analysis.json
```

To run the basic tests:

```bash
python -m unittest discover -s tests
```

## Learning Notes

- [Phishing awareness brief](docs/phishing_awareness_brief.md)
- [Evidence handling notes](docs/evidence_handling_notes.md)
