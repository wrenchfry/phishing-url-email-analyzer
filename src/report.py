from datetime import datetime

from url_checks import risk_label


def build_markdown_report(subject, sender, email_result, url_results, total_score, recommendation):
    lines = [
        "# Phishing Analysis Report",
        "",
        f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}",
        "",
        "## Summary",
        "",
        f"- Overall risk: {risk_label(total_score)}",
        f"- Total score: {total_score}",
        f"- Recommendation: {recommendation}",
        "",
        "## Email Details",
        "",
        f"- Subject: {subject or 'Not found'}",
        f"- Sender: {sender or 'Not found'}",
        f"- Email wording risk: {risk_label(email_result['score'])}",
        "",
        "## Email Findings",
        "",
    ]

    if email_result["findings"]:
        for finding in email_result["findings"]:
            lines.append(f"- {finding}")
    else:
        lines.append("- No obvious email wording issues found.")

    lines.extend(["", "## URL Findings", ""])

    if url_results:
        for index, result in enumerate(url_results, start=1):
            lines.append(f"### URL {index}")
            lines.append("")
            lines.append(f"- URL: {result['url']}")
            lines.append(f"- Domain: {result['domain'] or 'Not found'}")
            lines.append(f"- Risk: {risk_label(result['score'])}")
            if result["findings"]:
                for finding in result["findings"]:
                    lines.append(f"- {finding}")
            else:
                lines.append("- No obvious URL issues found.")
            lines.append("")
    else:
        lines.append("- No URLs found.")

    return "\n".join(lines).rstrip() + "\n"
