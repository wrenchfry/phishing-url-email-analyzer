from datetime import datetime


def build_markdown_report(analysis):
    lines = ["# Phishing Analysis Report", "", f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}", "", "## Summary", "", f"- Overall risk: {analysis['summary']['overall_risk']}", "- No URLs or attachments were opened by this tool.", "", "## Email Details", "", f"- Subject: {analysis['email']['subject'] or 'Not found'}", f"- Sender: {analysis['email']['sender'] or 'Not found'}", f"- Input format: {'.eml' if analysis['input']['is_eml'] else 'plain text'}", "", "## Findings by Category", ""]
    if not analysis["summary"]["groups"]:
        lines.append("- No warning signals were found by the implemented checks. This does not prove the message is safe.")
    for group in analysis["summary"]["groups"]:
        lines.extend([f"### {group['category']} - {group['severity'].title()} risk", ""])
        for item in group["signals"]:
            lines.extend([f"- **{item['message']}**", f"  - Evidence: {item['evidence']}", f"  - Why it matters: {item['recommendation']}"])
        lines.append("")
    lines.extend(["## URLs", ""])
    if not analysis["urls"]:
        lines.append("- No URLs found.")
    for result in analysis["urls"]:
        lines.extend([f"### {result['url']}", "", f"- Registrable domain: {result['registrable_domain'] or 'Not found'}"])
        if not result["signals"]:
            lines.append("- No URL-specific warning signals found.")
        lines.append("")
    if analysis["summary"]["recommendations"]:
        lines.extend(["## Recommended Next Steps", ""])
        lines.extend(f"- {item}" for item in analysis["summary"]["recommendations"])
    return "\n".join(lines).rstrip() + "\n"
