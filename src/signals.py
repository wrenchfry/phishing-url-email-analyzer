"""Shared signal shape and severity summarisation helpers."""

from collections import defaultdict


SEVERITY_POINTS = {"low": 1, "medium": 2, "high": 3}
SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3}
GROUP_CAP = 5


def signal(category, severity, message, evidence, recommendation):
    """Create one explainable analysis finding."""
    return {
        "category": category,
        "severity": severity,
        "message": message,
        "evidence": evidence,
        "recommendation": recommendation,
    }


def summarize_signals(signals):
    """Group related indicators so one noisy URL cannot inflate the verdict."""
    grouped = defaultdict(list)
    for item in signals:
        grouped[item["category"]].append(item)

    groups = []
    for category, items in grouped.items():
        capped_score = min(sum(SEVERITY_POINTS[item["severity"]] for item in items), GROUP_CAP)
        severity = max(items, key=lambda item: SEVERITY_ORDER[item["severity"]])["severity"]
        groups.append(
            {
                "category": category,
                "severity": severity,
                "capped_score": capped_score,
                "signals": items,
            }
        )

    groups.sort(key=lambda group: SEVERITY_ORDER[group["severity"]], reverse=True)
    if any(group["severity"] == "high" for group in groups):
        overall_risk = "High"
    elif any(group["severity"] == "medium" for group in groups):
        overall_risk = "Medium"
    else:
        overall_risk = "Low"

    recommendations = []
    for item in signals:
        if item["recommendation"] not in recommendations:
            recommendations.append(item["recommendation"])

    return {
        "overall_risk": overall_risk,
        "groups": groups,
        "recommendations": recommendations,
    }
