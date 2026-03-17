def analyze_metadata(metadata):
    score = 0

    sensitive_fields = [
        "Author", "Creator", "Producer",
        "Last Modified By", "Company",
        "Manager", "Template"
    ]

    for key in metadata:
        if key in sensitive_fields and metadata[key]:
            score += 15

    if score >= 60:
        level = "High"
    elif score >= 30:
        level = "Medium"
    else:
        level = "Low"

    return {
        "risk_level": level,
        "risk_score": score
    }
