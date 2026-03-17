def calculate_risk(metadata: dict):
    """
    Calculates risk score and risk level based on leaked metadata
    """

    # Weighted sensitive metadata
    FIELD_WEIGHTS = {
        "Author": 20,
        "Creator": 20,
        "Producer": 15,
        "Company": 20,
        "LastModifiedBy": 15,
        "Email": 25,
        "Username": 20,
        "InternalPath": 30,
        "Template": 15,
        "Application": 5,
        "CreatorTool": 5,
    }

    risk_score = 0
    detected_fields = []

    for key, value in metadata.items():
        if not value:
            continue

        for sensitive_key, weight in FIELD_WEIGHTS.items():
            if sensitive_key.lower() in key.lower():
                detected_fields.append(key)
                risk_score += weight

    # Bonus if many fields leaked
    if len(detected_fields) >= 5:
        risk_score += 15
    elif len(detected_fields) >= 3:
        risk_score += 10

    # Cap risk score
    risk_score = min(risk_score, 100)

    # Risk level mapping
    if risk_score >= 70:
        risk_level = "High"
    elif risk_score >= 40:
        risk_level = "Medium"
    else:
        risk_level = "Low"

    return risk_score, risk_level

def find_leaked_metadata(metadata):
    SAFE_FIELDS = {"PageCount", "FileSize", "Pages"}
    leaked = []

    for key, value in metadata.items():
        if value and key not in SAFE_FIELDS:
            leaked.append(f"{key}: {value}")

    return leaked