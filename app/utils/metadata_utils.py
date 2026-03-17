def find_leaked_metadata(metadata: dict):
    """
    Identify sensitive metadata fields
    """
    sensitive_keys = [
        "Author",
        "Creator",
        "Producer",
        "Company",
        "Last Modified By",
        "Email",
        "Username",
        "GPSLatitude",
        "GPSLongitude",
        "Location",
        "Software"
    ]

    leaked = []

    for key, value in metadata.items():
        if key in sensitive_keys and value:
            leaked.append(f"{key}: {value}")

    return leaked