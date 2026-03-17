from PyPDF2 import PdfReader

def extract_pdf_metadata(file_path):
    metadata_info = {}

    try:
        reader = PdfReader(file_path)
        metadata = reader.metadata

        if metadata:
            for key, value in metadata.items():
                metadata_info[key] = str(value)

    except Exception as e:
        metadata_info["error"] = str(e)

    return metadata_info

def calculate_risk_score(metadata):
    score = 0
    findings = []

    for key, value in metadata.items():
        value_str = str(value).lower()

        if key == "/Author":
            score += 4
            findings.append("Author name exposed")

        if key in ["/Creator", "/Producer"]:
            score += 3
            findings.append("Software information disclosed")

        if key in ["/CreationDate", "/ModDate"]:
            score += 2
            findings.append("Timeline information exposed")

        if "c:\\" in value_str or "\\\\" in value_str:
            score += 5
            findings.append("Internal file path leaked")

        if "@" in value_str:
            score += 5
            findings.append("Email address exposed")

    # Risk level classification
    if score >= 10:
        level = "HIGH"
    elif score >= 5:
        level = "MEDIUM"
    else:
        level = "LOW"

    return {
        "score": score,
        "level": level,
        "findings": list(set(findings))
    }

