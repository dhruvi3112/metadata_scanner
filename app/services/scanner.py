from .analyzer import analyze

def calculate_risk(findings):
    score = 0
    if findings["paths"]: score += 5
    if findings["emails"]: score += 3
    if findings["author"]: score += 2

    if score >= 7: return "HIGH"
    if score >= 4: return "MEDIUM"
    return "LOW"
